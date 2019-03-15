package co.elastic.logstash.plugins.filters;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;
import co.elastic.logstash.api.PluginHelper;
import org.elasticsearch.grok.Grok;
import org.elasticsearch.grok.ThreadWatchdog;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

@LogstashPlugin(name = "jgrok")
public class Jgrok implements Filter {

    public static final PluginConfigSpec<Map<String, Object>> MATCH =
            PluginConfigSpec.hashSetting("match", Collections.emptyMap(), false, false);
    public static final PluginConfigSpec<Long> MAX_EXECUTION_TIME_MILLIS =
            PluginConfigSpec.numSetting("max_execution_time_millis", 5000);
    public static final PluginConfigSpec<String> TAG_ON_TIMEOUT =
            PluginConfigSpec.stringSetting("tag_on_timeout", "_groktimeout");

    private String id;
    private String tagOnTimeout;
    private GrokMatchEntry[] grokMatchEntries;

    public Jgrok(String id, Configuration config, Context context) {
        this.id = id;
        this.tagOnTimeout = config.get(TAG_ON_TIMEOUT);
        Map<String, String> patternBank = Grok.getBuiltinPatterns();

        // read pattern_definitions hash
        // read patterns_file_glob from patterns_dir
        if (false) {
            patternBank.putAll(Collections.emptyMap());
        }

        long maxExecTimeMillis = config.get(MAX_EXECUTION_TIME_MILLIS);
        Map<String, Object> matchConfig = config.get(MATCH);
        grokMatchEntries = new GrokMatchEntry[matchConfig.size()];
        int k = 0;

        for (Map.Entry<String, Object> entry : matchConfig.entrySet()) {
            if (!(entry.getValue() instanceof String)) {
                throw new IllegalArgumentException("Match pattern '" + entry.getValue() + "' must be a string type");
            } else {
                String patterns = (String) entry.getValue();
                grokMatchEntries[k] = new GrokMatchEntry(
                        entry.getKey(),
                        new Grok(
                                patternBank,
                                combinePatterns(Collections.singletonList(patterns)),
                                createGrokThreadWatchdog(maxExecTimeMillis / 2, maxExecTimeMillis))
                        );
            }
            k++;
        }
    }

    @Override
    public Collection<Event> filter(Collection<Event> collection, FilterMatchListener filterMatchListener) {
        for (Event e : collection) {
            boolean matched = false;
            for (GrokMatchEntry grok : grokMatchEntries) {
                Object source = e.getField(grok.sourceField);
                if (source instanceof String) {
                    try {
                        Map<String, Object> captures = grok.grok.captures((String) source);
                        if (captures != null && captures.size() > 0) {
                            for (Map.Entry<String, Object> entry : captures.entrySet()) {
                                e.setField(entry.getKey(), entry.getValue());
                            }
                            matched = true;
                        }
                    } catch (RuntimeException ex) {
                        if (ex.getMessage().startsWith("grok pattern matching was interrupted after")) {
                            e.tag(tagOnTimeout);
                        } else {
                            throw ex;
                        }
                    }
                }
            }
            if (matched) {
                filterMatchListener.filterMatched(e);
            }
        }
        return collection;
    }

    static String combinePatterns(List<String> patterns) {
        String combinedPattern;
        if (patterns.size() > 1) {
            combinedPattern = "";
            for (int i = 0; i < patterns.size(); i++) {
                String pattern = patterns.get(i);
                String valueWrap;
                valueWrap = "(?:" + patterns.get(i) + ")";
                if (combinedPattern.equals("")) {
                    combinedPattern = valueWrap;
                } else {
                    combinedPattern = combinedPattern + "|" + valueWrap;
                }
            }
        } else {
            combinedPattern = patterns.get(0);
        }

        return combinedPattern;
    }

    private static ThreadWatchdog createGrokThreadWatchdog(long checkIntervalMillis, long maxExecutionTimeMillis) {
        ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();
        BiFunction<Long, Runnable, ScheduledFuture<?>> scheduler2 =
                (delay, command) ->  ses.schedule(command, delay, TimeUnit.MILLISECONDS);

        CachedTimeThread cachedTimeThread = new CachedTimeThread("GrokWatchdogTimeThread", checkIntervalMillis);
        cachedTimeThread.start();

        return ThreadWatchdog.newInstance(checkIntervalMillis, maxExecutionTimeMillis, cachedTimeThread::relativeTimeInMillis, scheduler2);
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return PluginHelper.commonFilterSettings(Arrays.asList(MATCH, MAX_EXECUTION_TIME_MILLIS, TAG_ON_TIMEOUT));
    }

    @Override
    public String getId() {
        return id;
    }

    static class CachedTimeThread extends Thread {

        final long interval;
        volatile boolean running = true;
        volatile long relativeMillis;

        CachedTimeThread(String name, long interval) {
            super(name);
            this.interval = interval;
            this.relativeMillis = System.nanoTime() / 1_000_000;
            setDaemon(true);
        }

        long relativeTimeInMillis() {
            return relativeMillis;
        }

        @Override
        public void run() {
            while (running) {
                relativeMillis = System.nanoTime() / 1_000_000;
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException e) {
                    running = false;
                    return;
                }
            }
        }
    }

    private class GrokMatchEntry {

        final String sourceField;
        final Grok grok;

        GrokMatchEntry(String sourceField, Grok grok) {
            this.sourceField = sourceField;
            this.grok = grok;
        }
    }
}

