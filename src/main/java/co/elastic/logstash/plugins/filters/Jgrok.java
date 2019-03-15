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

import java.util.ArrayList;
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

    public static final PluginConfigSpec<String> SOURCE_FIELD =
            PluginConfigSpec.stringSetting("source_field", "message");
    public static final PluginConfigSpec<String> MATCH_PATTERN =
            PluginConfigSpec.requiredStringSetting("match_pattern");
    public static final PluginConfigSpec<Long> MAX_EXECUTION_TIME_MILLIS =
            PluginConfigSpec.numSetting("max_execution_time_millis", 5000);
    public static final PluginConfigSpec<String> TAG_ON_TIMEOUT =
            PluginConfigSpec.stringSetting("tag_on_timeout", "_groktimeout");

    private Grok grok;
    private String id;
    private String sourceField;
    private String tagOnTimeout;

    public Jgrok(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_FIELD);
        this.tagOnTimeout = config.get(TAG_ON_TIMEOUT);
        Map<String, String> patternBank = Grok.getBuiltinPatterns();
        if (false) {
            patternBank.putAll(Collections.emptyMap());
        }

        List<String> matchPatterns = new ArrayList<>();
        matchPatterns.add(config.get(MATCH_PATTERN));

        long maxExecTimeMillis = config.get(MAX_EXECUTION_TIME_MILLIS);
        this.grok = new Grok(
                patternBank,
                combinePatterns(matchPatterns),
                createGrokThreadWatchdog(maxExecTimeMillis / 2, maxExecTimeMillis));
    }

    @Override
    public Collection<Event> filter(Collection<Event> collection, FilterMatchListener filterMatchListener) {
        for (Event e : collection) {
            Object source = e.getField(sourceField);
            if (source instanceof String) {
                try {
                    Map<String, Object> captures = grok.captures((String) source);
                    if (captures != null && captures.size() > 0) {
                        for (Map.Entry<String, Object> entry : captures.entrySet()) {
                            e.setField(entry.getKey(), entry.getValue());
                        }
                        filterMatchListener.filterMatched(e);
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
        return PluginHelper.commonFilterSettings(Arrays.asList(SOURCE_FIELD, MATCH_PATTERN, MAX_EXECUTION_TIME_MILLIS));
    }

    @Override
    public String getId() {
        return id;
    }

    /**
     * A thread to cache millisecond time values from
     * {@link System#nanoTime()} and {@link System#currentTimeMillis()}.
     *
     * The values are updated at a specified interval.
     */
    static class CachedTimeThread extends Thread {

        final long interval;
        volatile boolean running = true;
        volatile long relativeMillis;
        volatile long absoluteMillis;

        CachedTimeThread(String name, long interval) {
            super(name);
            this.interval = interval;
            this.relativeMillis = System.nanoTime() / 1_000_000;
            this.absoluteMillis = System.currentTimeMillis();
            setDaemon(true);
        }

        /**
         * Return the current time used for relative calculations. This is
         * {@link System#nanoTime()} truncated to milliseconds.
         */
        long relativeTimeInMillis() {
            return relativeMillis;
        }

        /**
         * Return the current epoch time, used to find absolute time. This is
         * a cached version of {@link System#currentTimeMillis()}.
         */
        long absoluteTimeInMillis() {
            return absoluteMillis;
        }

        @Override
        public void run() {
            while (running) {
                relativeMillis = System.nanoTime() / 1_000_000;
                absoluteMillis = System.currentTimeMillis();
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException e) {
                    running = false;
                    return;
                }
            }
        }

    }
}
