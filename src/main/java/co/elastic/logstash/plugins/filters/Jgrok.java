package co.elastic.logstash.plugins.filters;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;
import co.elastic.logstash.api.PluginHelper;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.grok.Grok;
import org.elasticsearch.grok.ThreadWatchdog;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.function.BiFunction;

@LogstashPlugin(name = "jgrok")
public class Jgrok implements Filter {

    //public static final PluginConfigSpec<Map<String, Object>> MATCH_CONFIG =
    //        PluginConfigSpec.hashSetting("match", Collections.emptyMap(), false, true);
    public static final PluginConfigSpec<String> SOURCE_FIELD =
            PluginConfigSpec.stringSetting("source_field", "message");
    public static final PluginConfigSpec<String> MATCH_PATTERN =
            PluginConfigSpec.requiredStringSetting("match_pattern");
    public static final PluginConfigSpec<Long> CHECK_INTERVAL_MILLIS =
            PluginConfigSpec.numSetting("check_internal_millis", 2500);
    public static final PluginConfigSpec<Long> MAX_EXECUTION_TIME_MILLIS =
            PluginConfigSpec.numSetting("max_execution_time_millis", 5000);


    private Grok grok;
    private String id;
    private String sourceField;

    public Jgrok(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_FIELD);
        Map<String, String> patternBank = Grok.getBuiltinPatterns();
        if (false) {
            patternBank.putAll(Collections.emptyMap());
        }

        List<String> matchPatterns = new ArrayList<>();
        matchPatterns.add(config.get(MATCH_PATTERN));

        this.grok = new Grok(
                patternBank,
                combinePatterns(matchPatterns),
                createGrokThreadWatchdog(
                        config.get(CHECK_INTERVAL_MILLIS),
                        config.get(MAX_EXECUTION_TIME_MILLIS)));
    }

    @Override
    public Collection<Event> filter(Collection<Event> collection, FilterMatchListener filterMatchListener) {
        for (Event e : collection) {
            Object source = e.getField(sourceField);
            if (source instanceof String) {
                Map<String, Object> captures = grok.captures((String) source);
                if (captures != null && captures.size() > 0) {
                    for (Map.Entry<String, Object> entry : captures.entrySet()) {
                        e.setField(entry.getKey(), entry.getValue());
                    }
                    filterMatchListener.filterMatched(e);
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
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "foo").build());
        BiFunction<Long, Runnable, ScheduledFuture<?>> scheduler =
                (delay, command) -> threadPool.schedule(TimeValue.timeValueMillis(delay), ThreadPool.Names.GENERIC, command);

        return ThreadWatchdog.newInstance(checkIntervalMillis, maxExecutionTimeMillis, threadPool::relativeTimeInMillis, scheduler);
    }


    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return PluginHelper.commonFilterSettings(Arrays.asList(SOURCE_FIELD, MATCH_PATTERN, CHECK_INTERVAL_MILLIS,
                MAX_EXECUTION_TIME_MILLIS));
    }

    @Override
    public String getId() {
        return id;
    }
}
