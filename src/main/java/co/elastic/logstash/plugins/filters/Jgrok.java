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

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
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
    public static final PluginConfigSpec<Long> TIMEOUT_MILLIS =
            PluginConfigSpec.numSetting("timeout_millis", 5000);
    public static final PluginConfigSpec<Boolean> BREAK_ON_MATCH =
            PluginConfigSpec.booleanSetting("break_on_match", true);
    public static final PluginConfigSpec<String> TAG_ON_TIMEOUT =
            PluginConfigSpec.stringSetting("tag_on_timeout", "_groktimeout");
    public static final PluginConfigSpec<String> TAG_ON_FAILURE =
            PluginConfigSpec.stringSetting("tag_on_failure", "_grokparsefailure");
    public static final PluginConfigSpec<Boolean> NAMED_CAPTURES_ONLY =
            PluginConfigSpec.booleanSetting("named_captures_only", true);
    public static final PluginConfigSpec<List<Object>> OVERWRITE =
            PluginConfigSpec.arraySetting("overwrite", Collections.emptyList(), false, false);
    public static final PluginConfigSpec<Map<String, Object>> PATTERN_DEFINITIONS =
            PluginConfigSpec.hashSetting("pattern_definitions", Collections.emptyMap(), false, false);
    public static final PluginConfigSpec<List<Object>> PATTERNS_DIR =
            PluginConfigSpec.arraySetting("patterns_dir", Collections.emptyList(), false, false);
    public static final PluginConfigSpec<String> PATTERNS_FILES_GLOB =
            PluginConfigSpec.stringSetting("patterns_files_glob", "*");

    private final String id;
    private final boolean breakOnMatch;
    private final boolean namedCapturesOnly;
    private final String tagOnTimeout;
    private final String tagOnFailure;
    private final List<String> overwrite;
    private final GrokMatchEntry[] grokMatchEntries;

    public Jgrok(String id, Configuration config, Context context) {
        this.id = id;
        this.breakOnMatch = config.get(BREAK_ON_MATCH);
        this.namedCapturesOnly = config.get(NAMED_CAPTURES_ONLY);
        this.tagOnTimeout = config.get(TAG_ON_TIMEOUT);
        this.tagOnFailure = config.get(TAG_ON_FAILURE);

        overwrite = new ArrayList<>();
        List<Object> overwriteConfig = config.get(OVERWRITE);
        for (Object o : overwriteConfig) {
            if (o instanceof String) {
                overwrite.add((String) o);
            } else {
                throw new IllegalArgumentException("Overwrite field name '" + o + "' must be a string type");
            }
        }

        Map<String, String> patternBank = new HashMap<>();
        patternBank.putAll(Grok.getBuiltinPatterns());
        patternBank.putAll(readPatternsFromDirs(config.get(PATTERNS_DIR), config.get(PATTERNS_FILES_GLOB)));
        patternBank.putAll(readPatternsFromConfig(config.get(PATTERN_DEFINITIONS)));

        long maxExecTimeMillis = config.get(TIMEOUT_MILLIS);
        Map<String, Object> matchConfig = config.get(MATCH);
        grokMatchEntries = new GrokMatchEntry[matchConfig.size()];
        int k = 0;
        for (Map.Entry<String, Object> entry : matchConfig.entrySet()) {
            List<String> patterns = new ArrayList<>();
            Object value = entry.getValue();
            if (value instanceof String) {
                patterns.add((String) value);
            } else if (value instanceof List) {
                List patternDefsList = (List) value;
                for (Object p : patternDefsList) {
                    if (p instanceof String) {
                        patterns.add((String) p);
                    } else {
                        throw new IllegalArgumentException("Match pattern list for field '" + entry.getKey() + "' must contain only string values");
                    }
                }
            } else {
                throw new IllegalArgumentException("Match pattern for field '" + entry.getKey() + "' must be a string or list value");
            }

            try {
                Constructor<Grok> constructor = Grok.class.getDeclaredConstructor(Map.class, String.class, boolean.class, ThreadWatchdog.class);
                constructor.setAccessible(true);
                Grok grok = constructor.newInstance(patternBank, combinePatterns(patterns), namedCapturesOnly, createGrokThreadWatchdog(maxExecTimeMillis / 2, maxExecTimeMillis));
                grokMatchEntries[k] = new GrokMatchEntry(entry.getKey(), grok);
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to initialize grok entry", ex);
            }
            k++;
        }
    }

    @Override
    public Collection<Event> filter(Collection<Event> collection, FilterMatchListener filterMatchListener) {
        for (Event e : collection) {
            boolean matched = false;
            GrokResult result = null;
            for (int k = 0; k < grokMatchEntries.length && (!breakOnMatch || !matched); k++) {
                GrokMatchEntry grok = grokMatchEntries[k];
                Object source = e.getField(grok.sourceField);
                if (source instanceof String) {
                    result = grok(grok.grok, (String) source);
                    if (result.timedOut) {
                        e.tag(tagOnTimeout);
                    } else if (result.captures != null && result.captures.size() > 0) {
                        for (Map.Entry<String, Object> entry : result.captures.entrySet()) {
                            final String targetField = entry.getKey();
                            if (e.getField(targetField) == null || overwrite.contains(targetField)) {
                                e.setField(targetField, entry.getValue());
                            }
                        }
                        matched = true;
                    }
                } else if (source instanceof List) {
                    List sourceList = (List) source;
                    Map<String, List<Object>> values = new HashMap<>();
                    for (Object item : sourceList) {
                        if (item instanceof String) {
                            result = grok(grok.grok, (String) item);
                            if (result.timedOut) {
                                e.tag(tagOnTimeout);
                            } else if (result.captures != null && result.captures.size() > 0) {
                                for (Map.Entry<String, Object> entry : result.captures.entrySet()) {
                                    appendValue(values, entry.getKey(), entry.getValue());
                                }
                                matched = true;
                            }
                        }
                    }
                    for (Map.Entry<String, List<Object>> entry : values.entrySet()) {
                        final String targetField = entry.getKey();
                        if (e.getField(targetField) == null || overwrite.contains(targetField)) {
                            e.setField(targetField, entry.getValue());
                        }
                    }
                }
            }
            if (matched) {
                filterMatchListener.filterMatched(e);
            } else if (result != null && !result.timedOut && tagOnFailure != null && !tagOnFailure.equals("")) {
                e.tag(tagOnFailure);
            }
        }
        return collection;
    }

    private static GrokResult grok(Grok grok, String source) {
        GrokResult result = new GrokResult();
        try {
            result.captures = grok.captures(source);
        } catch (RuntimeException ex) {
            if (ex.getMessage().startsWith("grok pattern matching was interrupted after")) {
                result.timedOut = true;
            } else {
                throw ex;
            }
        }
        return result;
    }

    private static void appendValue(Map<String, List<Object>> values, String key, Object value) {
        List<Object> valuesList = values.computeIfAbsent(key, k -> new ArrayList<>());
        valuesList.add(value);
    }

    private static String combinePatterns(List<String> patterns) {
        String combinedPattern;
        if (patterns.size() > 1) {
            combinedPattern = "";
            for (int i = 0; i < patterns.size(); i++) {
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

    private static Map<String, String> readPatternsFromDirs(List<Object> dirs, String glob) {
        Map<String, String> patterns = new HashMap<>();
        for (Object dir : dirs) {
            if (!(dir instanceof String)) {
                throw new IllegalArgumentException("All pattern directories must be string values");
            }

            Path patternDir = Paths.get((String) dir);
            try {
                Files.walkFileTree(patternDir, new PatternFileVisitor(patternDir, glob, patterns));
            } catch (IOException ex) {
                throw new IllegalArgumentException("Error reading patterns from directory '" + patternDir.toString() + "'");
            }
        }
        return patterns;
    }

    private static void readPatternsFromFile(Path patternFile, Map<String, String> patterns) {
        List<String> lines;
        try {
            lines = Files.readAllLines(patternFile);
        } catch (IOException ex) {
            throw new IllegalStateException("Error reading from patterns file '" + patternFile.toString() + "'", ex);
        }
        for (String line : lines) {
            String trimmedLine = line.trim();
            int spaceIndex = trimmedLine.indexOf(" ");
            if (spaceIndex == -1 || spaceIndex > trimmedLine.length() - 1) {
                throw new IllegalStateException("Could not find 'NAME PATTERN' format in patterns file '" + patternFile.toString() + "'");
            }
            patterns.put(trimmedLine.substring(0, spaceIndex - 1), trimmedLine.substring(spaceIndex + 1));
        }
    }

    private static Map<String, String> readPatternsFromConfig(Map<String, Object> patternDefsConfig) {
        Map<String, String> patterns = new HashMap<>();
        for (Map.Entry<String, Object> entry : patternDefsConfig.entrySet()) {
            if (!(entry.getValue() instanceof String)) {
                throw new IllegalArgumentException("Pattern definition for pattern '" + entry.getKey() + "' must be a string type");
            } else {
                patterns.put(entry.getKey(), (String) entry.getValue());
            }
        }
        return patterns;
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return PluginHelper.commonFilterSettings(Arrays.asList(MATCH, TIMEOUT_MILLIS, BREAK_ON_MATCH, TAG_ON_TIMEOUT,
                TAG_ON_FAILURE, NAMED_CAPTURES_ONLY, OVERWRITE, PATTERN_DEFINITIONS, PATTERNS_DIR,
                PATTERNS_FILES_GLOB));
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

    private static class PatternFileVisitor extends SimpleFileVisitor<Path> {

        private final PathMatcher pathMatcher;
        private final Map<String, String> patterns;

        PatternFileVisitor(Path dir, String glob, Map<String, String> patterns) {
            this.pathMatcher = FileSystems.getDefault().getPathMatcher("glob:" + dir.toString() + File.separator + glob);
            this.patterns = patterns;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            if (pathMatcher.matches(file)) {
                readPatternsFromFile(file, patterns);
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException ex) {
            return FileVisitResult.TERMINATE;
        }
    }

    private static class GrokResult {
        Map<String, Object> captures;
        boolean timedOut;
    }
}
