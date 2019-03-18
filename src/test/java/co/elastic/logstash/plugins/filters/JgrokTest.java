package co.elastic.logstash.plugins.filters;

import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.FilterMatchListener;
import org.junit.Assert;
import org.junit.Test;
import org.logstash.plugins.ConfigurationImpl;
import org.logstash.plugins.ContextImpl;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static co.elastic.logstash.plugins.filters.Jgrok.MATCH;
import static co.elastic.logstash.plugins.filters.Jgrok.OVERWRITE;
import static co.elastic.logstash.plugins.filters.Jgrok.PATTERNS_DIR;
import static co.elastic.logstash.plugins.filters.Jgrok.PATTERNS_FILES_GLOB;
import static co.elastic.logstash.plugins.filters.Jgrok.PATTERN_DEFINITIONS;
import static co.elastic.logstash.plugins.filters.Jgrok.TAG_ON_FAILURE;
import static co.elastic.logstash.plugins.filters.Jgrok.TIMEOUT_MILLIS;

public class JgrokTest {

    private static final String APACHE_LOG_LINE =
            "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"";
    private static final String SIMPLE_LOG_LINE = "55.3.244.1 GET /index.html 15824 0.043";


    @Test
    public void testSimpleGrok() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", SIMPLE_LOG_LINE);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        validateSimpleLogLine(resultEvent);
    }

    @Test
    public void testApacheLogs() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{COMBINEDAPACHELOG}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", APACHE_LOG_LINE);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        validateApacheLogLine(resultEvent);
    }

    @Test
    public void testNoMatches() {
        String notApacheLog = "foo";
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{COMBINEDAPACHELOG}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", notApacheLog);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        assertHasTag(e, "_grokparsefailure");
    }

    @Test
    public void testNoMatchesWithTagOnFailure() {
        String notApacheLog = "foo";
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{COMBINEDAPACHELOG}"));
        String failureTag = "new_grok_parse_failure";
        config.put(TAG_ON_FAILURE.name(), failureTag);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", notApacheLog);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        assertHasTag(e, failureTag);
    }

    @Test
    public void testMultipleMatchesInSingleField() {
        Map<String, Object> config = new HashMap<>();

        Map<String, Object> matches = new HashMap<>();
        matches.put("message", Arrays.asList(
                "%{IP:client1} %{WORD:method1} %{URIPATHPARAM:request1} %{NUMBER:bytes1} %{NUMBER:duration1}",
                "%{COMBINEDAPACHELOG}"));
        config.put(MATCH.name(), matches);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));
        Event e = new org.logstash.Event();
        e.setField("message", APACHE_LOG_LINE);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        validateApacheLogLine(resultEvent);
    }

    @Test
    public void testMultipleMatchesInSingleEvent() {
        Map<String, Object> config = new HashMap<>();


        Map<String, String> matches = new HashMap<>();
        matches.put("message1", "%{IP:client1} %{WORD:method1} %{URIPATHPARAM:request1} %{NUMBER:bytes1} %{NUMBER:duration1}");
        matches.put("message2", "%{COMBINEDAPACHELOG}");
        config.put(MATCH.name(), matches);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));
        Event e = new org.logstash.Event();
        e.setField("message1", SIMPLE_LOG_LINE);
        e.setField("message2", APACHE_LOG_LINE);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        validateSimpleLogLine(resultEvent, "1");
        validateApacheLogLine(resultEvent);
    }

    @Test
    public void testGrokTimeout() {
        String matchPatterns = "Bonsuche mit folgender Anfrage: Belegart->\\[%{WORD:param2},(?<param5>(\\s*%{NOTSPACE})*)\\] Zustand->ABGESCHLOSSEN Kassennummer->%{WORD:param9} Bonnummer->%{WORD:param10} Datum->%{DATESTAMP_OTHER:param11}";
        String fieldValue = "Bonsuche mit folgender Anfrage: Belegart->[EINGESCHRAENKTER_VERKAUF, VERKAUF, NACHERFASSUNG] Zustand->ABGESCHLOSSEN Kassennummer->2 Bonnummer->6362 Datum->Mon Jan 08 00:00:00 UTC 2018";
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", matchPatterns));
        config.put(TIMEOUT_MILLIS.name(), 100L);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e1 = new org.logstash.Event();
        e1.setField("message", fieldValue);
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e1), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        assertHasTag(e1, "_groktimeout");
    }

    @Test
    public void testOverwrite() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}"));
        config.put(OVERWRITE.name(), Arrays.asList("method", "bytes"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "55.3.244.1 GET /index.html 15824 0.043");
        e.setField("method", "originalMethodValue");
        e.setField("request", "originalRequestValue");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertEquals("55.3.244.1", resultEvent.getField("client"));
        Assert.assertEquals("GET", resultEvent.getField("method"));
        Assert.assertEquals("originalRequestValue", resultEvent.getField("request"));
        Assert.assertEquals("15824", resultEvent.getField("bytes"));
        Assert.assertEquals("0.043", resultEvent.getField("duration"));
    }

    @Test
    public void testExtraPatternDefinitions() {
        Map<String, Object> config = new HashMap<>();
        config.put(PATTERN_DEFINITIONS.name(), Collections.singletonMap("TESTPATTERN", "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}"));
        config.put(MATCH.name(), Collections.singletonMap("message", "%{TESTPATTERN}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", SIMPLE_LOG_LINE);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        validateSimpleLogLine(resultEvent);
    }

    @Test
    public void testPatternDirsForMissingPattern() throws IOException {
        Path[] dirs = new Path[0];
        try {
            dirs = setupPatternsDirTest();

            Map<String, Object> config = new HashMap<>();
            config.put(PATTERNS_DIR.name(), Arrays.asList(dirs[0].toString(), dirs[1].toString()));
            config.put(PATTERNS_FILES_GLOB.name(), "*.txt");
            config.put(MATCH.name(), Collections.singletonMap("message", "%{TESTPATTERN2}"));

            Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

            Event e = new org.logstash.Event();
            e.setField("message", SIMPLE_LOG_LINE);

            TestFilterMatchListener matchListener = new TestFilterMatchListener();
            jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.fail("Glob pattern should have excluded pattern2.conf file");
        } catch (IllegalArgumentException ex) {
            if (!ex.getMessage().equals("Unable to find pattern [TESTPATTERN2] in Grok's pattern dictionary")) {
                Assert.fail("Unexpected exception encountered: " + ex);
            }
        } finally {
            tearDownPatternsDirTest(dirs);
        }
    }

    private static Path[] setupPatternsDirTest() throws IOException {
        Path tempDir1 = Files.createTempDirectory("logstash_test");
        Path tempDir2 = Files.createTempDirectory("logstash_test");

        Path tempFile1 = tempDir1.resolve("pattern1.txt");
        Files.write(tempFile1, "TESTPATTERN1, %{IP:client1} %{WORD:method1} %{URIPATHPARAM:request1} %{NUMBER:bytes1} %{NUMBER:duration1}".getBytes());
        Path tempFile2 = tempDir1.resolve("pattern2.conf");
        Files.write(tempFile2, "TESTPATTERN2, %{IP:client2} %{WORD:method2} %{URIPATHPARAM:request2} %{NUMBER:bytes2} %{NUMBER:duration2}".getBytes());
        Path tempFile3 = tempDir2.resolve("pattern3.txt");
        Files.write(tempFile3, "TESTPATTERN3, %{IP:client3} %{WORD:method3} %{URIPATHPARAM:request3} %{NUMBER:bytes3} %{NUMBER:duration3}".getBytes());

        return new Path[]{tempDir1, tempDir2};
    }

    private static void tearDownPatternsDirTest(Path[] dirs) throws IOException {
        for (Path dir : dirs) {
            deleteDir(dir);
        }
    }

    @Test
    public void testPatternsDir() throws IOException {
        Path[] dirs = new Path[0];
        try {
            dirs = setupPatternsDirTest();

            Map<String, Object> config = new HashMap<>();
            config.put(PATTERNS_DIR.name(), Arrays.asList(dirs[0].toString(), dirs[1].toString()));
            config.put(PATTERNS_FILES_GLOB.name(), "*.txt");
            config.put(MATCH.name(), Collections.singletonMap("message", "%{TESTPATTERN3}"));

            Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

            Event e = new org.logstash.Event();
            e.setField("message", SIMPLE_LOG_LINE);

            TestFilterMatchListener matchListener = new TestFilterMatchListener();
            Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.assertEquals(1, result.size());
            Assert.assertEquals(1, matchListener.matchCount());
            Event resultEvent = result.stream().findFirst().get();
            validateSimpleLogLine(resultEvent, "3");
        } finally {
            tearDownPatternsDirTest(dirs);
        }
    }

    private static void deleteDir(Path dir) throws IOException {
        if (dir != null) {
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    private static void assertHasTag(Event e, String tag) {
        List eventTags = (List) e.getField("tags");
        Assert.assertTrue(eventTags.contains(tag));
    }

    private static void validateSimpleLogLine(Event e) {
        validateSimpleLogLine(e, "");
    }

    private static void validateSimpleLogLine(Event e, String suffix) {
        Assert.assertEquals("55.3.244.1", e.getField("client" + suffix));
        Assert.assertEquals("GET", e.getField("method" + suffix));
        Assert.assertEquals("/index.html", e.getField("request" + suffix));
        Assert.assertEquals("15824", e.getField("bytes" + suffix));
        Assert.assertEquals("0.043", e.getField("duration" + suffix));
    }
    
    private static void validateApacheLogLine(Event e) {
        Assert.assertEquals("GET", e.getField("verb"));
        Assert.assertEquals("/xampp/status.php", e.getField("request"));
        Assert.assertEquals("11/Dec/2013:00:01:45 -0800", e.getField("timestamp"));
        Assert.assertEquals("\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"", e.getField("agent"));
        Assert.assertEquals("127.0.0.1", e.getField("clientip"));
        Assert.assertEquals("-", e.getField("ident"));
        Assert.assertEquals("-", e.getField("auth"));
        Assert.assertEquals("1.1", e.getField("httpversion"));
        Assert.assertEquals("200", e.getField("response"));
        Assert.assertEquals("3891", e.getField("bytes"));
        Assert.assertEquals("\"http://cadenza/xampp/navi.php\"", e.getField("referrer"));
    }
}

class TestFilterMatchListener implements FilterMatchListener {

    private int matchCount;

    @Override
    public void filterMatched(Event event) {
        matchCount++;
    }

    public int matchCount() {
        return matchCount;
    }
}
