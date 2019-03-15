package co.elastic.logstash.plugins.filters;

import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.FilterMatchListener;
import org.junit.Assert;
import org.junit.Test;
import org.logstash.plugins.ConfigurationImpl;
import org.logstash.plugins.ContextImpl;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static co.elastic.logstash.plugins.filters.Jgrok.MATCH;
import static co.elastic.logstash.plugins.filters.Jgrok.MAX_EXECUTION_TIME_MILLIS;

public class JgrokTest {

    @Test
    public void testSimpleGrok() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "55.3.244.1 GET /index.html 15824 0.043");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertEquals("55.3.244.1", resultEvent.getField("client"));
        Assert.assertEquals("GET", resultEvent.getField("method"));
        Assert.assertEquals("/index.html", resultEvent.getField("request"));
        Assert.assertEquals("15824", resultEvent.getField("bytes"));
        Assert.assertEquals("0.043", resultEvent.getField("duration"));
    }

    @Test
    public void testApacheLogs() {
        String apacheLog =
                "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"";
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{COMBINEDAPACHELOG}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", apacheLog);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();

        Assert.assertEquals("GET", resultEvent.getField("verb"));
        Assert.assertEquals("/xampp/status.php", resultEvent.getField("request"));
        Assert.assertEquals("11/Dec/2013:00:01:45 -0800", resultEvent.getField("timestamp"));
        Assert.assertEquals("\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"", resultEvent.getField("agent"));
        Assert.assertEquals("127.0.0.1", resultEvent.getField("clientip"));
        Assert.assertEquals("-", resultEvent.getField("ident"));
        Assert.assertEquals("-", resultEvent.getField("auth"));
        Assert.assertEquals("1.1", resultEvent.getField("httpversion"));
        Assert.assertEquals("200", resultEvent.getField("response"));
        Assert.assertEquals("3891", resultEvent.getField("bytes"));
        Assert.assertEquals("\"http://cadenza/xampp/navi.php\"", resultEvent.getField("referrer"));
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
    }

    @Test
    public void testMultipleMatchesInSingleEvent() {
        Map<String, Object> config = new HashMap<>();

        Map<String, String> matches = new HashMap<>();
        matches.put("message1", "%{IP:client1} %{WORD:method1} %{URIPATHPARAM:request1} %{NUMBER:bytes1} %{NUMBER:duration1}");
        matches.put("message2", "%{COMBINEDAPACHELOG}");
        config.put(MATCH.name(), matches);

        String apacheLog =
                "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"";

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));
        Event e = new org.logstash.Event();
        e.setField("message1", "55.3.244.1 GET /index.html 15824 0.043");
        e.setField("message2", apacheLog);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertEquals("55.3.244.1", resultEvent.getField("client1"));
        Assert.assertEquals("GET", resultEvent.getField("method1"));
        Assert.assertEquals("/index.html", resultEvent.getField("request1"));
        Assert.assertEquals("15824", resultEvent.getField("bytes1"));
        Assert.assertEquals("0.043", resultEvent.getField("duration1"));

        Assert.assertEquals("GET", resultEvent.getField("verb"));
        Assert.assertEquals("/xampp/status.php", resultEvent.getField("request"));
        Assert.assertEquals("11/Dec/2013:00:01:45 -0800", resultEvent.getField("timestamp"));
        Assert.assertEquals("\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"", resultEvent.getField("agent"));
        Assert.assertEquals("127.0.0.1", resultEvent.getField("clientip"));
        Assert.assertEquals("-", resultEvent.getField("ident"));
        Assert.assertEquals("-", resultEvent.getField("auth"));
        Assert.assertEquals("1.1", resultEvent.getField("httpversion"));
        Assert.assertEquals("200", resultEvent.getField("response"));
        Assert.assertEquals("3891", resultEvent.getField("bytes"));
        Assert.assertEquals("\"http://cadenza/xampp/navi.php\"", resultEvent.getField("referrer"));
    }

    @Test
    public void testGrokTimeout() {
        String matchPatterns = "Bonsuche mit folgender Anfrage: Belegart->\\[%{WORD:param2},(?<param5>(\\s*%{NOTSPACE})*)\\] Zustand->ABGESCHLOSSEN Kassennummer->%{WORD:param9} Bonnummer->%{WORD:param10} Datum->%{DATESTAMP_OTHER:param11}";
        String fieldValue = "Bonsuche mit folgender Anfrage: Belegart->[EINGESCHRAENKTER_VERKAUF, VERKAUF, NACHERFASSUNG] Zustand->ABGESCHLOSSEN Kassennummer->2 Bonnummer->6362 Datum->Mon Jan 08 00:00:00 UTC 2018";
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", matchPatterns));
        config.put(MAX_EXECUTION_TIME_MILLIS.name(), 100L);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e1 = new org.logstash.Event();
        e1.setField("message", fieldValue);
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e1), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        List eventTags = (List) e1.getField("tags");
        Assert.assertTrue(eventTags.contains("_groktimeout"));
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
