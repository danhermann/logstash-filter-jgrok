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
import java.util.Map;

public class JgrokTest {

    @Test
    public void testSimpleGrok() {
        Map<String, Object> config = new HashMap<>();
        config.put("match_pattern", "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}");

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "55.3.244.1 GET /index.html 15824 0.043");

        Collection<Event> result = jgrok.filter(Collections.singletonList(e), new TestFilterMatchListener());
        Assert.assertEquals(1, result.size());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertEquals("55.3.244.1", resultEvent.getField("client") );
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
        config.put("match_pattern", "%{COMBINEDAPACHELOG}");

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", apacheLog);

        Collection<Event> result = jgrok.filter(Collections.singletonList(e), new TestFilterMatchListener());
        Assert.assertEquals(1, result.size());
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
}

class TestFilterMatchListener implements FilterMatchListener {

    @Override
    public void filterMatched(Event event) {
        // do nothing
    }
}