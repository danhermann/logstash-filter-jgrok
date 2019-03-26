package co.elastic.logstash.plugins.filters;

import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.PluginHelper;
import org.junit.Assert;
import org.junit.Test;
import org.logstash.plugins.ConfigurationImpl;
import org.logstash.plugins.ContextImpl;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static co.elastic.logstash.plugins.filters.Jgrok.BREAK_ON_MATCH;
import static co.elastic.logstash.plugins.filters.Jgrok.MATCH;
import static co.elastic.logstash.plugins.filters.Jgrok.NAMED_CAPTURES_ONLY;
import static co.elastic.logstash.plugins.filters.Jgrok.OVERWRITE;
import static co.elastic.logstash.plugins.filters.Jgrok.TAG_ON_FAILURE;
import static co.elastic.logstash.plugins.filters.Jgrok.TIMEOUT_MILLIS;

// partial port of grok_spec.rb to Java
public class GrokSpecs {

    @Test
    public void testSimpleSyslogLine() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{SYSLOGLINE}"));
        config.put(OVERWRITE.name(), Arrays.asList("message"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertNull(resultEvent.getField("tags"));
        Assert.assertEquals("evita", resultEvent.getField("logsource"));
        Assert.assertEquals("Mar 16 00:01:25", resultEvent.getField("timestamp"));
        Assert.assertEquals("connect from camomile.cloud9.net[168.100.1.3]", resultEvent.getField("message"));
        Assert.assertEquals("postfix/smtpd", resultEvent.getField("program"));
        Assert.assertEquals("1713", resultEvent.getField("pid"));
    }

    @Test
    public void testIetf5424SyslogLine() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{SYSLOG5424LINE}"));
        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - [id1 foo=\"bar\"][id2 baz=\"something\"] Hello, syslog.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        "4123",
                        null,
                        "[id1 foo=\"bar\"][id2 baz=\"something\"]",
                        "Hello, syslog."
                });


        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - [id1 foo=\"bar\"] No process ID.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        null,
                        null,
                        "[id1 foo=\"bar\"]",
                        "No process ID."
                });

        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - - No structured data.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        "4123",
                        null,
                        null,
                        "No structured data."
                });


        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - - No PID or SD.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        null,
                        null,
                        null,
                        "No PID or SD."
                });

        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 -  Missing structured data.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        "4123",
                        null,
                        null,
                        "Missing structured data."
                });

        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 - - Additional spaces.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        "4123",
                        null,
                        null,
                        "Additional spaces."
                });

        validateIetf5424Syslog(jgrok, "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 -  Additional spaces and missing SD.",
                new Object[]{
                        null,
                        "191",
                        "1",
                        "2009-06-30T18:30:00+02:00",
                        "paxton.local",
                        "grokdebug",
                        "4123",
                        null,
                        null,
                        "Additional spaces and missing SD."
                });

        validateIetf5424Syslog(jgrok, "<30>1 2014-04-04T16:44:07+02:00 osctrl01 dnsmasq-dhcp 8048 - -  Appname contains a dash",
                new Object[]{
                        null,
                        "30",
                        "1",
                        "2014-04-04T16:44:07+02:00",
                        "osctrl01",
                        "dnsmasq-dhcp",
                        "8048",
                        null,
                        null,
                        "Appname contains a dash"
                });

        validateIetf5424Syslog(jgrok, "<30>1 2014-04-04T16:44:07+02:00 osctrl01 - 8048 - -  Appname is nil",
                new Object[]{
                        null,
                        "30",
                        "1",
                        "2014-04-04T16:44:07+02:00",
                        "osctrl01",
                        null,
                        "8048",
                        null,
                        null,
                        "Appname is nil"
                });
    }

    private static void validateIetf5424Syslog(Jgrok jgrok, String input, Object[] outputs) {
        Event e = new org.logstash.Event();
        e.setField("message", input);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertEquals(outputs[0], resultEvent.getField("tags"));
        Assert.assertEquals(outputs[1], resultEvent.getField("syslog5424_pri"));
        Assert.assertEquals(outputs[2], resultEvent.getField("syslog5424_ver"));
        Assert.assertEquals(outputs[3], resultEvent.getField("syslog5424_ts"));
        Assert.assertEquals(outputs[4], resultEvent.getField("syslog5424_host"));
        Assert.assertEquals(outputs[5], resultEvent.getField("syslog5424_app"));
        Assert.assertEquals(outputs[6], resultEvent.getField("syslog5424_proc"));
        Assert.assertEquals(outputs[7], resultEvent.getField("syslog5424_msgid"));
        Assert.assertEquals(outputs[8], resultEvent.getField("syslog5424_sd"));
        Assert.assertEquals(outputs[9], resultEvent.getField("syslog5424_msg"));
    }

    @Test
    public void testMessageWithArrayOfStrings() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "(?:hello|world) %{NUMBER:number}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", Arrays.asList("hello 12345", "world 23456"));

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertNull(resultEvent.getField("tags"));
        Assert.assertEquals(Arrays.asList("12345", "23456"), e.getField("number"));
    }

    @Test
    public void testCoercingMatchedValues() {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "%{NUMBER:foo:int} %{NUMBER:bar:float}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "400 454.33");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertNull(resultEvent.getField("tags"));
        Object foo = resultEvent.getField("foo");
        Assert.assertEquals(400L, foo);
        Assert.assertTrue(foo instanceof Long);
        Object bar = resultEvent.getField("bar");
        Assert.assertTrue(bar instanceof Double);
        Assert.assertEquals(454.33, (Double) bar, 0.01);
    }

    @Test
    public void testInlinePattern() {
        try {
            basicGrokTest("%{FIZZLE=\\d+}", "hello 1234", Collections.singletonMap("FIZZLE", "1234"));
            Assert.fail("this is expected to fail");
        } catch (IllegalStateException ae) {
            if (!ae.getMessage().equals("Unable to initialize grok entry")) {
                Assert.fail("unexpected exception: " + ae);
            }

            // Java grok does not support inline patterns
        }
    }

    @Test
    public void testSelectedFields() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new HashMap<>();
        match.put("message", "%{WORD:word}");
        match.put("examplefield", "%{NUMBER:num}");
        config.put(MATCH.name(), match);
        config.put(BREAK_ON_MATCH.name(), false);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "hello world");
        e.setField("examplefield", "12345");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertNull(resultEvent.getField("tags"));
        Assert.assertEquals("12345", resultEvent.getField("num"));
        Assert.assertEquals("hello", resultEvent.getField("word"));
    }

    @Test
    public void testAddFieldOnMatch() {
        // filter actions happen in the java plugin pipeline, not in the plugin itself, so this test would pass
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", "matchme %{NUMBER:fancy}"));
        config.put(PluginHelper.ADD_FIELD_CONFIG.name(), Arrays.asList("new_field", "%{fancy}"));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "matchme 1234");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        Assert.assertNull(resultEvent.getField("tags"));
    }

    @Test
    public void testEmptyFields1() {
        Event e = basicGrokTest("1=%{WORD:foo1} *(2=%{WORD:foo2})?", "1=test", Collections.singletonMap("foo1", "test"));
        Assert.assertNull(e.getField("foo2"));
    }

    @Test
    public void testEmptyFields2() {
        try {
            Event e = basicGrokTest("1=%{WORD:foo1} *(2=%{WORD:foo2})?", "1=test", Collections.singletonMap("foo1", "test"));
            Assert.assertNotNull(e.getField("foo2"));
            Assert.fail("this is expected to fail");
        } catch (AssertionError ae) {
            // fails because keep_empty_captures not supported
        }
    }

    @Test
    public void testNotNamedCapturesOnly() {
        try {
            Map<String, Object> config = new HashMap<>();
            config.put(MATCH.name(), Collections.singletonMap("message", "Hello %{WORD}. %{WORD:foo}"));
            config.put(NAMED_CAPTURES_ONLY.name(), false);

            Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

            Event e = new org.logstash.Event();
            e.setField("message", "Hello World, yo!");

            TestFilterMatchListener matchListener = new TestFilterMatchListener();
            Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.assertEquals(1, result.size());
            Assert.assertEquals(1, matchListener.matchCount());
            Event resultEvent = result.stream().findFirst().get();
            Assert.assertEquals("World", e.getField("WORD"));
            Assert.assertEquals("yo", e.getField("foo"));

            Assert.fail("this is expected to fail");
        } catch (AssertionError ae) {
            // this fails because Java grok appends a match index to each unnamed capture
        }
    }

    @Test
    public void testOnigurumaNamedCaptures() {
        basicGrokTest("(?<foo>\\w+)", "hello world", Collections.singletonMap("foo", "hello"));
    }

    @Test
    public void testOnigurumaNamedCapturesWithGrokPattern() {
        basicGrokTest("(?<timestamp>%{DATE_EU} %{TIME})", "fancy 12-12-12 12:12:12", Collections.singletonMap("timestamp", "12-12-12 12:12:12"));
    }

    @Test
    public void testGrokOnIntegerTypes() {
        try {
            // test passes if match listener count == 1
            basicGrokTest("^403$", 403, Collections.singletonMap("message", 403));
            Assert.fail("this is expected to fail.");
        } catch (AssertionError ae) {
            // this is expected to fail because Java grok does not support integer type patterns
        }
    }

    @Test
    public void testGrokOnFloatTypes() {
        try {
            // test passes if match listener count == 1
            basicGrokTest("^1.0$", 1.0, Collections.emptyMap());
            Assert.fail("this is expected to fail");
        } catch (AssertionError ae) {
            // this is expected to fail because Java grok does not support float type patterns
        }
    }

    @Test
    public void testGrokOnLogLevel() {
        String[] logLevels = {"trace", "Trace", "TRACE", "debug", "Debug", "DEBUG", "notice", "Notice", "Notice",
                "info", "Info", "INFO", "warn", "warning", "Warn", "Warning", "WARN", "WARNING", "err", "error",
                "Err", "Error", "ERR", "ERROR", "crit", "critical", "Crit", "Critical", "CRIT", "CRITICAL", "fatal",
                "Fatal", "FATAL", "severe", "Severe", "SEVERE", "emerg", "emergency", "Emerg", "Emergency", "EMERG",
                "EMERGENCY"};
        for (String logLevel:logLevels) {
            basicGrokTest("%{LOGLEVEL:level}: error!", logLevel+": error!", Collections.singletonMap("level", logLevel));
        }
    }

    @Test
    public void testTimeoutOnFailure() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new HashMap<>();
        match.put("message", "(.*a){30}");
        config.put(MATCH.name(), match);
        config.put(TIMEOUT_MILLIS.name(), 100L);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        JgrokTest.assertHasTag(e, "_groktimeout");
        JgrokTest.assertDoesNotHaveTag(e, "_grokparsefailure");
    }

    @Test
    public void testTagOnFailure() {
        String notAMatch = "not_a_match";
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new HashMap<>();
        match.put("message", "matchme %{NUMBER:fancy}");
        config.put(MATCH.name(), match);
        config.put(TAG_ON_FAILURE.name(), notAMatch);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "matchme 1234");
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        JgrokTest.assertNoTags(e);

        e = new org.logstash.Event();
        e.setField("message", "this will not be matched");
        matchListener = new TestFilterMatchListener();
        result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        JgrokTest.assertHasTag(e, notAMatch);
    }

    @Test
    public void testNamedFieldsWithWholeTextMatch() {
        basicGrokTest("%{DATE_EU:stimestamp}", "11/01/01", Collections.singletonMap("stimestamp", "11/01/01"));
    }

    @Test
    public void testAllowDashesInCaptureName() {
        basicGrokTest("%{WORD:foo-bar}", "hello world", Collections.singletonMap("foo-bar", "hello"));
    }

    @Test
    public void testPerformance() {
        int event_count = 100000;
        int min_rate = 2000;
        int max_duration = event_count / min_rate;
        String logLine = "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]";

        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new HashMap<>();
        match.put("message", "%{SYSLOGLINE}");
        config.put(MATCH.name(), match);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", logLine);
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        for (int m = 0; m < 2; m++) {
            long startTime = System.nanoTime();
            for (int k = 0; k < event_count; k++) {
                jgrok.filter(Collections.singletonList(e), matchListener);
            }
            long elapsedTimeMilli = (System.nanoTime() - startTime) / 1_000_000L;
            System.out.println("Elapsed time (ms): " + elapsedTimeMilli);
            Assert.assertTrue((elapsedTimeMilli / 1000L) < max_duration);
        }
    }

    @Test
    public void testSingleValueMatchWithDuplicateFieldName() {
        Event e = basicGrokTest("%{INT:foo}|%{WORD:foo}", "hello world", Collections.emptyMap());
        Assert.assertTrue(e.getField("foo") instanceof String);

        e = basicGrokTest("%{INT:foo}|%{WORD:foo}", "123 world", Collections.emptyMap());
        Assert.assertTrue(e.getField("foo") instanceof String);
    }

    @Test
    public void testBreakOnMatchExitsFilter() {
        //Assert.fail("this needs a linked hash map to work");
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("message", "%{INT:foo}");
        match.put("somefield", "%{INT:bar}");
        config.put(MATCH.name(), match);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "hello world 123");
        e.setField("somefield", "testme abc 999");
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Assert.assertEquals("123", e.getField("foo"));
        Assert.assertNull(e.getField("bar"));
    }

    @Test
    public void testBreakOnMatchFalseTriesAllPatterns() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("message", "%{INT:foo}");
        match.put("somefield", "%{INT:bar}");
        config.put(MATCH.name(), match);
        config.put(BREAK_ON_MATCH.name(), false);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "hello world 123");
        e.setField("somefield", "testme abc 999");
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Assert.assertEquals("123", e.getField("foo"));
        Assert.assertEquals("999", e.getField("bar"));
    }

    @Test
    public void testBreakOnMatchWithMultiplePatternsInSingleField() {
        try {
            Map<String, Object> config = new HashMap<>();
            Map<String, Object> match = new LinkedHashMap<>();
            match.put("message", Arrays.asList("%{GREEDYDATA:name1}beard", "tree%{GREEDYDATA:name2}"));
            match.put("somefield", "%{INT:bar}");
            config.put(MATCH.name(), match);
            config.put(BREAK_ON_MATCH.name(), false);

            Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

            Event e = new org.logstash.Event();
            e.setField("message", "treebeard");
            TestFilterMatchListener matchListener = new TestFilterMatchListener();
            Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.assertEquals(1, result.size());
            Assert.assertEquals(1, matchListener.matchCount());
            Assert.assertEquals("branch", e.getField("name2"));

            e = new org.logstash.Event();
            e.setField("message", "bushbeard");
            matchListener = new TestFilterMatchListener();
            result = jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.assertEquals(1, result.size());
            Assert.assertEquals(1, matchListener.matchCount());
            Assert.assertEquals("bush", e.getField("name1"));

            e = new org.logstash.Event();
            e.setField("message", "treebeard");
            matchListener = new TestFilterMatchListener();
            result = jgrok.filter(Collections.singletonList(e), matchListener);
            Assert.assertEquals(1, result.size());
            Assert.assertEquals(1, matchListener.matchCount());
            Assert.assertEquals("tree", e.getField("name1"));
            Assert.assertEquals("beard", e.getField("name2"));

            Assert.fail("this is expected to fail");
        } catch (AssertionError ae) {
            // this test is expected to fail because Java grok
            // doesn't support break_on_match=false within a single field
        }
    }




    @Test
    public void testWithUnicode() {
        Map<String, Object> expected = new HashMap<>();
        expected.put("syslog_pri", "22");
        expected.put("syslog_program", "postfix/policy-spf");
        Event e = basicGrokTest(
                "<%{POSINT:syslog_pri}>%{SPACE}%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(:?)(?:\\[%{GREEDYDATA:syslog_pid}\\])?(:?) %{GREEDYDATA:syslog_message}",
                "<22>Jan  4 07:50:46 mailmaster postfix/policy-spf[9454]: : SPF permerror (Junk encountered in record 'v=spf1 mx a:mail.domain.no ip4:192.168.0.4 �all'): Envelope-from: email@domain.no",
                expected);
        JgrokTest.assertNoTags(e);
    }




    /*

  describe  "grok with unicode" do
    config <<-CONFIG
      filter {
        grok {
          #match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
          match => { "message" => "<%{POSINT:syslog_pri}>%{SPACE}%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(:?)(?:\\[%{GREEDYDATA:syslog_pid}\\])?(:?) %{GREEDYDATA:syslog_message}" }
        }
      }
    CONFIG

    sample "<22>Jan  4 07:50:46 mailmaster postfix/policy-spf[9454]: : SPF permerror (Junk encountered in record 'v=spf1 mx a:mail.domain.no ip4:192.168.0.4 �all'): Envelope-from: email@domain.no" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog_pri") } == "22"
      insist { subject.get("syslog_program") } == "postfix/policy-spf"
    end
  end


     */


    @Test
    public void testNilCoercedValue() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("message", "test (N/A|%{BASE10NUM:duration:float}ms)");
        config.put(MATCH.name(), match);

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", "test N/A");
        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(0, matchListener.matchCount());
        Assert.assertNull(e.getField("duration"));
    }

    @Test
    public void testWithoutCoercion1() {
        basicGrokTest("test (N/A|%{BASE10NUM:duration}ms)", "test 28.4ms", Collections.singletonMap("duration", "28.4"));
    }

    @Test
    public void testWithoutCoercion2() {
        try {
            basicGrokTest("test (N/A|%{BASE10NUM:duration}ms)", "test N/A", Collections.singletonMap("duration", null));
            Assert.fail("This is expected to fail");
        } catch (AssertionError ae) {
            // Java grok exhibits a difference in matching behavior here
        }
    }

    private static Event basicGrokTest(String pattern, Object fieldValue, Map<String, Object> expectedResults) {
        Map<String, Object> config = new HashMap<>();
        config.put(MATCH.name(), Collections.singletonMap("message", pattern));

        Jgrok jgrok = new Jgrok("test-jgrok", new ConfigurationImpl(config), new ContextImpl(null));

        Event e = new org.logstash.Event();
        e.setField("message", fieldValue);

        TestFilterMatchListener matchListener = new TestFilterMatchListener();
        Collection<Event> result = jgrok.filter(Collections.singletonList(e), matchListener);
        Assert.assertEquals(1, result.size());
        Assert.assertEquals(1, matchListener.matchCount());
        Event resultEvent = result.stream().findFirst().get();
        for (Map.Entry<String, Object> entry : expectedResults.entrySet()) {
            Assert.assertEquals(entry.getValue(), resultEvent.getField(entry.getKey()));
        }
        return resultEvent;
    }


}
