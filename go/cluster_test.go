package main

import (
	"regexp"
	"strings"
	"testing"
)

// A single capability with no threat says nothing: ordinary code decodes
// base64, spawns processes and builds strings all day. But several distinct
// capabilities stacked in one file is a shape, even with no threat rule
// matching. `atob` then `eval` is the classic loader stager, and untyped
// pairing alone cannot see it because neither half is a threat.

func capProbeA() Pattern {
	return Pattern{
		Name: "cap-a", Risk: MediumRisk, Description: "capability A",
		Regex: regexp.MustCompile(`AAA`), Identifies: Capability,
	}
}

func capProbeB() Pattern {
	return Pattern{
		Name: "cap-b", Risk: MediumRisk, Description: "capability B",
		Regex: regexp.MustCompile(`BBB`), Identifies: Capability,
	}
}

func clusterProbes() []Pattern {
	return []Pattern{capProbeA(), capProbeB(), threatProbe()}
}

func TestTwoCapabilitiesWithNoThreatAreReported(t *testing.T) {
	got := scanContentWith(t, "x.js", "AAA and BBB", clusterProbes())
	fired := firedPatterns(got)
	if !fired["cap-a"] || !fired["cap-b"] {
		t.Errorf("two co-occurring capabilities were suppressed; got %v", fired)
	}
}

func TestSingleCapabilityWithNoThreatIsStillSuppressed(t *testing.T) {
	got := scanContentWith(t, "x.js", "AAA only", clusterProbes())
	if len(got) != 0 {
		t.Errorf("a lone capability was reported; got %v", got)
	}
}

// One rule matching many times is still one capability. The signal is
// distinct abilities co-occurring, not match volume.
func TestRepeatedSingleCapabilityIsStillSuppressed(t *testing.T) {
	got := scanContentWith(t, "x.js", strings.Repeat("AAA\n", 10), clusterProbes())
	if len(got) != 0 {
		t.Errorf("one capability repeated was reported as a cluster; got %v", got)
	}
}

// A clustered capability should say what justified it, so a reader can tell
// it was co-occurrence rather than a threat.
func TestClusteredCapabilityNamesItsCompanion(t *testing.T) {
	got := scanContentWith(t, "x.js", "AAA and BBB", clusterProbes())
	for _, f := range got {
		if f.Identifies != string(Capability) {
			t.Errorf("%s: identifies=%q, want capability", f.Name, f.Identifies)
		}
		if f.PairedWith == "" {
			t.Errorf("%s: paired_with is empty; it should name the companion capability", f.Name)
		}
	}
	byName := map[string]string{}
	for _, f := range got {
		byName[f.Name] = f.PairedWith
	}
	if byName["cap-a"] != "cap-b" {
		t.Errorf("cap-a paired_with = %q, want cap-b", byName["cap-a"])
	}
	if byName["cap-b"] != "cap-a" {
		t.Errorf("cap-b paired_with = %q, want cap-a", byName["cap-b"])
	}
}

// When a real threat is present it remains the citation, not the cluster.
func TestThreatStillWinsAsThePairingPartner(t *testing.T) {
	got := scanContentWith(t, "x.js", "AAA and BBB and THREAT", clusterProbes())
	for _, f := range got {
		if f.Identifies == string(Capability) && f.PairedWith != "threat-probe" {
			t.Errorf("%s paired_with = %q, want threat-probe", f.Name, f.PairedWith)
		}
	}
}

// End to end on the shape that motivated this: the two-line JS stager, which
// went silent when base64 and eval-exec were both demoted to capabilities.
func TestRealStagerShapeIsReported(t *testing.T) {
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	fired := firedPatterns(scanContentPatterns(t, "stager.js",
		"const p = atob(blob);\neval(p);", s.Patterns))

	if !fired["base64"] || !fired["eval-exec"] {
		t.Errorf("the atob/eval stager is still silent; fired = %v", fired)
	}
}

// scanContentWith runs an explicit pattern set over one file's content.
func scanContentWith(t *testing.T, filename, content string, patterns []Pattern) []Finding {
	t.Helper()
	return scanWith(t, filename, content, patterns)
}

// scanContentPatterns is the same thing, named for readability at call sites
// that pass the real shipped ruleset.
func scanContentPatterns(t *testing.T, filename, content string, patterns []Pattern) []Finding {
	t.Helper()
	return scanWith(t, filename, content, patterns)
}

// Several rules matching the SAME text are one construct seen twice, not a
// cluster. String.fromCharCode trips both char-codes and js-obfuscation at
// the identical span; treating that as evidence would report every file that
// builds a string from character codes.
func TestOverlappingCapabilitiesDoNotCluster(t *testing.T) {
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	fired := firedPatterns(scanContentPatterns(t, "x.js",
		`var s = String.fromCharCode(104, 105);`, s.Patterns))

	if fired["char-codes"] || fired["js-obfuscation"] {
		t.Errorf("overlapping rules on one construct formed a cluster; fired = %v", fired)
	}
}

// Two capabilities on the SAME line still cluster when they match different
// text: a subprocess call and a paste-site URL are two different things.
func TestSameLineButDistinctTextDoesCluster(t *testing.T) {
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	fired := firedPatterns(scanContentPatterns(t, "f.py",
		`subprocess.Popen(["curl", "https://pastebin.com/raw/aaa"])`, s.Patterns))

	if !fired["eval-exec"] || !fired["shady-urls"] {
		t.Errorf("distinct capabilities on one line failed to cluster; fired = %v", fired)
	}
}
