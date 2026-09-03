package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The zero value must mean threat. A rule nobody classifies has to behave
// exactly as it does today, which is what makes the opt-in migration safe.
func TestZeroValueIdentifiesIsThreat(t *testing.T) {
	var p Pattern
	if p.isCapability() {
		t.Error("zero-value Pattern reports as capability; it must default to threat")
	}
	if p.Identifies != Threat {
		t.Errorf("zero value is %q, want %q", p.Identifies, Threat)
	}
}

func TestCapabilityPatternReportsAsCapability(t *testing.T) {
	p := Pattern{Identifies: Capability}
	if !p.isCapability() {
		t.Error("Pattern with Identifies=Capability does not report as capability")
	}
}

// Every rule in the shipped set must default to threat at this stage. This
// test is what proves Task 1 changes no behaviour.
func TestAllShippedRulesAreThreatsInitially(t *testing.T) {
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	for _, p := range s.Patterns {
		if p.isCapability() {
			t.Errorf("rule %q is already a capability; Task 1 must not reclassify anything", p.Name)
		}
	}
}

func capProbe() Pattern {
	return Pattern{
		Name: "cap-probe", Risk: MediumRisk, Description: "capability probe",
		Regex: regexp.MustCompile(`CAPABILITY`), Identifies: Capability,
	}
}

func threatProbe() Pattern {
	return Pattern{
		Name: "threat-probe", Risk: HighRisk, Description: "threat probe",
		Regex: regexp.MustCompile(`THREAT`),
	}
}

func TestCapabilityAloneIsSuppressed(t *testing.T) {
	got := scanWith(t, "x.js", "CAPABILITY", []Pattern{capProbe(), threatProbe()})
	if len(got) != 0 {
		t.Errorf("capability with no paired threat produced %d findings, want 0", len(got))
	}
}

func TestThreatAloneIsReported(t *testing.T) {
	got := scanWith(t, "x.js", "THREAT", []Pattern{capProbe(), threatProbe()})
	if len(got) != 1 || got[0].Name != "threat-probe" {
		t.Errorf("threat alone produced %v, want one threat-probe finding", got)
	}
}

func TestCapabilityPairsWithThreatInSameFile(t *testing.T) {
	got := scanWith(t, "x.js", "CAPABILITY and THREAT", []Pattern{capProbe(), threatProbe()})
	names := map[string]bool{}
	for _, f := range got {
		names[f.Name] = true
	}
	if !names["cap-probe"] || !names["threat-probe"] {
		t.Errorf("expected both probes reported, got %v", got)
	}
}

// The severity filter must not change which capabilities pair. A HIGH threat
// plus a MEDIUM capability has to unlock the capability under -high-only too,
// otherwise the filter silently changes detection semantics.
func TestHighOnlyDoesNotChangePairing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.js")
	if err := os.WriteFile(path, []byte("CAPABILITY and THREAT"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, level := range []FilterLevel{FilterAll, FilterHigh} {
		s := &Scanner{
			ScanPath: dir, FilterLevel: level, MaxFileSize: 1 << 20,
			IgnoreDirs: map[string]struct{}{}, JSONOutput: true,
			Patterns: []Pattern{capProbe(), threatProbe()},
		}
		s.checkFile(path)
		if s.IssuesFound != 2 {
			t.Errorf("filter %s: IssuesFound=%d, want 2 (pairing must ignore the display filter)",
				level, s.IssuesFound)
		}
	}
}

func TestSuppressedCapabilityDoesNotCountAsIssue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.js")
	if err := os.WriteFile(path, []byte("CAPABILITY"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{
		ScanPath: dir, FilterLevel: FilterAll, MaxFileSize: 1 << 20,
		IgnoreDirs: map[string]struct{}{}, JSONOutput: true,
		Patterns: []Pattern{capProbe(), threatProbe()},
	}
	s.checkFile(path)
	if s.IssuesFound != 0 {
		t.Errorf("IssuesFound=%d after a suppressed capability, want 0", s.IssuesFound)
	}
}
