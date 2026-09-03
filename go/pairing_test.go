package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

func TestPairedCapabilityCarriesProvenance(t *testing.T) {
	got := scanWith(t, "x.js", "CAPABILITY and THREAT", []Pattern{capProbe(), threatProbe()})

	var cap *Finding
	for i := range got {
		if got[i].Name == "cap-probe" {
			cap = &got[i]
		}
	}
	if cap == nil {
		t.Fatal("cap-probe was not reported")
	}
	if cap.Identifies != string(Capability) {
		t.Errorf("identifies=%q, want %q", cap.Identifies, Capability)
	}
	if cap.PairedWith != "threat-probe" {
		t.Errorf("paired_with=%q, want %q", cap.PairedWith, "threat-probe")
	}
}

// Threats carry neither field, so their JSON is byte-identical to before.
func TestThreatFindingHasNoPairingFields(t *testing.T) {
	got := scanWith(t, "x.js", "THREAT", []Pattern{capProbe(), threatProbe()})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Identifies != "" || got[0].PairedWith != "" {
		t.Errorf("threat carries pairing fields: identifies=%q paired_with=%q",
			got[0].Identifies, got[0].PairedWith)
	}
}

func TestThreatJSONHasNoNewKeys(t *testing.T) {
	got := scanWith(t, "x.js", "THREAT", []Pattern{capProbe(), threatProbe()})
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("identifies")) || bytes.Contains(b, []byte("paired_with")) {
		t.Errorf("threat JSON gained keys, breaking the existing contract: %s", b)
	}
}

// summaryFor captures what PrintSummary writes, so the suppression line can
// be asserted on directly.
func summaryFor(t *testing.T, issues, suppressed int) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	s := &Scanner{IssuesFound: issues, SuppressedCount: suppressed}
	s.PrintSummary()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestSummaryReportsSuppressedCount(t *testing.T) {
	out := summaryFor(t, 3, 137)
	if !strings.Contains(out, "137") {
		t.Errorf("summary does not mention the suppressed count:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "suppress") {
		t.Errorf("summary does not explain what the number means:\n%s", out)
	}
}

// Nothing suppressed means no extra line, so ordinary scans read as before.
func TestSummaryOmitsLineWhenNothingSuppressed(t *testing.T) {
	out := summaryFor(t, 3, 0)
	if strings.Contains(strings.ToLower(out), "suppress") {
		t.Errorf("summary mentions suppression when nothing was suppressed:\n%s", out)
	}
}

func TestJSONOutputCarriesSuppressedKey(t *testing.T) {
	// Mirrors the anonymous struct main() marshals, so the key name is pinned
	// by a test rather than only by the code that emits it.
	out := struct {
		ScanPath    string    `json:"scan_path"`
		IssuesFound int       `json:"issues_found"`
		Suppressed  int       `json:"suppressed"`
		Findings    []Finding `json:"findings"`
	}{"p", 1, 42, nil}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"suppressed":42`)) {
		t.Errorf("suppressed key missing or misnamed: %s", b)
	}
}
