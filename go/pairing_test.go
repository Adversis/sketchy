package main

import "testing"

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
