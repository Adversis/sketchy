package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateGolden regenerates the golden file instead of asserting against it:
//
//	go test ./... -update-golden
//
// Regenerating is a deliberate act. The diff it produces is the review
// artifact for any change to the ruleset.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/golden.json from current scanner output")

const goldenPath = "testdata/golden.json"

// goldenEntry is a finding reduced to the fields that must stay stable.
// Preview text is deliberately excluded: it is cosmetic, and including it
// would make the golden file churn on unrelated fixture edits.
type goldenEntry struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Name string `json:"name"`
	Risk string `json:"risk"`
}

// scanCorpus runs a full walk of dir exactly as the CLI would, and returns
// findings in a deterministic order.
func scanCorpus(t *testing.T, dir string) []goldenEntry {
	t.Helper()

	s := NewScanner(dir, FilterAll, true, map[string]struct{}{})
	s.JSONOutput = true
	if err := s.Scan(); err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}

	out := make([]goldenEntry, 0, len(s.Findings))
	for _, f := range s.Findings {
		out = append(out, goldenEntry{
			File: filepath.ToSlash(f.File),
			Line: f.Line,
			Name: f.Name,
			Risk: f.Risk,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// TestGoldenCorpus pins the scanner's output over the checked-in sample tree.
// Adding a rule should only ever ADD lines here. A removed or changed line
// means an existing detection moved, which is the regression this guards.
func TestGoldenCorpus(t *testing.T) {
	got := scanCorpus(t, "testdata")

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("encode findings: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateGolden {
		if err := os.WriteFile(goldenPath, encoded, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d findings)", goldenPath, len(got))
		return
	}

	wantRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run: go test ./... -update-golden): %v", err)
	}

	var want []goldenEntry
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	if diff := diffEntries(want, got); diff != "" {
		t.Errorf("scanner output drifted from %s\n%s\n"+
			"If every line below is a '+' from a rule you just added, regenerate with:\n"+
			"  go test ./... -update-golden", goldenPath, diff)
	}
}

// diffEntries renders a line-oriented diff of two sorted finding sets.
func diffEntries(want, got []goldenEntry) string {
	key := func(e goldenEntry) string {
		return fmt.Sprintf("%s:%d:%s:%s", e.File, e.Line, e.Name, e.Risk)
	}

	inWant := map[string]bool{}
	for _, e := range want {
		inWant[key(e)] = true
	}
	inGot := map[string]bool{}
	for _, e := range got {
		inGot[key(e)] = true
	}

	var b strings.Builder
	for _, e := range want {
		if !inGot[key(e)] {
			fmt.Fprintf(&b, "  - %s\n", key(e))
		}
	}
	for _, e := range got {
		if !inWant[key(e)] {
			fmt.Fprintf(&b, "  + %s\n", key(e))
		}
	}
	return b.String()
}
