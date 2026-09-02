package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scanContent writes content to a temp file named filename and returns every
// finding the scanner produces for it. Using JSONOutput routes findings into
// s.Findings instead of stdout, so tests can assert on them directly.
func scanContent(t *testing.T, filename, content string) []Finding {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", filename, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}

	s := NewScanner(dir, FilterAll, false, map[string]struct{}{})
	s.JSONOutput = true
	s.checkFile(path)
	return s.Findings
}

// firedPatterns returns the set of pattern names that matched.
func firedPatterns(findings []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		out[f.Name] = true
	}
	return out
}

// fixture is one sample of code plus the filename it should be scanned under.
// Filename matters: many patterns are scoped by FileTypes or PathContains.
type fixture struct {
	pattern string // pattern Name this fixture exercises
	file    string // filename (and optionally path) to scan the content as
	content string
}

// positives are samples that MUST trigger their named pattern. Every pattern
// registered in initPatterns needs at least one, enforced by
// TestEveryPatternHasPositiveFixture.
var positives = []fixture{}

// negatives are samples that must NOT trigger their named pattern. These are
// the false-positive guards; they are what stops a rule port from quietly
// turning into a firehose.
var negatives = []fixture{}

func TestEveryPatternHasPositiveFixture(t *testing.T) {
	s := NewScanner(t.TempDir(), FilterAll, false, map[string]struct{}{})

	covered := map[string]bool{}
	for _, f := range positives {
		covered[f.pattern] = true
	}

	var missing []string
	for _, p := range s.Patterns {
		if !covered[p.Name] {
			missing = append(missing, p.Name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("%d of %d patterns have no positive fixture:\n  %s",
			len(missing), len(s.Patterns), strings.Join(missing, "\n  "))
	}
}

func TestPositiveFixturesFire(t *testing.T) {
	for _, f := range positives {
		t.Run(f.pattern+"/"+f.file, func(t *testing.T) {
			fired := firedPatterns(scanContent(t, f.file, f.content))
			if !fired[f.pattern] {
				t.Errorf("pattern %q did not fire on its positive fixture (%s)\ncontent:\n%s",
					f.pattern, f.file, f.content)
			}
		})
	}
}

func TestNegativeFixturesDoNotFire(t *testing.T) {
	for _, f := range negatives {
		t.Run(f.pattern+"/"+f.file, func(t *testing.T) {
			fired := firedPatterns(scanContent(t, f.file, f.content))
			if fired[f.pattern] {
				t.Errorf("pattern %q fired on a negative fixture it should ignore (%s)\ncontent:\n%s",
					f.pattern, f.file, f.content)
			}
		})
	}
}

// TestPatternNamesAreUnique guards against a copy-paste port silently
// shadowing an existing rule's name in JSON output and baselines.
func TestPatternNamesAreUnique(t *testing.T) {
	s := NewScanner(t.TempDir(), FilterAll, false, map[string]struct{}{})

	seen := map[string]int{}
	for _, p := range s.Patterns {
		seen[p.Name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("pattern name %q registered %d times", name, n)
		}
	}
}
