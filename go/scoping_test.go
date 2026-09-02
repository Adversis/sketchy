package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scanWith runs an explicit pattern set against one file, bypassing
// initPatterns. Lets scoping behaviour be tested without depending on the
// real ruleset.
func scanWith(t *testing.T, filename, content string, patterns []Pattern) []Finding {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", filename, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}

	s := &Scanner{
		ScanPath:    dir,
		FilterLevel: FilterAll,
		MaxFileSize: 1024 * 1024,
		IgnoreDirs:  map[string]struct{}{},
		JSONOutput:  true,
		Patterns:    patterns,
	}
	s.checkFile(path)
	return s.Findings
}

func TestPathExcludeSuppressesMatchInExcludedPath(t *testing.T) {
	p := Pattern{
		Name:        "probe",
		Risk:        HighRisk,
		Description: "test probe",
		Regex:       regexp.MustCompile(`NEEDLE`),
		FileTypes:   []string{".js"},
		PathExclude: []string{"node_modules/"},
	}

	inside := scanWith(t, "node_modules/pkg/index.js", "NEEDLE", []Pattern{p})
	if len(inside) != 0 {
		t.Errorf("pattern fired inside an excluded path: got %d findings, want 0", len(inside))
	}

	outside := scanWith(t, "src/index.js", "NEEDLE", []Pattern{p})
	if len(outside) != 1 {
		t.Errorf("pattern did not fire outside the excluded path: got %d findings, want 1", len(outside))
	}
}

// PathExclude must work on its own, without FileTypes or PathContains, so an
// unscoped rule can still be kept out of vendored trees.
func TestPathExcludeWorksWithoutOtherScoping(t *testing.T) {
	p := Pattern{
		Name:        "probe",
		Risk:        HighRisk,
		Description: "test probe",
		Regex:       regexp.MustCompile(`NEEDLE`),
		PathExclude: []string{"vendor/"},
	}

	if got := scanWith(t, "vendor/lib/x.py", "NEEDLE", []Pattern{p}); len(got) != 0 {
		t.Errorf("unscoped pattern fired in excluded path: got %d findings, want 0", len(got))
	}
	if got := scanWith(t, "app/x.py", "NEEDLE", []Pattern{p}); len(got) != 1 {
		t.Errorf("unscoped pattern did not fire outside excluded path: got %d findings, want 1", len(got))
	}
}

// A zero MaxHits means "unset", and must fall back to the historical cap of
// three rather than silently reporting nothing. This is the zero-value trap.
func TestMaxHitsZeroMeansDefaultNotSilence(t *testing.T) {
	p := Pattern{
		Name:        "probe",
		Risk:        HighRisk,
		Description: "test probe",
		Regex:       regexp.MustCompile(`NEEDLE`),
		// MaxHits deliberately unset.
	}

	content := strings.Repeat("NEEDLE\n", 10)
	got := scanWith(t, "x.py", content, []Pattern{p})
	if len(got) != defaultMaxHits {
		t.Errorf("unset MaxHits reported %d findings, want the default of %d", len(got), defaultMaxHits)
	}
}

func TestMaxHitsCapsFindingsPerFile(t *testing.T) {
	p := Pattern{
		Name:        "probe",
		Risk:        HighRisk,
		Description: "test probe",
		Regex:       regexp.MustCompile(`NEEDLE`),
		MaxHits:     1,
	}

	content := strings.Repeat("NEEDLE\n", 10)
	got := scanWith(t, "x.py", content, []Pattern{p})
	if len(got) != 1 {
		t.Errorf("MaxHits=1 reported %d findings, want 1", len(got))
	}
}

// MaxHits must be able to raise the cap above the old hardcoded 3, not just
// lower it, otherwise it is not a generalisation of that constant.
func TestMaxHitsCanExceedLegacyLimit(t *testing.T) {
	p := Pattern{
		Name:        "probe",
		Risk:        HighRisk,
		Description: "test probe",
		Regex:       regexp.MustCompile(`NEEDLE`),
		MaxHits:     5,
	}

	content := strings.Repeat("NEEDLE\n", 10)
	got := scanWith(t, "x.py", content, []Pattern{p})
	if len(got) != 5 {
		t.Errorf("MaxHits=5 reported %d findings, want 5", len(got))
	}
}
