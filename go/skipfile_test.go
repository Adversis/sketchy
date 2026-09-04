package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Scanning a relative path must skip the same directories as scanning an
// absolute one. The old check searched for "/." in the path, so a hidden
// directory at the scan root — ".git" rather than "/repo/.git" — had no
// leading slash and was never skipped. That made "sketchy ." scan .git while
// "sketchy /abs/path" did not.
func TestHiddenDirsSkippedForRelativeAndAbsolutePaths(t *testing.T) {
	root := t.TempDir()

	// A file inside a hidden directory that must always be skipped.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("eval(atob(x))"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A normal file that must always be scanned.
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("eval(atob(x))"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewScanner(root, FilterAll, false, map[string]struct{}{})

	if !s.shouldSkipFile(filepath.Join(root, ".git", "config")) {
		t.Error("absolute path inside .git was not skipped")
	}
	if !s.shouldSkipFile(filepath.Join(".git", "config")) {
		t.Error("relative path inside .git was not skipped — this is the bug")
	}
	if s.shouldSkipFile(filepath.Join(root, "app.js")) {
		t.Error("ordinary file was skipped")
	}
	if s.shouldSkipFile("app.js") {
		t.Error("ordinary relative file was skipped")
	}
}

// The hidden-directory skip has a deliberate exception: AI-agent config and
// instruction directories are a primary scan target. Fixing the relative-path
// bug must not start skipping those.
func TestAgentDirsScannedForRelativeAndAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	s := NewScanner(root, FilterAll, false, map[string]struct{}{})

	cases := []string{
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(".claude", "settings.json"),
		filepath.Join(root, ".cursor", "rules", "x.mdc"),
		filepath.Join(".cursor", "rules", "x.mdc"),
	}
	for _, p := range cases {
		if s.shouldSkipFile(p) {
			t.Errorf("agent config path was skipped: %s", p)
		}
	}
}

// "." and ".." are not hidden directories and must not cause a skip.
func TestDotAndDotDotAreNotTreatedAsHidden(t *testing.T) {
	root := t.TempDir()
	s := NewScanner(root, FilterAll, false, map[string]struct{}{})

	for _, p := range []string{"app.js", "./app.js", "../sibling/app.js"} {
		if s.shouldSkipFile(p) {
			t.Errorf("path was skipped but should not be: %s", p)
		}
	}
}

// py-deserialize is named for deserialization but its regex also matched
// plain dynamic imports, which dynamic-import already covers. Because
// py-deserialize is a threat, it paired dynamic-import back into visibility
// on every Python file, making that demotion a no-op for .py.
//
// Narrowing it must not make it quiet about what it is actually for.
func TestPyDeserializeStillCatchesDeserialization(t *testing.T) {
	mustFire := []struct{ name, content string }{
		{"pickle", `obj = pickle.loads(blob)`},
		{"marshal", `code = marshal.loads(data)`},
		{"codecs", `s = codecs.decode(payload, "rot13")`},
		{"compile", `compile(src, "<string>", "exec")`},
		{"exec-decode", `exec(blob.decode())`},
	}
	for _, c := range mustFire {
		t.Run(c.name, func(t *testing.T) {
			if !firedPatterns(scanContent(t, "x.py", c.content))["py-deserialize"] {
				t.Errorf("py-deserialize went quiet on %s: %s", c.name, c.content)
			}
		})
	}
}

// The overlap itself: a plugin loader is not deserialization.
func TestPyDeserializeIgnoresPlainDynamicImport(t *testing.T) {
	content := "mod = importlib.import_module(\"myapp.plugins.\" + name)\nmod.register()"
	fired := firedPatterns(scanContent(t, "plugins.py", content))
	if fired["py-deserialize"] {
		t.Error("py-deserialize fired on a plain dynamic import")
	}
	// With no threat left in the file, the dynamic-import capability should
	// now be suppressed — which is what demoting it was supposed to achieve.
	if fired["dynamic-import"] {
		t.Error("dynamic-import still reported; its demotion is still a no-op on .py")
	}
}
