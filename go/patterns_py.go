package main

import "regexp"

func (s *Scanner) addPythonPatterns() {
	pyPatterns := []Pattern{
		{
			// Deliberately does NOT match __import__ or
			// importlib.import_module. Those are plain dynamic imports, which
			// dynamic-import already covers as a capability. Matching them here
			// made this rule fire on every Python file that loads a plugin, and
			// because this rule is a threat, that paired dynamic-import back
			// into visibility and made its demotion a no-op on .py files.
			//
			// Everything this rule is actually named for stays: pickle and
			// marshal loading, codecs decoding, compile(), and exec of decoded
			// data.
			Name:        "py-deserialize",
			Risk:        MediumRisk,
			Description: "Deserialization or dynamic code compilation",
			Regex:       regexp.MustCompile(`(compile\(|pickle\.loads|marshal\.loads|codecs\.decode|exec\(.*decode)`),
			FileTypes:   []string{".py"},
		},
		{
			Name:        "py-template-injection",
			Risk:        MediumRisk,
			Description: "[GuardDog] Potential template injection",
			Regex:       regexp.MustCompile(`(jinja2\.Template|render_template_string|autoescape\s*=\s*False)`),
			FileTypes:   []string{".py"},
		},
	}
	s.Patterns = append(s.Patterns, pyPatterns...)
}
