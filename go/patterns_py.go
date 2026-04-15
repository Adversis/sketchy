package main

import "regexp"

func (s *Scanner) addPythonPatterns() {
	pyPatterns := []Pattern{
		{
			Name:        "py-deserialize",
			Risk:        MediumRisk,
			Description: "Dynamic imports or deserialization",
			Regex:       regexp.MustCompile(`(compile\(|__import__|importlib\.import_module|pickle\.loads|marshal\.loads|codecs\.decode|exec\(.*decode)`),
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
