package main

import "regexp"

func (s *Scanner) addJavaScriptPatterns() {
	jsPatterns := []Pattern{
		{
			Name:        "js-obfuscation",
			Risk:        MediumRisk,
			Description: "Potentially obfuscated JavaScript",
			Regex:       regexp.MustCompile(`(\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode|unescape\(|document\.write\(|eval\(.*unescape)`),
			FileTypes:   []string{".js", ".ts", ".jsx", ".tsx"},
		},
	}
	s.Patterns = append(s.Patterns, jsPatterns...)
}
