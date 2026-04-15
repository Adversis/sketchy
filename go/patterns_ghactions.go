package main

import (
	"regexp"
	"strings"
)

func (s *Scanner) addGitHubActionsPatterns() {
	ghPatterns := []Pattern{
		{
			Name:        "gh-secret-exfil",
			Risk:        HighRisk,
			Description: "GitHub Actions secret exfiltration",
			Regex:       regexp.MustCompile(`\$\{\{\s*secrets\.[A-Z_]+\s*\}\}.*(\||curl|wget|base64)`),
			FileTypes:   []string{".yml", ".yaml"},
			Validator: func(content string) bool {
				return strings.Contains(content, "name:") && strings.Contains(content, "jobs:")
			},
		},
		{
			Name:        "gh-token-exposure",
			Risk:        HighRisk,
			Description: "GitHub token exposure in workflow",
			Regex:       regexp.MustCompile(`\$\{\{\s*(github\.token|secrets\.GITHUB_TOKEN)\s*\}\}.*(echo|cat|curl|wget|POST)`),
			FileTypes:   []string{".yml", ".yaml"},
			Validator: func(content string) bool {
				return strings.Contains(content, "name:") && strings.Contains(content, "jobs:")
			},
		},
	}
	s.Patterns = append(s.Patterns, ghPatterns...)
}
