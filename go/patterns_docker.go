package main

import "regexp"

func (s *Scanner) addDockerfilePatterns() {
	dockerPatterns := []Pattern{
		{
			Name:        "dockerfile-curl-exec",
			Risk:        MediumRisk,
			Description: "Dockerfile downloading and executing remote code",
			Regex:       regexp.MustCompile(`RUN\s+.*(curl|wget).*\|.*(sh|bash)|RUN\s+.*(curl|wget).*-O.*&&.*chmod.*\+x`),
			FileTypes:   []string{"Dockerfile", "Containerfile"},
		},
		{
			Name:        "dockerfile-secrets",
			Risk:        HighRisk,
			Description: "Dockerfile exposing secrets in ENV",
			Regex:       regexp.MustCompile(`ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY|PRIVATE|API_KEY|ACCESS_KEY)`),
			FileTypes:   []string{"Dockerfile", "Containerfile"},
		},
		{
			Name:        "dockerfile-entrypoint",
			Risk:        MediumRisk,
			Description: "Dockerfile suspicious ENTRYPOINT/CMD",
			Regex:       regexp.MustCompile(`(ENTRYPOINT|CMD).*("|').*(nc\s|netcat|/bin/sh|bash\s+-i|curl.*\|)`),
			FileTypes:   []string{"Dockerfile", "Containerfile"},
		},
	}
	s.Patterns = append(s.Patterns, dockerPatterns...)
}
