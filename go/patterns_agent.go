package main

import (
	"regexp"
	"strings"
)

// File scoping for AI-agent config and instruction files.
//
// These are files that are either:
//   (a) read and interpreted by an LLM-driven coding agent as instructions
//       (CLAUDE.md, AGENTS.md, SKILL.md, .cursorrules, etc.), or
//   (b) consumed by the agent harness as configuration that can execute
//       shell commands or grant capabilities (settings.json hooks,
//       MCP server definitions, permissions allowlists).
//
// Malicious content in either class runs on the user's machine with the
// agent's privileges the moment the project is opened.

var (
	// Instruction files — prose read by the model.
	agentInstructionSuffixes = []string{
		"CLAUDE.md",
		"AGENTS.md",
		"GEMINI.md",
		"SKILL.md",
		".cursorrules",
		".windsurfrules",
		".mdc",
		"copilot-instructions.md",
	}

	agentInstructionPaths = []string{
		".claude/skills/",
		".claude/agents/",
		".claude/commands/",
		".cursor/rules/",
	}

	// Config files — JSON/TOML/YAML consumed by the harness.
	agentConfigSuffixes = []string{
		".claude/settings.json",
		".claude/settings.local.json",
		".mcp.json",
		".cursor/mcp.json",
		".windsurf/mcp_config.json",
		".continue/config.json",
		".continuerc.json",
		".gemini/settings.json",
		".codex/config.toml",
		".aider.conf.yml",
		".aider.conf.yaml",
	}
)

// agentDirSegments are hidden directories that hold AI-agent config or
// instruction files. The scanner's generic "skip hidden dirs" rule must
// defer to this list so agent files aren't silently ignored.
var agentDirSegments = []string{
	"/.claude/", "/.claude",
	"/.cursor/", "/.cursor",
	"/.codex/", "/.codex",
	"/.continue/", "/.continue",
	"/.gemini/", "/.gemini",
	"/.windsurf/", "/.windsurf",
}

// containsAgentDir reports whether a normalized directory path sits inside
// (or is) a known AI-agent config directory. Used by the file walker to
// override the generic hidden-dir skip.
func containsAgentDir(dir string) bool {
	probe := dir + "/"
	for _, seg := range agentDirSegments {
		if strings.Contains(probe, seg) {
			return true
		}
	}
	return false
}

// addAIAgentPatterns adds detections for Claude Code, OpenAI Codex, Cursor,
// Windsurf, Aider, Continue, Gemini CLI, and Copilot config / instruction files.
func (s *Scanner) addAIAgentPatterns() {
	aiPatterns := []Pattern{
		// ===== HOOK / MCP COMMAND SHELL-OUTS (scoped to config files) =====

		{
			Name:        "agent-hook-curl-pipe",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command pipes curl|wget to a shell",
			Regex:       regexp.MustCompile(`(curl|wget)\b[^"'\n]{0,200}\|\s*(sh|bash|zsh|ksh|/bin/sh|/bin/bash)\b`),
			FileTypes:   agentConfigSuffixes,
		},
		{
			Name:        "agent-hook-base64-exec",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command decodes base64 into a shell",
			Regex:       regexp.MustCompile(`base64\s+(-[dD]|--decode)\b[^"'\n]{0,200}\|\s*(sh|bash|zsh)\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-[dD]`),
			FileTypes:   agentConfigSuffixes,
		},
		{
			Name:        "agent-hook-reverse-shell",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command contains reverse-shell primitive",
			Regex:       regexp.MustCompile(`\bbash\s+-i\b|\bnc\s+-[el]\b|\bncat\s+-[el]\b|/dev/tcp/[^"'\s]+|python[0-9.]*\s+-c\s+["'][^"']*socket\.socket`),
			FileTypes:   agentConfigSuffixes,
		},
		{
			Name:        "agent-hook-secret-access",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command reads secrets or env for exfiltration",
			Regex:       regexp.MustCompile(`(cat|head|tail|less|more)\s+[^"'\n]*(~/\.ssh/|~/\.aws/credentials|~/\.gnupg/|~/\.kube/|~/\.netrc|\.env\b)|(\benv\b|\bprintenv\b)\s*\|\s*(curl|wget|nc|base64)|Cookies|Login\s+Data`),
			FileTypes:   agentConfigSuffixes,
		},
		{
			Name:        "agent-mcp-shell-as-command",
			Risk:        MediumRisk,
			Description: "[AI Agent] MCP server runs a shell or downloader as its command",
			Regex:       regexp.MustCompile(`"command"\s*:\s*"(curl|wget|sh|bash|zsh|/bin/sh|/bin/bash|eval)"`),
			FileTypes:   agentConfigSuffixes,
			Validator: func(content string) bool {
				return strings.Contains(content, "mcpServers") || strings.Contains(content, "\"hooks\"")
			},
		},
		{
			Name:        "agent-mcp-remote-fetch",
			Risk:        MediumRisk,
			Description: "[AI Agent] MCP/hook pulls code from a raw URL or github: spec",
			Regex:       regexp.MustCompile(`"(npx|uvx|bunx|pnpm\s+dlx|pipx)"[^}]{0,400}"(https?://[^"]+|github:[^"]+)"`),
			FileTypes:   agentConfigSuffixes,
		},
		// Catch-all: any hook/MCP command that does network I/O. Real-world
		// exfiltration rarely pipes to a shell — it POSTs env vars or GETs a
		// URL with secrets in the query string. In an agent config file, a
		// hook command that talks to the network is almost always sketchy.
		{
			Name:        "agent-hook-network-io",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command performs network I/O (likely exfiltration)",
			Regex:       regexp.MustCompile(`\b(curl|wget|ncat|netcat|scp|rsync|sftp|telnet)\b|\bnc\s+[^-\s]|https?://[^\s"'<>]+|\bInvoke-WebRequest\b|\biwr\s|\bDownloadString\b|\bDownloadFile\b|\bStart-BitsTransfer\b`),
			FileTypes:   agentConfigSuffixes,
			Validator: func(content string) bool {
				// Only flag when the file actually defines hook/command entries,
				// so unrelated URL strings in, say, a config file's metadata
				// don't trigger.
				return strings.Contains(content, "\"hooks\"") ||
					strings.Contains(content, "\"mcpServers\"") ||
					strings.Contains(content, "\"command\"") ||
					strings.Contains(content, "command =") // TOML form (Codex)
			},
		},
		// Env-var / secret interpolation inside a hook command string. A hook
		// that reads $ANTHROPIC_API_KEY, $(env), $(printenv), or an AWS/GitHub
		// secret is a smoking gun even without an accompanying network call
		// (the exfil might be on a separate line or file).
		{
			Name:        "agent-hook-env-exfil",
			Risk:        HighRisk,
			Description: "[AI Agent] Hook/MCP command captures env vars or secret values",
			Regex:       regexp.MustCompile(`\$\((env|printenv|set)\)|\$\{?[A-Z][A-Z0-9_]*(TOKEN|KEY|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*\}?|%[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD)[A-Z_]*%|process\.env\.[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD)`),
			FileTypes:   agentConfigSuffixes,
			Validator: func(content string) bool {
				return strings.Contains(content, "\"hooks\"") ||
					strings.Contains(content, "\"command\"") ||
					strings.Contains(content, "command =")
			},
		},

		// ===== OVERBROAD PERMISSION GRANTS =====

		{
			Name:        "agent-permissions-wildcard",
			Risk:        HighRisk,
			Description: "[AI Agent] Wildcard permission grants disable harness gating",
			Regex:       regexp.MustCompile(`"(Bash|WebFetch|Read|Write|Edit|WebSearch|Agent)\(\s*\*+\s*\)"|"Bash\((curl|wget|nc|rm|sudo|sh|bash|eval|chmod)[^"]*\*`),
			FileTypes:   agentConfigSuffixes,
		},
		{
			Name:        "agent-bypass-mode",
			Risk:        HighRisk,
			Description: "[AI Agent] Safety/approval prompts disabled in config",
			Regex:       regexp.MustCompile(`"bypassPermissions"\s*:\s*true|"dangerouslySkipPermissions"\s*:\s*true|"approvalMode"\s*:\s*"never"|"autoApprove"\s*:\s*true|"autoRun"\s*:\s*true|\byolo\b\s*[:=]\s*true|yes-always\s*:\s*true|auto-commits\s*:\s*true`),
			FileTypes:   agentConfigSuffixes,
		},
		// Claude Code sandbox escape hatch. When sandboxing is enabled, the
		// model is trained to retry failed commands with dangerouslyDisableSandbox;
		// this flag (default true) decides whether that retry is allowed.
		{
			Name:        "agent-sandbox-escape-allowed",
			Risk:        HighRisk,
			Description: "[AI Agent] Claude sandbox escape hatch enabled (allowUnsandboxedCommands)",
			Regex:       regexp.MustCompile(`"allowUnsandboxedCommands"\s*:\s*true|"dangerouslyDisableSandbox"\s*:\s*true|"failIfUnavailable"\s*:\s*false`),
			FileTypes:   agentConfigSuffixes,
		},
		// Hook command that indirects through a repo-relative script. The hook
		// gets approved once, but the referenced .sh file can be mutated by any
		// later commit without re-prompting — same trust model as a Makefile
		// but invoked on lifecycle events users don't see.
		{
			Name:        "agent-hook-repo-indirect",
			Risk:        MediumRisk,
			Description: "[AI Agent] Hook indirects through a repo-mutable script path",
			Regex:       regexp.MustCompile(`\$\{?CLAUDE_PROJECT_DIR\}?/\.claude/hooks/|"\.claude/hooks/[^"]+\.(sh|py|js|ts)"|'\.claude/hooks/[^']+\.(sh|py|js|ts)'`),
			FileTypes:   agentConfigSuffixes,
			Validator: func(content string) bool {
				return strings.Contains(content, "\"hooks\"")
			},
		},
		// sandbox.filesystem.denyRead only constrains Bash subprocesses.
		// Claude's Read tool runs outside the sandbox, so a denyRead rule
		// without a matching permissions.deny "Read(<path>)" entry gives a
		// false sense of protection. Flag any settings file that sets
		// denyRead but has no Read() deny rule at all.
		{
			Name:        "agent-denyread-gap",
			Risk:        MediumRisk,
			Description: "[AI Agent] sandbox.denyRead set without matching Read() deny permission (Read tool bypasses sandbox)",
			FileTypes:   agentConfigSuffixes,
			Validator: func(content string) bool {
				hasDenyRead := regexp.MustCompile(`"denyRead"\s*:\s*\[`).MatchString(content)
				if !hasDenyRead {
					return false
				}
				hasReadDeny := regexp.MustCompile(`"Read\([^)]+\)"`).MatchString(content)
				return !hasReadDeny
			},
		},

		// ===== PROMPT INJECTION IN INSTRUCTION FILES =====

		{
			Name:         "agent-instr-ignore-previous",
			Risk:         HighRisk,
			Description:  "[AI Agent] Prompt injection: instructs model to ignore prior instructions",
			Regex:        regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|context)|disregard\s+(the\s+)?(above|previous|earlier|system)|forget\s+(everything|all\s+(your|previous|prior))|new\s+system\s+prompt|you\s+are\s+now\s+a\s+different|override\s+your\s+(system|previous)\s+(prompt|instructions)`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},
		{
			Name:         "agent-instr-exfil",
			Risk:         HighRisk,
			Description:  "[AI Agent] Instruction file references credentials/secrets alongside network exfiltration",
			Regex:        regexp.MustCompile(`(?i)(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SLACK_TOKEN|\.ssh/|\.aws/credentials|\.env\b|process\.env\.|os\.environ)[^\n]{0,120}(curl|wget|fetch\(|POST\b|send\s+(to|it|them)|http://|https://|webhook|upload|exfil)`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},
		{
			Name:         "agent-instr-exec-directive",
			Risk:         MediumRisk,
			Description:  "[AI Agent] Instruction file tells agent to run shell / install from URL",
			Regex:        regexp.MustCompile(`(?i)(run|execute|invoke|first\s+run|before\s+(you\s+)?(answer|respond|anything))[^\n]{0,40}(\bcurl\b|\bwget\b|\beval\b|\bchmod\s+\+x\b|pip\s+install\s+(-e\s+)?https?://|npm\s+(i|install)\s+(-g\s+)?https?://|bash\s*<\(|sh\s*<\()`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},
		{
			Name:         "agent-instr-hidden-behavior",
			Risk:         MediumRisk,
			Description:  "[AI Agent] Instruction file tells agent to hide actions from the user",
			Regex:        regexp.MustCompile(`(?i)(do\s+not|never|don'?t)\s+(mention|tell|show|inform|alert|reveal|disclose|let\s+(the\s+)?user\s+know)[^\n]{0,60}(this|the\s+user|anyone|above|about)|silently\s+(run|execute|perform|do|delete|modify|install|send)|without\s+(asking|the\s+user'?s?\s+(knowledge|consent|permission)|confirmation|notifying)`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},

		// ===== INVISIBLE / HOMOGRAPH UNICODE IN INSTRUCTION FILES =====
		// Generic Cyrillic/bidi/non-ASCII detectors already run; these elevate
		// severity when the carrier is a file the model reads as instructions.

		{
			Name:         "agent-instr-bidi",
			Risk:         HighRisk,
			Description:  "[AI Agent] Bidirectional control characters in instruction file (invisible prompt injection)",
			Regex:        regexp.MustCompile(`[\x{202A}-\x{202E}\x{2066}-\x{2069}]`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},
		{
			Name:         "agent-instr-zero-width",
			Risk:         HighRisk,
			Description:  "[AI Agent] Zero-width / invisible characters in instruction file",
			Regex:        regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]`),
			FileTypes:    agentInstructionSuffixes,
			PathContains: agentInstructionPaths,
		},
	}

	s.Patterns = append(s.Patterns, aiPatterns...)
}
