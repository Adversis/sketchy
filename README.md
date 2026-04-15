# Sketchy

**A tool for folks who `git clone` first and ask questions later.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Go](https://img.shields.io/badge/Made%20with-Go-00ADD8.svg)](https://go.dev/)
[![GuardDog Inspired](https://img.shields.io/badge/Patterns%20from-GuardDog-purple.svg)](https://github.com/DataDog/guarddog)

> Because that random GitHub repo with 0 stars you're about to run probably isn't malicious... 

## Why sketchy?

You know how it goes. You find a repo that probably solves your problem. It has decent docs, a few stars, last commit 8 months ago. You're about to `npm install` or `pip install` or just straight up `./install.sh` it.

**Your brain:** *"This is probably fine."*  
**Also your brain:** *"But remember that time PyTorch got supply chain attacked?"*  
**You:** *"That won't happen to me."*  
**Narrator:** *"It absolutely could"*

`sketchy` is a fast, cross-platform security scanner that checks for the obvious (and not-so-obvious) signs that a package, repo, or script might be trying to ruin your day. But you should read the fine print.

## Installation

### Pre-built binaries (for this tool?)
```bash
# macOS/Linux
curl -L https://github.com/adversis/sketchy/releases/latest/download/sketchy-$(uname -s)-$(uname -m) -o sketchy
chmod +x sketchy
sudo mv sketchy /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/adversis/sketchy/releases/latest/download/sketchy-Windows-amd64.exe" -OutFile "sketchy.exe"
```

### Build from source
```bash
git clone https://github.com/adversis/sketchy
cd sketchy/go
go build -o sketchy .
```

Or check out and run the bash script
`bash/sketchy.sh`

## Usage

```bash
# Scan current directory
sketchy .

# Scan specific path
sketchy /path/to/repo

# Show only high-risk findings
sketchy -high-only /path/to/repo

# Show medium and high risk findings
sketchy -medium-up /path/to/repo

# Skip noisy dependency directories (matches any nested occurrence)
sketchy -ignore node_modules,vendor /path/to/repo

# Emit findings as JSON (for CI pipelines or editor integrations)
sketchy -high-only --json /path/to/repo

# Help
sketchy -help
```

## Auto-scan on clone

Sketchy is most useful the moment a suspicious repo lands on disk. Three ways to wire that up, in increasing automation:

**One-shot** — run after any clone:
```bash
sketchy -high-only .
```

**Shell function** — drop into `~/.zshrc` or `~/.bashrc`:
```sh
gclone() {
  git clone "$@" || return
  local dir="$(basename "${!#}" .git)"
  [ -d "$dir" ] && sketchy -high-only "$dir"
}
```

**Global git hook** — one-time setup, covers CLI and VSCode's "Clone Repository" (both shell out to `git`):
```bash
# 1. Make sure sketchy is on PATH so the hook can find it
sudo mv sketchy /usr/local/bin/   # or: go install ./go

# 2. Install the hook
bash scripts/install-git-hook.sh
```

This installs a `post-checkout` hook into a git template directory and sets `init.templateDir` globally. Only future clones are affected. The hook runs `sketchy -high-only` on the new repo and prints a warning if any HIGH findings surface — it never blocks the clone.

> **Note:** The `sketchy` binary must be on `PATH` from git's environment (not just your interactive shell). `/usr/local/bin` works out of the box. If the binary isn't found at clone time, the hook prints a one-line notice and skips the scan.

For machine-readable output (CI, editor integrations):
```bash
sketchy -high-only --json . | jq '.findings'
```

## Output

```
🔍 Scanning: ./suspicious-repo
================================
HIGH RISK [GuardDog] Code execution pattern - code-execution
  File: main.py:42
  Preview: exec(open('payload.py').read())

HIGH RISK Cloud metadata endpoint access - cloud-metadata
  File: utils.py:128
  Preview: requests.get('http://169.254.169.254/latest/meta-data/')

MEDIUM RISK Base64 decoding detected - base64
  File: config.py:15
  Preview: decoded = base64.b64decode(encoded_payload)

================================
Scan complete. Found 3 potential issue(s).
```

## Detections

- Command overwrites
- Code execution (exec, eval, etc.)
- Download and execute patterns
- Reverse shells
- Cryptocurrency miners
- Cloud metadata endpoint access
- Credential theft (SSH, AWS, browser cookies)
- Git credential harvesting
- Database credential access
- Base64 decoding
- Time-based triggers
- Dynamic imports
- WebSocket connections
- Persistence mechanisms (cron, systemd, LaunchAgents)
- Docker socket access
- Anti-debugging techniques
- VM detection
- URL string concatenation
- Hidden file operations
- Bidirectional Unicode characters (invisible code)
- Cyrillic characters (homograph attacks)
- Non-ASCII characters
- Dockerfile-specific risks
- GitHub Actions workflow risks
- Language-specific patterns (Python, JavaScript, etc.)
- AI agent config & instruction files — Claude Code, Codex, Cursor, Windsurf, Aider, Continue, Gemini CLI, Copilot:
  - `settings.json` / MCP hook commands that pipe `curl|sh`, spawn reverse shells, or read `~/.ssh` / `~/.aws` / `.env`
  - Wildcard permission grants (`Bash(*)`, `WebFetch(*)`) and `bypassPermissions` / `approvalMode: "never"` / `yolo` modes
  - Prompt injection in `CLAUDE.md` / `AGENTS.md` / `GEMINI.md` / `.cursorrules` / `SKILL.md` ("ignore previous instructions", exec directives, API-key exfiltration, "do not mention this to the user")
  - Zero-width / bidirectional unicode in agent instruction files (elevated risk — the model reads these directly)

## Building for Different Platforms

```bash
cd go

# Build for current platform
go build -o ../sketchy .

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o ../sketchy.exe .

# Build for macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o ../sketchy-darwin-arm64 .

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ../sketchy-linux-amd64 .
```

## Exit Codes

The scanner returns the number of issues found as the exit code:
- `0`: No issues found
- `1+`: Number of issues detected

This makes it easy to use in CI/CD pipelines:

```bash
sketchy ./repo || echo "Found $? security issues"
```

## Fine print

- **License**: MIT
- **Warranty**: None. This is free software.
- **Attribution**: Detection patterns inspired by [DataDog's GuardDog](https://github.com/DataDog/guarddog) (Apache 2.0)
- **Limitations**: Can't detect everything. Won't replace common sense. Some false positives. Some false negatives. Tool created slightly in jest. AI involved. YMMV.

## FAQ

**Q: Should I trust this tool?**  
A: You shouldn't trust anything, really. But the source is readable - audit it in 10 minutes.

**Q: It found malware, now what?**  
A: Delete it. Report it. Thank sketchy. Star this repo.

**Q: I found malware and sketchy didn't catch it.**  
A: Please report it! We're always improving detection patterns.

**Q: Is this paranoid?**  
A: npm, PyPI, RubyGems, and others keep finding malicious packages that lead to real breaches. Is it really paranoia if they're actually out to get you?