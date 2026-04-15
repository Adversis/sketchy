package main

import (
	"regexp"
	"strings"
)

// initPatterns initializes all detection patterns
func (s *Scanner) initPatterns() {
	s.Patterns = []Pattern{
		// ===== GUARDDOG-INSPIRED DETECTIONS =====
		
		// Command overwrite
		{
			Name:        "cmd-overwrite",
			Risk:        HighRisk,
			Description: "[GuardDog] Command overwrite detected",
			Regex:       regexp.MustCompile(`(ls|dir|cat|find|grep|which|curl|wget)\s*=\s*['"]|alias\s+(ls|dir|cat|find|grep|which|curl|wget)=`),
		},
		
		// Code execution patterns
		{
			Name:        "code-execution",
			Risk:        HighRisk,
			Description: "[GuardDog] Code execution pattern",
			Regex:       regexp.MustCompile(`(exec\(open\(|exec\(compile\(|eval\(compile\(|__import__\(['"]os['"]\)|__import__\(['"]subprocess['"]\))`),
		},
		
		// Download and execute
		{
			Name:        "download-exec",
			Risk:        HighRisk,
			Description: "[GuardDog] Download and execute pattern",
			Regex:       regexp.MustCompile(`(urllib\.request\.urlretrieve|wget.*&&.*chmod|curl.*\|.*sh|requests\.get.*open.*wb)`),
		},
		
		// Steganography
		{
			Name:        "steganography",
			Risk:        MediumRisk,
			Description: "[GuardDog] Potential steganography",
			Regex:       regexp.MustCompile(`(PIL\.Image.*extract|steganography|stegano|from.*PIL.*import|cv2\.imread.*decode)`),
		},
		
		// Silent process execution
		{
			Name:        "silent-process",
			Risk:        MediumRisk,
			Description: "[GuardDog] Silent process execution",
			Regex:       regexp.MustCompile(`(subprocess\..*stdout\s*=\s*subprocess\.DEVNULL|subprocess\..*stderr\s*=\s*subprocess\.DEVNULL|os\.devnull|> /dev/null 2>&1)`),
		},
		
		// Sensitive data exfiltration
		{
			Name:        "sensitive-exfil",
			Risk:        HighRisk,
			Description: "[GuardDog] Sensitive data exfiltration",
			Regex:       regexp.MustCompile(`(\.ssh/|\.aws/|\.docker/|\.kube/|\.gnupg/|\.password-store/|id_rsa|id_dsa|credentials|\.env).*(requests\.|urllib\.|curl|wget|POST|upload)`),
		},
		
		// Suspicious npm scripts
		{
			Name:        "npm-scripts",
			Risk:        HighRisk,
			Description: "[GuardDog] Suspicious npm script",
			Regex:       regexp.MustCompile(`(preinstall|postinstall|preuninstall|postuninstall).*(&& rm|&& curl|&& wget|\|\| curl|\|\| wget|node -e|eval)`),
			FileTypes:   []string{"package.json"},
		},
		
		// DLL hijacking
		{
			Name:        "dll-hijack",
			Risk:        MediumRisk,
			Description: "[GuardDog] Potential DLL hijacking",
			Regex:       regexp.MustCompile(`(ctypes\.windll|ctypes\.WinDLL|kernel32\.dll|LoadLibrary|GetProcAddress)`),
		},
		
		// Suspicious shortened URLs
		{
			Name:        "shady-urls",
			Risk:        MediumRisk,
			Description: "[GuardDog] Suspicious shortened/paste URL",
			Regex:       regexp.MustCompile(`(bit\.ly|tinyurl|short\.link|rebrand\.ly|t\.me|discord\.gg|pastebin\.com|hastebin\.com)`),
		},
		
		// ===== OBFUSCATION DETECTION =====
		
		// Character code construction
		{
			Name:        "char-codes",
			Risk:        MediumRisk,
			Description: "String obfuscation via character codes",
			Regex:       regexp.MustCompile(`(chr\s*\([0-9]+\)|String\.fromCharCode|Buffer\([^)]+\)\.toString|\\x[0-9a-f]{2}|\\[0-7]{3})`),
		},
		
		// DNS operations
		{
			Name:        "dns-ops",
			Risk:        HighRisk,
			Description: "DNS operations (possible data exfiltration)",
			Regex:       regexp.MustCompile(`(dns\.resolve|dns\.lookup|getaddrinfo|socket\.gethostby|nslookup|dig\s+)`),
		},
		
		// Environment variable access
		{
			Name:        "env-access-sensitive",
			Risk:        HighRisk,
			Description: "Accessing sensitive environment variables",
			Regex:       regexp.MustCompile(`(AWS|KEY|TOKEN|SECRET|PASSWORD|CRED|API).*(process\.env|os\.environ|getenv)`),
		},
		
		// Package manager in code
		{
			Name:        "package-manager",
			Risk:        HighRisk,
			Description: "Package manager invoked from code",
			Regex:       regexp.MustCompile(`(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)`),
		},
		
		// Time-based triggers
		{
			Name:        "time-trigger",
			Risk:        MediumRisk,
			Description: "Time-based trigger detected",
			Regex:       regexp.MustCompile(`(setTimeout\s*\([^,]+,\s*[0-9]{6,}|time\.sleep\s*\([0-9]{4,}|datetime.*days\s*[><=]|cron|schedule\.)`),
		},
		
		// Dynamic imports
		{
			Name:        "dynamic-import",
			Risk:        MediumRisk,
			Description: "Dynamic module loading",
			Regex:       regexp.MustCompile(`(__import__|importlib\.import_module|require\(['"].*['"]\).replace|require\(.*\+|dynamic import)`),
		},
		
		// Suspicious network operations (excluding localhost/127.0.0.1)
		{
			Name:        "suspicious-network",
			Risk:        HighRisk,
			Description: "Suspicious network operation",
			Regex:       regexp.MustCompile(`(curl|wget|nc|netcat|telnet|ssh|scp|rsync)\s+[^|>]*\.(ru|cn|tk|ml|ga|cf)|https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`),
			Validator: func(content string) bool {
				re := regexp.MustCompile(`(curl|wget|nc|netcat|telnet|ssh|scp|rsync)\s+[^|>]*\.(ru|cn|tk|ml|ga|cf)|https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
				lines := strings.Split(content, "\n")
				foundSuspicious := false
				for _, line := range lines {
					if re.MatchString(line) {
						// Check if this line contains localhost or 127.x.x.x
						if strings.Contains(line, "://127.") || strings.Contains(line, "://localhost") {
							continue
						}
						// Check for direct IP addresses, but skip 127.x.x.x
						if ipMatch := regexp.MustCompile(`https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`).FindStringSubmatch(line); len(ipMatch) > 1 {
							if strings.HasPrefix(ipMatch[1], "127.") {
								continue
							}
						}
						foundSuspicious = true
						break
					}
				}
				return foundSuspicious
			},
		},
		
		// WebSocket connections
		{
			Name:        "websocket",
			Risk:        MediumRisk,
			Description: "WebSocket connection detected",
			Regex:       regexp.MustCompile(`(WebSocket|ws\s*://|wss\s*://|socket\.io|SockJS)`),
		},
		
		// Base64 decoding
		{
			Name:        "base64",
			Risk:        MediumRisk,
			Description: "Base64 decoding detected",
			Regex:       regexp.MustCompile(`(base64\s+-d|base64\s+--decode|atob\(|Buffer\.from\([^,]+,\s*['"]base64|b64decode|base64\.b64decode)`),
		},
		
		// Eval and exec
		{
			Name:        "eval-exec",
			Risk:        MediumRisk,
			Description: "Dynamic code execution",
			Regex:       regexp.MustCompile(`(\beval\s*\(|\bexec\s*\(|subprocess\.call|subprocess\.run|subprocess\.Popen|os\.system|shell_exec|system\(|passthru\()`),
		},
		
		// Reverse shells
		{
			Name:        "reverse-shell",
			Risk:        HighRisk,
			Description: "Potential reverse shell",
			Regex:       regexp.MustCompile(`(bash\s+-i|/bin/sh\s+-i|nc\s+.*\s+-e\s+/bin/|mkfifo\s+/tmp/|telnet\s+.*\s+.*\s+\||socket\.socket\(.*SOCK_STREAM)`),
		},
		
		// Cryptocurrency miners
		{
			Name:        "crypto-miner",
			Risk:        HighRisk,
			Description: "Potential crypto miner",
			Regex:       regexp.MustCompile(`(?i)(xmrig|cgminer|bfgminer|ethminer|minergate|nicehash|stratum\+tcp://|monero|ethereum.*wallet)`),
		},
		
		// Dangerous file operations
		{
			Name:        "dangerous-file-ops",
			Risk:        MediumRisk,
			Description: "Dangerous file operation",
			Regex:       regexp.MustCompile(`(rm\s+-rf\s+/|chmod\s+777|chmod\s+\+s|setuid|setgid)`),
		},
		
		// Hidden file operations
		{
			Name:        "hidden-files",
			Risk:        LowRisk,
			Description: "Hidden file operations",
			Regex:       regexp.MustCompile(`(touch\s+\.|echo.*>\s*\.|cat.*>\s*\.|\$HOME/\.)`),
		},
		
		// URL concatenation
		{
			Name:        "url-concat",
			Risk:        LowRisk,
			Description: "URL string concatenation",
			Regex:       regexp.MustCompile(`(['"]https?['"].*\+|url\s*=.*\+.*['"]://|\.join\([^)]*https?)`),
		},
		
		// ===== ADVANCED DETECTIONS =====
		
		// Git hooks
		{
			Name:        "git-hooks",
			Risk:        MediumRisk,
			Description: "Git hooks manipulation",
			Regex:       regexp.MustCompile(`(\.git/hooks/|git.*hooks.*pre-commit|git.*hooks.*post-checkout|git.*hooks.*pre-push|git.*hooks.*post-merge)`),
		},
		
		// Shell profile persistence
		{
			Name:        "shell-persistence",
			Risk:        HighRisk,
			Description: "Shell profile modification for persistence",
			Regex:       regexp.MustCompile(`(~/\.bashrc|~/\.zshrc|~/\.bash_profile|~/\.profile|~/\.zprofile|\.config/fish/config\.fish|/etc/profile|/etc/bash\.bashrc).*(echo|cat|>>|tee)`),
		},
		
		// Browser credential theft
		{
			Name:        "browser-creds",
			Risk:        HighRisk,
			Description: "Browser credential/cookie theft",
			Regex:       regexp.MustCompile(`(Chrome/Default/Cookies|Chrome/Default/Login Data|firefox.*cookies\.sqlite|Safari.*Cookies|Cookies\.binarycookies|Chrome.*Local Storage|Firefox.*storage)`),
		},
		
		// Cloud CLI credentials
		{
			Name:        "cloud-creds",
			Risk:        HighRisk,
			Description: "Cloud CLI credential access",
			Regex:       regexp.MustCompile(`(~/\.aws/credentials|~/\.aws/config|accessTokens\.json|~/\.azure|~/\.config/gcloud|application_default_credentials|~/\.kube/config|\.dockercfg|\.docker/config\.json)`),
		},
		
		// Cloud metadata endpoints
		{
			Name:        "cloud-metadata",
			Risk:        HighRisk,
			Description: "Cloud metadata endpoint access (possible credential theft)",
			Regex:       regexp.MustCompile(`(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|instance-data|/latest/meta-data|/computeMetadata/|/metadata/instance)`),
		},
		
		// Cron persistence
		{
			Name:        "cron-persist",
			Risk:        MediumRisk,
			Description: "Cron job persistence mechanism",
			Regex:       regexp.MustCompile(`(crontab\s+-l|crontab\s+-e|\|\s*crontab|/etc/crontab|/etc/cron\.|/var/spool/cron|@reboot|@daily|@hourly).*(curl|wget|bash|sh|python|exec)`),
		},
		
		// macOS persistence
		{
			Name:        "macos-persist",
			Risk:        MediumRisk,
			Description: "macOS Launch persistence",
			Regex:       regexp.MustCompile(`(LaunchAgents|LaunchDaemons|launchctl\s+load|launchctl\s+submit|com\.apple\.|RunAtLoad|StartInterval)`),
		},
		
		// Systemd persistence
		{
			Name:        "systemd-persist",
			Risk:        MediumRisk,
			Description: "Systemd service persistence",
			Regex:       regexp.MustCompile(`(/etc/systemd/system|systemctl\s+enable|systemctl\s+daemon-reload|WantedBy=multi-user\.target|\[Service\]|\[Unit\]).*(ExecStart|curl|wget|bash)`),
		},
		
		// Docker socket
		{
			Name:        "docker-socket",
			Risk:        MediumRisk,
			Description: "Docker socket abuse (container escape)",
			Regex:       regexp.MustCompile(`(/var/run/docker\.sock|--unix-socket.*docker\.sock|docker\s+-H\s+unix://|DOCKER_HOST.*unix://)`),
		},
		
		// Kubernetes tokens
		{
			Name:        "k8s-token",
			Risk:        HighRisk,
			Description: "Kubernetes service account token access",
			Regex:       regexp.MustCompile(`(/var/run/secrets/kubernetes\.io/serviceaccount|/serviceaccount/token|kube-api|kubectl.*--token)`),
		},
		
		// SSH key theft
		{
			Name:        "ssh-theft",
			Risk:        HighRisk,
			Description: "SSH key theft",
			Regex:       regexp.MustCompile(`(~/\.ssh/id_rsa|~/\.ssh/id_ed25519|~/\.ssh/id_dsa|~/\.ssh/id_ecdsa|ssh-keygen|~/.ssh/authorized_keys).*(cat|cp|curl|wget|POST|upload)`),
		},
		
		// History harvesting
		{
			Name:        "history-harvest",
			Risk:        MediumRisk,
			Description: "History file harvesting",
			Regex:       regexp.MustCompile(`(\.bash_history|\.zsh_history|\.sh_history|\.mysql_history|\.psql_history|\.sqlite_history).*(grep|cat|strings|upload|POST)`),
		},
		
		// Git credentials
		{
			Name:        "git-creds",
			Risk:        HighRisk,
			Description: "Git credential harvesting",
			Regex:       regexp.MustCompile(`(\.git-credentials|credential\.helper|GIT_ASKPASS|\.netrc|\.gitconfig.*password)`),
		},
		
		// Database credentials
		{
			Name:        "db-creds",
			Risk:        HighRisk,
			Description: "Database credential file access",
			Regex:       regexp.MustCompile(`(\.pgpass|\.my\.cnf|\.mongocreds|\.redis-cli|tnsnames\.ora|\.cassandra/cqlshrc)`),
		},
		
		// Package registry tokens
		{
			Name:        "registry-tokens",
			Risk:        HighRisk,
			Description: "Package registry token theft",
			Regex:       regexp.MustCompile(`(\.npmrc.*authToken|\.pypirc|\.gem/credentials|\.cargo/credentials|\.config/hub)`),
		},
		
		// Anti-debugging
		{
			Name:        "anti-debug",
			Risk:        MediumRisk,
			Description: "Anti-debugging/analysis techniques",
			Regex:       regexp.MustCompile(`(IsDebuggerPresent|CheckRemoteDebugger|ptrace.*PTRACE_TRACEME|/proc/self/status.*TracerPid)`),
		},
		
		// VM detection
		{
			Name:        "vm-detect",
			Risk:        MediumRisk,
			Description: "VM/Sandbox detection",
			Regex:       regexp.MustCompile(`(/sys/class/dmi/id/product_name|/sys/hypervisor|VirtualBox|VMware|QEMU|Hyper-V|/proc/scsi/scsi.*VBOX)`),
		},
		
		// Special validators (patterns that need custom logic)
		{
			Name:        "bidi-chars",
			Risk:        HighRisk,
			Description: "[GuardDog] Bidirectional Unicode characters (possible invisible code)",
			Validator:   checkForBidiChars,
		},
		{
			Name:        "cyrillic-chars",
			Risk:        Suspicious,
			Description: "[GuardDog] Cyrillic characters in code (possible homograph attack)",
			Validator:   checkForCyrillic,
		},
		{
			Name:        "non-ascii",
			Risk:        Suspicious,
			Description: "Non-ASCII/Unicode characters detected",
			Validator:   checkForNonASCII,
		},
	}
	
	// Add Dockerfile-specific patterns
	s.addDockerfilePatterns()
	
	// Add GitHub Actions patterns
	s.addGitHubActionsPatterns()
	
	// Add JavaScript/TypeScript specific patterns
	s.addJavaScriptPatterns()
	
	// Add Python specific patterns
	s.addPythonPatterns()

	// Add AI-agent config / instruction file patterns
	s.addAIAgentPatterns()
}

