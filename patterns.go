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

// addDockerfilePatterns adds Dockerfile-specific patterns
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

// addGitHubActionsPatterns adds GitHub Actions workflow patterns
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

// addJavaScriptPatterns adds JavaScript/TypeScript specific patterns
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

// addPythonPatterns adds Python specific patterns
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