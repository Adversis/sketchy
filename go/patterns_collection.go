package main

import "regexp"

// pyJSFileTypes is the Python plus JavaScript scope most of the upstream
// collection rules use.
var pyJSFileTypes = []string{
	".py", ".pyx", ".pyi", ".pth",
	".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
}

var (
	// Keylogging: a capture call, not merely an import. The keyboard module
	// has legitimate hotkey uses, so a bare import does not count.
	reKeyCapture = regexp.MustCompile(
		`keyboard\.hook\s*\(|keyboard\.on_press\s*\(` +
			`|pyHook|HookManager\s*\(` +
			`|SetWindowsHookEx|hook_keyboard` +
			`|require\s*\(\s*['"](iohook|keypress|node-global-key-listener)['"]\s*\)` +
			`|iohook\.start\s*\(`)
	rePynputListener = regexp.MustCompile(`from\s+pynput\s+import\s+keyboard|keyboard\.Listener\s*\(`)
	rePynputOnPress  = regexp.MustCompile(`on_press`)
	reEvdev          = regexp.MustCompile(`from\s+evdev\s+import|InputDevice\s*\(`)
	reEvdevKey       = regexp.MustCompile(`ecodes\.EV_KEY`)
	reXlib           = regexp.MustCompile(`from\s+Xlib\s+import|display\.Display\s*\(`)
	reXlibRecord     = regexp.MustCompile(`record\.create_context\s*\(`)

	// Process memory / credential dumping.
	reMemDumpTool = regexp.MustCompile(`(?i)mimikatz|pypykatz|\blsass\b|secretsdump`)
	reMemLowLevel = regexp.MustCompile(`ptrace\.attach\s*\(|PTRACE_PEEKDATA|ReadProcessMemory`)
	reMemOpenProc = regexp.MustCompile(`OpenProcess`)
	reMemPsutil   = regexp.MustCompile(`psutil\.Process\s*\(|\.memory_info\s*\(|\.memory_maps\s*\(`)
	reMemCredHunt = regexp.MustCompile(
		`(?i)(search|scan|find|extract|dump|read)[^\n]{0,40}(password|credential|secret|token|memory|heap)`)

	// Clipboard access. Upstream treats this as a capability; sketchy has no
	// capability pairing, so it is narrowed here to the hijacking threat by
	// requiring a crypto-address or exfil co-signal.
	reClipboard = regexp.MustCompile(
		`(?i)pyperclip\.(paste|copy)\s*\(` +
			`|pandas\.read_clipboard\s*\(|\.to_clipboard\s*\(|read_clipboard\s*\(` +
			`|clipboard_get\s*\(` +
			`|clipboardy\.(read|readSync|write|writeSync)` +
			`|clipboard\.readText\s*\(` +
			`|clipboard\.(ReadAll|WriteAll)\s*\(`)
	reCryptoAddress = regexp.MustCompile(
		`\[13\]\[a-km-zA-HJ-NP-Z1-9\]|0x\[a-fA-F0-9\]\{40\}` +
			`|0x[a-fA-F0-9]{40}` +
			`|(?i)(address|wallet)_(btc|eth|xmr|xchain)|(?i)(btc|eth|xmr)_address`)
	reClipExfil = regexp.MustCompile(`(?i)exfiltrate|\bsend_?(data|loot)\b`)

	// Messenger exfiltration: a hardcoded webhook or bot token, not merely
	// using the platform's SDK.
	reMessenger = regexp.MustCompile(
		`(?i)discord(app)?\.com/api/webhooks/\d+/` +
			`|api\.telegram\.org/bot\d+:` +
			`|\b\d{8,12}:[A-Za-z0-9_-]{30,40}\b`)
)

// addCollectionPatterns adds the credential-access and collection rules
// ported from upstream GuardDog.
func (s *Scanner) addCollectionPatterns() {
	collectionPatterns := []Pattern{
		// upstream: threat-runtime-keylogging
		{
			Name:        "keylogging",
			Risk:        HighRisk,
			Description: "[GuardDog] Keylogging or input capture",
			Regex: regexp.MustCompile(
				`keyboard\.hook\s*\(|keyboard\.on_press\s*\(|keyboard\.Listener\s*\(` +
					`|pyHook|HookManager\s*\(|SetWindowsHookEx|hook_keyboard` +
					`|require\s*\(\s*['"](iohook|keypress|node-global-key-listener)['"]\s*\)` +
					`|iohook\.start\s*\(|InputDevice\s*\(|record\.create_context\s*\(`),
			FileTypes:   pyJSFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				if reKeyCapture.MatchString(content) {
					return true
				}
				if rePynputListener.MatchString(content) && rePynputOnPress.MatchString(content) {
					return true
				}
				if reEvdev.MatchString(content) && reEvdevKey.MatchString(content) {
					return true
				}
				return reXlib.MatchString(content) && reXlibRecord.MatchString(content)
			},
		},

		// upstream: threat-runtime-screencapture
		{
			Name:        "screencapture",
			Risk:        MediumRisk,
			Description: "[GuardDog] Screen capture of the user's display",
			Regex: regexp.MustCompile(
				`\bImageGrab\s*\.\s*grab\s*\(` +
					`|\bpyscreenshot\s*\.\s*grab\s*\(` +
					`|\bpyautogui\s*\.\s*screenshot\s*\(` +
					`|\bmss\s*\.\s*mss\s*\(\s*\)` +
					`|\bwith\s+mss\s*\.\s*mss\s*\(\s*\)\s+as\b` +
					`|\bd3dshot\s*\.\s*create\s*\([^)]*\)\s*\.\s*screenshot\s*\(`),
			FileTypes:   pyFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
		},

		// upstream: threat-process-memory
		{
			Name:        "process-memory",
			Risk:        HighRisk,
			Description: "[GuardDog] Process memory scraping or credential dumping",
			Regex: regexp.MustCompile(
				`(?i)mimikatz|pypykatz|\blsass\b|secretsdump` +
					`|ptrace\.attach\s*\(|PTRACE_PEEKDATA|ReadProcessMemory|OpenProcess` +
					`|psutil\.Process\s*\(`),
			FileTypes:   pyJSFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				if reMemDumpTool.MatchString(content) || reMemLowLevel.MatchString(content) {
					return true
				}
				// OpenProcess alone is a benign liveness check; it only counts
				// with an actual memory read.
				if reMemOpenProc.MatchString(content) && reMemLowLevel.MatchString(content) {
					return true
				}
				// Reading memory stats only matters when paired with hunting
				// for credentials in the result.
				return reMemPsutil.MatchString(content) && reMemCredHunt.MatchString(content)
			},
		},

		// upstream: capability-runtime-clipboard (narrowed, see note above)
		{
			Name:        "clipboard-access",
			Risk:        HighRisk,
			Description: "[GuardDog] Clipboard hijacking (clipboard access paired with crypto address or exfil)",
			Regex: regexp.MustCompile(
				`(?i)pyperclip\.(paste|copy)\s*\(` +
					`|read_clipboard\s*\(|\.to_clipboard\s*\(|clipboard_get\s*\(` +
					`|clipboardy\.(read|readSync|write|writeSync)` +
					`|clipboard\.readText\s*\(|clipboard\.(ReadAll|WriteAll)\s*\(`),
			FileTypes:   append(append([]string{}, pyJSFileTypes...), ".go"),
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				if !reClipboard.MatchString(content) {
					return false
				}
				return reCryptoAddress.MatchString(content) || reClipExfil.MatchString(content)
			},
		},

		// upstream: threat-network-exfil-messenger
		{
			Name:        "exfil-messenger",
			Risk:        HighRisk,
			Description: "[GuardDog] Hardcoded messenger webhook or bot token (exfiltration channel)",
			Regex:       reMessenger,
			FileTypes:   pyJSFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
		},
	}

	s.Patterns = append(s.Patterns, collectionPatterns...)
}
