package main

import "regexp"

var (
	// PowerShell encoded commands and download cradles.
	rePSEncoded = regexp.MustCompile(
		`(?i)powershell[^\n]{0,80}-EncodedCommand\s+[A-Za-z0-9+/=]{20,}` +
			`|powershell[^\n]{0,80}-enc\s+[A-Za-z0-9+/=]{20,}`)
	rePSCradle = regexp.MustCompile(
		`(?i)IEX\s*\(\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest)` +
			`|\(New-Object\s+Net\.WebClient\)\.DownloadString\s*\(` +
			`|\(New-Object\s+Net\.WebClient\)\.DownloadFile\s*\(`)
	rePSHidden  = regexp.MustCompile(`(?i)powershell[^\n]{0,80}-WindowStyle\s+Hidden`)
	rePSInvoked = regexp.MustCompile(`(?i)Popen\s*\(\s*['"]?powershell|os\.(system|popen)\s*\(\s*['"]?powershell|exec\w*\s*\(\s*['"]?[^'"]*powershell`)

	// JavaScript name mangling: _0x identifiers. Counted, because one hex
	// constant is meaningless and a packed file has many.
	reMangledIdent = regexp.MustCompile(`_0x[a-f0-9]{4,6}\b`)

	// Console suppression paired with obfuscation in the same file.
	reLogSuppress = regexp.MustCompile(
		`(?i)console\.(log|warn|error)\s*=\s*function\s*\(\s*\)|console\s*=\s*\{`)
	reObfNearby = regexp.MustCompile(
		`(?i)\[\s*0x[0-9a-f]+\s*,\s*0x[0-9a-f]+\s*,\s*0x[0-9a-f]+|fromCodePoint|fromCharCode`)

	// Reflective resolution where the resolved value is immediately invoked.
	reReflectiveCall = regexp.MustCompile(
		`getattr\s*\([^,]+,\s*['"](__import__|exec|eval|compile)['"]\s*\)\s*\(` +
			`|getattr\s*\(\s*__builtins__\s*,[^)]*\)\s*\(` +
			`|Object\s*\.\s*getOwnPropertyDescriptor\s*\([^)]+,[^)]+\)\s*\.\s*value\s*\(` +
			`|\[\s*Object\s*\.\s*getOwnPropertyNames\s*\([^)]+\)\s*\.\s*find\s*\(` +
			`|\[\s*Object\s*\.\s*keys\s*\([^)]+\)\s*\.\s*find\s*\(` +
			`|Object\s*\.\s*entries\s*\([^)]+\)\s*\.\s*find\s*\([^)]+\)\s*\[\s*1\s*\]` +
			`|Object\s*\.\s*entries\s*\([^)]+\)\s*\.\s*filter\s*\([^)]+\)\s*\[\s*0\s*\]\s*\[\s*1\s*\]`)

	// Autostart locations. Unix shell startup files and system-wide init
	// directories, plus the Windows Run keys and Startup folder.
	reAutostartLocation = regexp.MustCompile(
		`(?i)SOFTWARE\\+Microsoft\\+Windows\\+CurrentVersion\\+Run(Once)?` +
			`|\\+Start Menu\\+Programs\\+Startup` +
			`|\.bashrc|\.bash_profile|\.zshrc|\.zprofile` +
			`|['"][^'"]*\.profile['"]` +
			`|/etc/rc\.local|/etc/init\.d/|/etc/profile\.d/|\.config/autostart/`)
	// The write that actually installs persistence. Scoped so a bare
	// reference to a path, or an unrelated urlopen, does not qualify.
	reAutostartWrite = regexp.MustCompile(
		`(?i)winreg\.SetValueEx\s*\(|RegSetValue` +
			`|fs\.(writeFile|appendFile)` +
			`|\bopen\s*\([^)]*,\s*['"][wa]` +
			`|\.write\s*\(|>>`)

	// Host and network enumeration. Upstream requires two signals.
	reEnumSignals = []*regexp.Regexp{
		regexp.MustCompile(`psutil\.process_iter\s*\(|psutil\.pids\s*\(`),
		regexp.MustCompile(`(?i)require\s*\(\s*['"](ps-list|process-list|find-process|network-list)['"]`),
		regexp.MustCompile(`netifaces\.interfaces\s*\(|os\.networkInterfaces\s*\(`),
		regexp.MustCompile(`(?i)\bifconfig\b|\bip\s+addr\b`),
		regexp.MustCompile(`/etc/passwd|pwd\.getpwall\s*\(`),
		regexp.MustCompile(`(?i)\bport[\s_-]?scan`),
		regexp.MustCompile(`\bnmap\b`),
	}
)

// addEvasionPatterns adds the evasion, obfuscation and Windows-persistence
// rules ported from upstream GuardDog.
func (s *Scanner) addEvasionPatterns() {
	evasionPatterns := []Pattern{
		// upstream: threat-process-powershell-encoded
		{
			Name:        "powershell-encoded",
			Risk:        HighRisk,
			Description: "[GuardDog] PowerShell encoded command, hidden window or download cradle",
			Regex: regexp.MustCompile(
				`(?i)-EncodedCommand\s+[A-Za-z0-9+/=]{20,}|-enc\s+[A-Za-z0-9+/=]{20,}` +
					`|IEX\s*\(\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest)` +
					`|\(New-Object\s+Net\.WebClient\)\.Download(String|File)\s*\(` +
					`|powershell[^\n]{0,80}-WindowStyle\s+Hidden`),
			FileTypes:   append(append([]string{}, pyJSFileTypes...), ".ps1", ".sh", ".bat", ".cmd"),
			PathExclude: generatedPaths,
			MaxHits:     3,
			Validator: func(content string) bool {
				if rePSEncoded.MatchString(content) || rePSCradle.MatchString(content) {
					return true
				}
				// A hidden window only counts when something is actually
				// invoking PowerShell.
				return rePSHidden.MatchString(content) && rePSInvoked.MatchString(content)
			},
		},

		// upstream: threat-runtime-obfuscation-js-mangling
		{
			Name:        "js-mangling",
			Risk:        MediumRisk,
			Description: "[GuardDog] JavaScript name mangling (_0x identifiers) from an obfuscator",
			Regex:       reMangledIdent,
			FileTypes:   jsFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
			Validator: func(content string) bool {
				// Upstream requires three distinct mangled-identifier hits.
				// One or two hex-looking names are ordinary constants.
				return len(reMangledIdent.FindAllString(content, 4)) >= 3
			},
		},

		// upstream: threat-runtime-obfuscation-log-suppress
		{
			Name:        "js-log-suppress",
			Risk:        MediumRisk,
			Description: "[GuardDog] Console suppression alongside obfuscated code",
			Regex:       reLogSuppress,
			FileTypes:   jsFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
			Validator: func(content string) bool {
				return reLogSuppress.MatchString(content) && reObfNearby.MatchString(content)
			},
		},

		// upstream: threat-runtime-obfuscation-api
		{
			Name:        "obfuscation-api",
			Risk:        MediumRisk,
			Description: "[GuardDog] API call obfuscated through reflection or introspection",
			Regex:       reReflectiveCall,
			FileTypes:   append(append([]string{}, pyJSFileTypes...), ".go"),
			PathExclude: generatedPaths,
			MaxHits:     2,
		},

		// upstream: threat-filesystem-autostart
		//
		// Deliberately file-scoped rather than line-scoped. The existing
		// shell-persistence rule requires the startup file and the write verb
		// on one line, so it misses the ordinary shape where a path is bound
		// to a variable and written a few lines later. This rule adds the
		// Windows Run keys and Startup folder at the same time.
		{
			Name:        "autostart-persistence",
			Risk:        HighRisk,
			Description: "[GuardDog] Autostart persistence (shell startup file, init dir, Run key or Startup folder)",
			Regex:       reAutostartLocation,
			FileTypes:   pyJSFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				// Referencing an autostart location only matters if something
				// is written to it.
				return reAutostartLocation.MatchString(content) &&
					reAutostartWrite.MatchString(content)
			},
		},

		// upstream: threat-runtime-enumeration
		{
			Name:        "runtime-enumeration",
			Risk:        MediumRisk,
			Description: "[GuardDog] Extensive system or network enumeration",
			Regex: regexp.MustCompile(
				`psutil\.process_iter\s*\(|psutil\.pids\s*\(|netifaces\.interfaces\s*\(` +
					`|os\.networkInterfaces\s*\(|/etc/passwd|pwd\.getpwall\s*\(` +
					`|(?i)\bport[\s_-]?scan|\bnmap\b`),
			FileTypes:   pyJSFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				// Two independent signals, matching upstream's "2 of them".
				hits := 0
				for _, re := range reEnumSignals {
					if re.MatchString(content) {
						hits++
					}
				}
				return hits >= 2
			},
		},
	}

	s.Patterns = append(s.Patterns, evasionPatterns...)
}
