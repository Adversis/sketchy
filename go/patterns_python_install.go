package main

import "regexp"

// pyFileTypes matches the Python sources upstream GuardDog scopes to.
var pyFileTypes = []string{".py", ".pyx", ".pyi", ".pth"}

// setupFileTypes scopes a rule to build scripts. FileTypes is a suffix match,
// so this covers both setup.py and pkg/setup.py.
var setupFileTypes = []string{"setup.py"}

var (
	// A build script is identified by the setuptools/distutils entry point.
	// Without it, a file merely named setup.py is not necessarily install
	// time code.
	reSetupIndicator = regexp.MustCompile(`\bsetup\s*\(|from\s+setuptools\s+import|from\s+distutils`)

	// Aliased imports of process and code execution. Aliasing exists to make
	// the call site unrecognisable, which a build script never needs.
	reSetupAliasExec = regexp.MustCompile(
		`(?i)from\s+os\s+import\s+system\s+as\s` +
			`|from\s+os\s+import\s+popen\s+as\s` +
			`|from\s+subprocess\s+import\s+(call|run|Popen|check_output|check_call)\s+as\s` +
			`|from\s+os\s+import\s+exec\w*\s+as\s` +
			`|from\s+builtins\s+import\s+exec\s+as\s`)
	// Re-invoking the interpreter, aliased. Half of the classic dropper.
	reSetupAliasExecutable  = regexp.MustCompile(`(?i)from\s+sys\s+import\s+executable\s+as\s`)
	reSetupTempfile         = regexp.MustCompile(`(?i)from\s+tempfile\s+import\s+NamedTemporaryFile\s+as\s`)
	reSetupSystemDirect     = regexp.MustCompile(`(?i)from\s+os\s+import\s+system\b`)
	reSetupExecutableDirect = regexp.MustCompile(`(?i)from\s+sys\s+import\s+executable\b`)

	// Imports with no place in a build script.
	reSetupImportNetwork = regexp.MustCompile(
		`(?i)\bimport\s+requests\b|\bimport\s+urllib\b|\bfrom\s+urllib|\bimport\s+http\.client\b|\bimport\s+socket\b`)
	reSetupImportSystem = regexp.MustCompile(`(?i)\bimport\s+subprocess\b|\bimport\s+ctypes\b|\bimport\s+winreg\b`)
	reSetupImportCrypto = regexp.MustCompile(`(?i)\bimport\s+base64\b|\bimport\s+marshal\b|\bimport\s+codecs\b`)

	// Network calls and host fingerprinting at install time.
	reSetupNetCall = regexp.MustCompile(
		`(?i)requests\.(get|post|put)\s*\(` +
			`|urllib\.\w+\.urlopen\s*\(` +
			`|urllib\.\w+\.urlretrieve\s*\(` +
			`|http\.client\.HTTP` +
			`|socket\.\w*\.?\s*connect\s*\(` +
			`|socket\.socket\s*\(`)
	reSetupSysinfo = regexp.MustCompile(
		`(?i)socket\.gethostname\s*\(\s*\)` +
			`|platform\.(system|machine|node|uname)\s*\(\s*\)` +
			`|getpass\.getuser\s*\(\s*\)` +
			`|os\.getlogin\s*\(\s*\)`)
	reSetupB64 = regexp.MustCompile(`(?i)base64\.\w*decode\s*\(`)

	// Dynamic loading: resolve a module by name, fetch code, run it.
	reDynImport = regexp.MustCompile(`importlib\.import_module\s*\(|importlib\.util\.spec_from_|__import__\s*\(`)
	reDynFetch  = regexp.MustCompile(`(?i)urllib\.\w*request\w*\.(urlopen|urlretrieve)\s*\(|requests\.get\s*\(`)
	// Bare exec(/eval(, not a method call, so obj.eval() does not count.
	reDynSink    = regexp.MustCompile(`(^|[^.\w])(exec|eval)\s*\(`)
	reDynGetattr = regexp.MustCompile(`getattr\s*\(\s*\w+\s*,`)
	reDynB64     = regexp.MustCompile(`(?i)base64\.\w*decode|b64decode\s*\(`)
)

// addPythonInstallPatterns adds the Python install-time and dynamic-loading
// rules ported from upstream GuardDog.
func (s *Scanner) addPythonInstallPatterns() {
	pyPatterns := []Pattern{
		// upstream: threat-setup-import-aliasing
		{
			Name:        "py-setup-import-aliasing",
			Risk:        HighRisk,
			Description: "[GuardDog] setup.py aliases dangerous imports (dropper pattern)",
			Regex: regexp.MustCompile(
				`(?i)from\s+(os|subprocess|builtins|sys|tempfile)\s+import\s+\w+\s+as\s|from\s+os\s+import\s+system\b|from\s+sys\s+import\s+executable\b`),
			FileTypes:   setupFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     3,
			Validator: func(content string) bool {
				if !reSetupIndicator.MatchString(content) {
					return false
				}
				if reSetupAliasExec.MatchString(content) || reSetupAliasExecutable.MatchString(content) {
					return true
				}
				// Direct (unaliased) imports only count alongside the
				// tempfile half of the dropper.
				if reSetupTempfile.MatchString(content) {
					return reSetupSystemDirect.MatchString(content) ||
						reSetupExecutableDirect.MatchString(content)
				}
				return false
			},
		},

		// upstream: threat-setup-suspicious-imports
		{
			Name:        "py-setup-suspicious-imports",
			Risk:        HighRisk,
			Description: "[GuardDog] setup.py imports network, system or crypto libraries",
			Regex: regexp.MustCompile(
				`(?i)\bimport\s+(requests|urllib|socket|subprocess|ctypes|winreg|base64|marshal|codecs)\b|\bfrom\s+urllib|\bimport\s+http\.client\b`),
			FileTypes:   setupFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     3,
			Validator: func(content string) bool {
				if !reSetupIndicator.MatchString(content) {
					return false
				}
				if reSetupImportNetwork.MatchString(content) {
					return true
				}
				// os and sys alone are ordinary in a build script; a system
				// module only counts alongside network or encoding imports.
				return reSetupImportSystem.MatchString(content) &&
					(reSetupImportNetwork.MatchString(content) || reSetupImportCrypto.MatchString(content))
			},
		},

		// upstream: threat-setup-network-in-install
		{
			Name:        "py-setup-network",
			Risk:        HighRisk,
			Description: "[GuardDog] setup.py performs network I/O or host fingerprinting at install time",
			Regex: regexp.MustCompile(
				`(?i)requests\.(get|post|put)\s*\(|urllib\.\w+\.(urlopen|urlretrieve)\s*\(|http\.client\.HTTP|socket\.socket\s*\(|socket\.gethostname\s*\(`),
			FileTypes:   setupFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     3,
			Validator: func(content string) bool {
				if !reSetupIndicator.MatchString(content) {
					return false
				}
				if reSetupNetCall.MatchString(content) {
					return true
				}
				return reSetupB64.MatchString(content) && reSetupSysinfo.MatchString(content)
			},
		},

		// upstream: threat-runtime-dynamic-loader
		{
			Name:        "py-dynamic-loader",
			Risk:        HighRisk,
			Description: "[GuardDog] Downloads and executes code at runtime via dynamic import",
			Regex:       regexp.MustCompile(`importlib\.import_module\s*\(|importlib\.util\.spec_from_|__import__\s*\(`),
			FileTypes:   pyFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
			Validator: func(content string) bool {
				if !reDynImport.MatchString(content) {
					return false
				}
				// Fetch the payload then run it.
				if reDynFetch.MatchString(content) && reDynSink.MatchString(content) {
					return true
				}
				// Or resolve the call target reflectively from decoded data.
				return reDynGetattr.MatchString(content) && reDynB64.MatchString(content)
			},
		},

		// upstream: threat-runtime-obfuscation-pyarmor
		// PyArmor is a commercial packer. It is legal to use, but a package
		// that ships obfuscated bytecode cannot be reviewed, which is why
		// upstream rates it medium rather than high.
		{
			Name:        "py-pyarmor",
			Risk:        MediumRisk,
			Description: "[GuardDog] PyArmor-obfuscated Python (source cannot be reviewed)",
			Regex: regexp.MustCompile(
				`__pyarmor__\s*\(` +
					`|from\s+pytransform\s+import\s` +
					`|import\s+pytransform\b` +
					`|pyarmor_runtime\s*\(` +
					`|from\s+pyarmor_runtime\w*\s+import\s` +
					`|__armor_enter__|__armor_exit__|__pyarmor_enter__|__pyarmor_exit__` +
					`|check_armored\s*\(|assert_armored\s*\(`),
			FileTypes:   pyFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
		},
	}

	s.Patterns = append(s.Patterns, pyPatterns...)
}
