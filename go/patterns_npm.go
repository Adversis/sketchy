package main

import "regexp"

// jsFileTypes matches the JavaScript/TypeScript sources upstream GuardDog
// scopes its npm rules to (path_include on the .yar rules).
var jsFileTypes = []string{".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

// generatedPaths are trees where obfuscation-shaped code is expected and
// says nothing about intent: bundler output and vendored dependencies.
// Upstream sets these as path_exclude on its JS obfuscation rules.
var generatedPaths = []string{"node_modules/", "dist/", "build/", "vendor/"}

var (
	// Programmatically invoking a registry publish from package code. A
	// publish is a human or CI action; a package doing it to itself at
	// runtime is propagating.
	reNpmPublish = regexp.MustCompile(`['"` + "`" + `]\s*(npm|yarn|pnpm)\s+publish`)
	// Rewriting its own manifest to clone itself under a new identity.
	reWriteManifest = regexp.MustCompile(`\b(writeFile(Sync)?|writeJson(Sync)?|outputJson(Sync)?)\s*\(\s*['"` + "`" + `][^'"` + "`" + `]*package(-lock)?\.json`)
	// Process-execution capability used to drive the publish.
	reChildProcess = regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)|\bexec(Sync|File|FileSync)?\s*\(|\bspawn(Sync)?\s*\(`)

	// Hidden-payload indicators.
	reGlobalRequire = regexp.MustCompile(`global\s*\[\s*['"][A-Za-z0-9_$]{1,6}['"]\s*\]\s*=\s*require\b`)
	reWhitespaceGap = regexp.MustCompile(`[ ]{400,}\S`)
	reJSExecSink    = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(`)

	// package.json dependency-specifier shapes.
	reHTTPDepIP     = regexp.MustCompile(`:\s*"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	reHTTPDepArch   = regexp.MustCompile(`(?i):\s*"https?://[^"]+\.(tar\.gz|tgz|zip)"`)
	reHTTPPlain     = regexp.MustCompile(`:\s*"http://[^"]+"`)
	reHTTPMeta      = regexp.MustCompile(`(?i)"(web|website|homepage|funding|bugs|email|wiki|blog|docs|documentation|repository|author|maintainers|contributors|logo|image)"\s*:\s*"http://`)
	reHTTPMetaURL   = regexp.MustCompile(`(?i)"(author|repository|bugs|funding|contributors|maintainers)"\s*:\s*[\[{][^}]*"url"\s*:\s*"http://`)
	reHTTPDepAnchor = regexp.MustCompile(`:\s*"https?://`)
)

// addNpmPatterns adds the npm / JavaScript supply-chain rules ported from
// upstream GuardDog. Several upstream rules combine multiple independent
// signals with boolean logic that a single RE2 expression cannot express,
// so those use a Validator and keep the regex only to anchor the report.
func (s *Scanner) addNpmPatterns() {
	npmPatterns := []Pattern{
		// upstream: threat-runtime-self-propagation
		// Worm behaviour: the package rewrites its own manifest and publishes
		// copies of itself. All three signals are required.
		{
			Name:        "npm-self-propagation",
			Risk:        HighRisk,
			Description: "[GuardDog] Self-propagating package (rewrites own manifest and publishes)",
			Regex:       reNpmPublish,
			FileTypes:   jsFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
			Validator: func(content string) bool {
				return reNpmPublish.MatchString(content) &&
					reWriteManifest.MatchString(content) &&
					reChildProcess.MatchString(content)
			},
		},

		// upstream: threat-runtime-obfuscation-hidden-code
		// Either require aliased through a global (dodges static require
		// detection), or a payload pushed off-screen by a long space run.
		{
			Name:        "js-hidden-code",
			Risk:        HighRisk,
			Description: "[GuardDog] Payload hidden via global-aliased require or whitespace padding",
			Regex:       regexp.MustCompile(`global\s*\[\s*['"][A-Za-z0-9_$]{1,6}['"]\s*\]\s*=\s*require\b|[ ]{400,}\S`),
			FileTypes:   jsFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     1,
			Validator: func(content string) bool {
				if reGlobalRequire.MatchString(content) {
					return true
				}
				return reWhitespaceGap.MatchString(content) && reJSExecSink.MatchString(content)
			},
		},

		// upstream: threat-runtime-obfuscation-dynamic-eval
		// eval / Function over a self-decoding wrapper or decoded data.
		// Bare eval() is deliberately not included; eval-exec covers that.
		{
			Name:        "js-dynamic-eval",
			Risk:        HighRisk,
			Description: "[GuardDog] eval/Function over a self-decoding or decoded payload",
			Regex: regexp.MustCompile(
				`\beval\s*\(\s*function\s*\(` +
					`|\beval\s*\([^;]{0,160}\bfromCharCode\b` +
					`|\bnew\s+Function\s*\([^;]{0,160}\bfromCharCode\b` +
					`|\beval\s*\(\s*atob\s*\(` +
					`|\bnew\s+Function\s*\(\s*atob\s*\(` +
					`|\beval\s*\(\s*[A-Za-z_$][\w$]*\s*\(\s*\[\s*\d{1,3}(\s*,\s*\d{1,3}){19,}`),
			FileTypes:   jsFileTypes,
			PathExclude: generatedPaths,
			MaxHits:     2,
		},

		// upstream: threat-npm-http-dependency
		// A dependency fetched over plain HTTP or from a raw archive URL is
		// mutable and unauthenticated. Plain-http URLs that are explained by
		// metadata fields (homepage, author, ...) are not counted, which is
		// why this needs a validator rather than a single regex.
		{
			Name:        "npm-http-dependency",
			Risk:        HighRisk,
			Description: "[GuardDog] HTTP URL dependency in package.json (mutable, unauthenticated source)",
			Regex:       reHTTPDepAnchor,
			FileTypes:   []string{"package.json"},
			PathExclude: generatedPaths,
			MaxHits:     3,
			Validator: func(content string) bool {
				if reHTTPDepIP.MatchString(content) || reHTTPDepArch.MatchString(content) {
					return true
				}
				plain := len(reHTTPPlain.FindAllString(content, -1))
				explained := len(reHTTPMeta.FindAllString(content, -1)) +
					len(reHTTPMetaURL.FindAllString(content, -1))
				return plain > explained
			},
		},

		// upstream: threat-npm-dependency-confusion
		// DNS and beacon callbacks in install scripts, the standard
		// dependency-confusion probe.
		{
			Name:        "npm-dependency-confusion",
			Risk:        HighRisk,
			Description: "[GuardDog] Dependency-confusion probe in package.json scripts (DNS/beacon callback)",
			Regex: regexp.MustCompile(
				`(?i)nslookup\s+[^"]*\$` +
					`|\bdig\s+[^"]*\$` +
					`|\bhost\s+[^"]*\$` +
					`|curl\s+[^"]*\$\{?[A-Z_]+\}?\.` +
					`|\$\(whoami\)` +
					`|\$\(hostname\)` +
					// Word boundary rather than a required leading dot, so a
					// bare collaborator host with no subdomain still matches.
					// Bounded by [^/"]* this stays inside the hostname, so an
					// unrelated path segment cannot trigger it.
					`|https?://[^/"]*\b(burpcollaborator|oastify|interact|canarytokens|dnslog)\b`),
			FileTypes:   []string{"package.json"},
			PathExclude: generatedPaths,
			MaxHits:     2,
		},
	}

	s.Patterns = append(s.Patterns, npmPatterns...)
}
