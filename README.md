# SMB Sentinel — MR CYBER HARSH 

A lightweight, friendly SMB misconfiguration scanner for home/small-office
networks. Cross-platform GUI (Windows + Linux) built with Python + customtkinter.

## What it checks (read-only, no exploitation)

- Is SMB (port 445/139) open on a device?
- Is legacy **SMBv1** enabled? (outdated, high risk)
- Is **SMB signing** enabled/required? (protects against relay attacks)

All checks are passive protocol negotiation probes — the same first step
any normal SMB client (like Windows Explorer) performs. No login attempts,
no exploitation, no brute-forcing.

## Running it

```bash
pip install -r requirements.txt --break-system-packages   # Linux may need this flag
python main.py
```

## Building a standalone .exe / Linux binary

```bash
pip install pyinstaller --break-system-packages
pyinstaller --onefile --windowed --name "SMB-Sentinel" main.py
```

- Windows: run this on a Windows machine to get `SMB-Sentinel.exe`
- Linux: run this on Linux to get an ELF binary (put it in an AppImage or .deb later)

You cannot cross-compile a Windows .exe from Linux with PyInstaller — build
each platform's binary on that platform (or use a CI runner, e.g. GitHub
Actions with both `windows-latest` and `ubuntu-latest` jobs).

## Free vs Premium

| Feature | Free | Premium |
|---|---|---|
| Network scan | Up to 14 devices | Unlimited range |
| SMBv1 / signing check | ✅ | ✅ |
| CVE matching + severity | 🔒 | ✅ |
| Deep null-session/guest check | 🔒 | ✅ |
| PDF / CSV export | 🔒 | ✅ |
| Scan history & trends |
## COPYRIGHT BY MR CYBER HARSH 
