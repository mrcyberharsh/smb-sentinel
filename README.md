# SMB Sentinel — MR CYBER

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
| Scan history & trends | 🔒 | ✅ |

## Premium activation (manual, until you have a payment gateway)

Since you're not able to open a payment-gateway merchant account yet:

1. Customer pays you directly (UPI, personal transfer, etc.) — you verify it yourself.
2. You run:
   ```bash
   python generate_license.py "customer name or email"
   ```
3. Copy the printed key and email it to the customer.
4. They paste it into **Settings → Premium License Key → Activate**.

The key is cryptographically signed (HMAC-SHA256) against a secret embedded
in the app, so it can't just be guessed or typo'd into working — but like
any client-side check, someone determined enough could eventually extract
the secret from the binary. **Before you have real paying customers, change
the placeholder `_SECRET` value in `license_manager.py` to your own random
string, and don't commit that real value to a public GitHub repo.**

When you're 18 and have a payment gateway (Cashfree/Instamojo/Razorpay) set
up with a backend, replace this offline check with a server-side license
verification API call — that closes the "extract the secret from the exe"
gap almost entirely. This manual system is a solid stopgap, not the
permanent design.

## Notes on the CVE-matching, PDF export, and deep-check premium features

These are currently placeholders (the buttons show an upgrade prompt or a
confirmation if premium). Let me know when you want these actually built out —
CVE matching needs a small bundled CVE dataset or an online lookup, and PDF
export needs the `reportlab` or similar library.
