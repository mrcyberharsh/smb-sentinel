# SMB Sentinel — MR CYBER

<p align="center"><strong>Read-only SMB configuration review for private networks</strong></p>

SMB Sentinel checks common SMB configuration signals on devices you own or are explicitly authorized to assess. It uses standard SMB negotiation messages and does not authenticate, exploit services, or attempt password guessing.

## Current checks

- SMB service reachability
- Legacy SMBv1 negotiation support
- SMB2/3 dialect information when returned by the host
- SMB signing enabled/required posture
- Human-readable risk findings

Results are configuration indicators, not proof that a host is vulnerable or secure.

## New in this development build

- Local scan history (up to 50 snapshots)
- CSV export
- PDF configuration reports
- Private IPv4 scope enforcement (maximum /24)
- Authorization confirmation before a scan
- Ed25519-based offline license verification (publisher private key is not shipped in the app)

The history file is stored in the user's home directory as `.smb-sentinel-history.json`. It contains internal IP addresses and SMB configuration details; do not publish it.

## Requirements

- Python 3.10+
- Windows or Linux desktop environment
- Python dependencies from [requirements.txt](requirements.txt)

## Installation

```bash
git clone https://github.com/mrcyberharsh/smb-sentinel.git
cd smb-sentinel
python -m venv .venv
```

**Linux**
```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

**Windows PowerShell**
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

The app also has a small Tkinter/CustomTkinter GUI. For a local network, choose **Auto-Detect My Network** or enter a private IPv4 CIDR no larger than /24. The app asks you to confirm authorization before scanning.

## Premium license setup (publisher only)

The previous HMAC secret was embedded in a public source file, which made license forgery possible. This branch replaces it with Ed25519 signatures:

1. On your trusted publisher machine, run `python generate_signing_keys.py`.
2. Keep `smb_sentinel_private_key.pem` offline and never commit or distribute it.
3. Copy the printed public key into `PUBLIC_KEY_B64` in `license_manager.py`.
4. Generate a customer key with `python generate_license.py "customer tag"`.
5. Send only the generated license string to the customer.

The app fails closed until a public verification key is configured. If you rotate the key pair, previously issued licenses will no longer verify unless you maintain a deliberate key-rotation strategy. The generator and public-key setup should be completed before offering premium activation.

## Exports and history

After a scan, premium users can export:
- **CSV** — spreadsheet-friendly host and configuration findings.
- **PDF** — printable SMB posture report.
- **Scan history** — recent scan timestamps and high/medium finding counts.

Exports are generated locally. Review reports before sharing because IP addresses and device configuration can be sensitive.

## Build a standalone application

Build on the target operating system:

```bash
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name SMB-Sentinel main.py
```

Build Windows executables on Windows and Linux binaries on Linux (or use matching CI runners).

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q main.py scanner.py license_manager.py history.py reports.py
```

GitHub Actions runs these checks on pushes and pull requests.

## Responsible use

- Scan only private networks and devices you own or have explicit permission to review.
- Keep assessments within the approved scope.
- Do not use the tool to disrupt services or attempt unauthorized access.
- Treat findings as leads for an administrator to validate.

## License and credits

See [LICENSE](LICENSE) for the applicable license.

**MR CYBER PULSE** · https://github.com/mrcyberharsh
