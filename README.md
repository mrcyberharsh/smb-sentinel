# SMB Sentinel — MR CYBER

A lightweight desktop utility for reviewing common SMB security configuration signals on home and small-office networks. The GUI is built with Python and CustomTkinter.

## Current checks

- Checks whether SMB services are reachable on the standard SMB ports.
- Identifies whether legacy SMBv1 appears to be enabled.
- Reviews SMB signing support/requirements where the peer exposes that information.

The checks are intended as read-only configuration probes. SMB Sentinel does not attempt exploitation, password guessing, or unauthorized access.

## Requirements

- Python 3
- Dependencies listed in `requirements.txt`
- Windows or Linux desktop environment for the GUI

## Install and run

Clone the repository:

```bash
git clone https://github.com/mrcyberharsh/smb-sentinel.git
cd smb-sentinel
```

Install dependencies in a virtual environment:

```bash
python -m venv .venv
```

**Linux**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

**Windows PowerShell**
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

If the dependency file is missing from your checkout, check the repository's current files or open an issue before installing packages manually.

## Build a standalone application

PyInstaller can package the application on the operating system where the build is performed:

```bash
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name SMB-Sentinel main.py
```

Build separately on Windows and Linux. A Windows executable should be built on Windows (or a Windows CI runner); a Linux binary should be built on Linux.

## Feature status

| Capability | Status in current README/source description |
|---|---|
| SMB service reachability check | Documented |
| SMBv1 configuration check | Documented |
| SMB signing check | Documented |
| PDF/CSV reporting | Not confirmed |
| Scan history and trend dashboard | Not confirmed |
| CVE matching | Not confirmed |

Unconfirmed items are not advertised as available features. They can be considered for future development after implementation and testing.

## Responsible use

Only assess devices and networks you own or have explicit permission to review. Keep scans within the approved scope and avoid disrupting business or personal services. Results are configuration indicators and should be validated by an administrator.

## Contributing

Please include your operating system, Python version, steps to reproduce, and sanitized logs when reporting a problem. Do not include private network details or credentials.

## License and credits

See [LICENSE](LICENSE) for the applicable license.

**MR CYBER PULSE** · https://github.com/mrcyberharsh
