# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Development build (current `main`) | :white_check_mark: |
| Older tagged releases | :x: |

> SMB Sentinel is under active development. Only the latest `main` branch and the most recent tagged release receive security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in **SMB Sentinel itself** (not an SMB configuration finding on a scanned host), report it privately:

- **Maintainer / Developer:** Harsh Saini — cyber.h4rsh@zohomail.in
- **Manager:** Prachi Sharma — manager.prachi@zohomail.in
- **Organization:** MR Cyber Pulse

Please include:

- Type of issue (e.g., license bypass, path traversal, insecure defaults, dependency flaw, scope-limit bypass)
- Full paths of the source file(s) related to the issue
- Step-by-step reproduction instructions
- Impact assessment (does it break the read-only guarantee, the /24 scope limit, or the authorization gate?)
- Suggested fix, if available

You can expect an acknowledgement within **7 days**. We will keep you informed of progress and coordinate disclosure timing with you.

## Out of Scope

The following are **not** considered vulnerabilities in SMB Sentinel:

- SMB configuration findings produced by the tool on an authorized host
  (e.g., "SMBv1 enabled", "signing not required", "guest access")
- Risk findings that differ from manual administrator assessment
  (documented limitation — findings are configuration indicators, not proof of exploitability)
- Missing optional dependencies or unsupported Python versions
- Ed25519 license keys being non-transferable or requiring a publisher-issued signature
- Refusal to scan public IP ranges or ranges larger than /24
  (this is intentional scope enforcement, not a bypass target)

## Safe Harbor

We support safe harbor for security researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service interruption
- Only interact with SMB services they own or have explicit written permission to review
- Do not attempt authentication, exploitation, or password guessing against scanned hosts
- Report findings privately and give us reasonable time to fix before disclosure

## Security-Relevant Design Guarantees

SMB Sentinel is built around the following invariants. Reports that break any of these are treated as security issues, not feature requests:

1. **Read-only by default** — the scanner uses SMB negotiation messages only; it must never authenticate, write, exploit, or brute-force credentials.
2. **Private scope only** — scans are limited to private IPv4 ranges, maximum `/24`.
3. **Authorization gate** — a scan must not start until the operator confirms authorization.
4. **Offline license verification** — Ed25519 public-key verification only; the publisher private key must never ship in the application or repository.
5. **History file privacy** — `.smb-sentinel-history.json` contains internal IPs and SMB configuration details and must never be uploaded or transmitted by the tool.
