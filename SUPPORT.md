# Support

Thanks for using **SMB Sentinel**! Here's how to get help.

## Documentation

Start with:

- [README.md](README.md) — installation, GUI usage, scan checks, history, exports, licensing, and responsible-use guidance
- [SECURITY.md](SECURITY.md) — responsible-disclosure policy for vulnerabilities in the tool itself
- `CONTRIBUTING.md` — contribution workflow *(if present in the repository)*

## Questions and Discussions

For usage questions, ideas, and general discussion, please use [GitHub Discussions](https://github.com/mrcyberharsh/smb-sentinel/discussions) (if enabled) or open a GitHub issue using the appropriate template.

## Bug Reports

Open an issue using the **Bug report** template and include:

- OS and Python version
- SMB Sentinel version/commit
- How you launched the app (`python main.py`, GUI, or built executable)
- The private CIDR you scanned (sanitized — do not paste real internal IPs, hostnames, or share names)
- Expected behavior vs actual behavior
- Sanitized logs or error output
- Whether you are on the free or premium/licensed path, and whether license verification succeeded

Please sanitize logs, screenshots, CSV/PDF exports, and any `.smb-sentinel-history.json` snippets before posting. Remove internal IP addresses, hostnames, share names, and SMB configuration details.

## Feature Requests

Open an issue using the **Feature request** template and describe:

- The SMB configuration review use case
- Why existing checks are insufficient
- Whether the feature stays read-only and within the private `/24` scope
- Safety and authorization implications
- Proposed test plan

> Requests for authentication, credential guessing, relay attacks, exploitation, or write operations against SMB hosts are out of scope and will be closed.

## Security Issues

Do **not** open a public issue for vulnerabilities in SMB Sentinel itself. Report privately:

- **Maintainer / Developer:** Harsh Saini — cyber.h4rsh@zohomail.in
- **Manager:** Prachi Sharma — manager.prachi@zohomail.in

See [SECURITY.md](SECURITY.md) for the full responsible-disclosure policy, supported versions, and out-of-scope items.

## Licensing Support

For premium license activation issues:

- Confirm `PUBLIC_KEY_B64` in `license_manager.py` is populated with the publisher's current public key.
- Confirm the license string was issued after the current key pair was set up (key rotation invalidates older licenses).
- Do **not** paste full license strings, private keys, or publisher key material in public issues.

For licensing or commercial queries, contact the manager:

- **Manager:** Prachi Sharma — manager.prachi@zohomail.in

## Project and Collaboration Queries

For partnership, collaboration, or organizational queries:

- **Manager:** Prachi Sharma — manager.prachi@zohomail.in
- **Organization:** MR Cyber Pulse

## Response Expectations

This is a community-maintained project. Response times vary, but security reports are prioritized. Please be patient and avoid pinging maintainers on multiple channels for the same issue.
