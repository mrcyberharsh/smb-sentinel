# Code of Conduct

## Our Pledge

We as members, contributors, and maintainers pledge to make participation in the SMB Sentinel community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming, diverse, inclusive, and healthy community.

Because SMB Sentinel is a **read-only defensive SMB configuration review tool**, we also pledge to keep the community focused on **authorized, ethical, non-destructive use** of the software.

## Our Standards

Examples of behavior that contribute to a positive environment:

- Demonstrating empathy and kindness toward other people
- Being respectful of differing opinions, viewpoints, and experiences
- Giving and gracefully accepting constructive feedback
- Accepting responsibility and apologizing to those affected by our mistakes, and learning from the experience
- Focusing on what is best for the overall community
- Following the project's responsible-use boundaries described in the README
- Sanitizing logs, reports, and history files before sharing them publicly

Examples of unacceptable behavior:

- The use of sexualized language or imagery, and sexual attention or advances of any kind
- Trolling, insulting or derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Sharing real scan outputs, `.smb-sentinel-history.json` contents, internal IP addresses, hostnames, share names, or SMB configuration details in public issues or pull requests
- Posting content that encourages or facilitates unauthorized SMB access, credential guessing, relay attacks, or disruption of file-sharing services
- Submitting contributions that add authentication attempts, exploitation, password guessing, or write operations to the scanner
- Submitting contributions that bypass the private-range or `/24` scope limit, the authorization gate, or the Ed25519 license verification
- Other conduct which could reasonably be considered inappropriate in a professional setting

## Scope

This Code of Conduct applies within all community spaces, including:

- GitHub issues, pull requests, discussions, and code review comments
- Project documentation and commit messages
- Any chat, forum, or mailing list associated with the project
- Public spaces when an individual is officially representing the project

It also applies when an individual is representing the project in public spaces, for example by using an official project email address, posting via an official social media account, or acting as an appointed representative at an online or offline event.

## Enforcement Responsibilities

Project maintainers are responsible for clarifying and enforcing our standards of acceptable behavior and will take appropriate and fair corrective action in response to any behavior that they deem inappropriate, threatening, offensive, or harmful.

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits, code, issues, and other contributions that are not aligned with this Code of Conduct, and will communicate reasons for moderation decisions when appropriate.

## Reporting

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported privately to the project maintainer:

- **Maintainer / Developer:** Harsh Saini — cyber.h4rsh@zohomail.in
- **Manager:** Prachi Sharma — manager.prachi@zohomail.in
- **Organization:** MR Cyber Pulse

All complaints will be reviewed and investigated promptly and fairly.

All project maintainers are obligated to respect the privacy and security of the reporter of any incident.

Do **not** report Code of Conduct violations through public GitHub issues. Use one of the private email channels above.

## Enforcement Guidelines

Project maintainers will follow these Community Impact Guidelines in determining the consequences for any action they deem in violation of this Code of Conduct.

### 1. Correction

**Community Impact**: Use of inappropriate language or other behavior deemed unprofessional or unwelcome in the community.

**Consequence**: A private, written warning from the maintainer, providing clarity around the nature of the violation and an explanation of why the behavior was inappropriate. A public apology may be requested.

### 2. Warning

**Community Impact**: A violation through a single incident or series of actions.

**Consequence**: A warning with consequences for continued behavior. No interaction with the people involved, including unsolicited interaction with those enforcing the Code of Conduct, for a specified period of time. Violating these terms may lead to a temporary or permanent ban.

### 3. Temporary Ban

**Community Impact**: A serious violation of community standards, including sustained inappropriate behavior, or sharing sensitive SMB scan data or offensive-security content after a warning.

**Consequence**: A temporary ban from any sort of interaction or public communication with the community for a specified period of time. Violating these terms may lead to a permanent ban.

### 4. Permanent Ban

**Community Impact**: Demonstrating a pattern of violation of community standards, including sustained inappropriate behavior, harassment of an individual, or repeatedly sharing sensitive SMB scan data or offensive-security content.

**Consequence**: A permanent ban from any sort of public interaction within the community.

## Security-Specific Rules

In addition to the standards above, the SMB Sentinel community expects the following:

1. **Authorized use only.** Do not use the tool to scan SMB services on devices you do not own or have explicit permission to review.
2. **Read-only remains non-negotiable.** Issues and PRs requesting authentication, credential guessing, relay attacks, exploitation, or write operations against SMB hosts will be closed.
3. **Scope limits stay.** PRs that weaken the private-range restriction, the `/24` maximum, or the authorization confirmation will be rejected.
4. **Licensing integrity stays.** PRs that weaken Ed25519 license verification, reintroduce a shipped secret, or expose the publisher private key will be rejected.
5. **Sanitize before sharing.** Redact internal IPs, hostnames, share names, SMB configuration details, and `.smb-sentinel-history.json` contents from logs, reports, screenshots, and issues.
6. **Report vulnerabilities in SMB Sentinel privately.** Do not open public issues for security flaws in the tool itself. See [SECURITY.md](SECURITY.md).
7. **Respect the defensive scope.** Contributions must keep the tool non-destructive and preserve its authorization safeguards.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org), version 2.1, available at [https://www.contributor-covenant.org/version/2/1/code_of_conduct.html](https://www.contributor-covenant.org/version/2/1/code_of_conduct.html).

Community Impact Guidelines were inspired by [Mozilla's code of conduct enforcement ladder](https://github.com/mozilla/inclusion).

For answers to common questions about this code of conduct, see the FAQ at [https://www.contributor-covenant.org/faq](https://www.contributor-covenant.org/faq).
