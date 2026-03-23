# Security Policy

## Reporting a Vulnerability

If you discover a security issue in ProxQL, please report it responsibly.

**Email**: baron2yan@gmail.com

Please include:
- Description of the issue
- Steps to reproduce (ideally a SQL query that bypasses validation when it shouldn't)
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for confirmed issues.

**Please do not open a public GitHub issue for security reports.**

## Scope

ProxQL is a validation guardrail, not a complete security solution. It is designed to catch common issues and reduce risk, but it:

- Validates query **structure**, not query **results**
- Cannot prevent all possible adversarial queries
- Is not a replacement for proper database permissions and read-only credentials
- Should be used as one layer in a defense-in-depth strategy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Rules

ProxQL includes built-in detection for common patterns including file access attempts, dynamic SQL, obfuscated keywords, and privilege escalation. See the [README](README.md) for the full list of security rules and their severity levels.

If you find a pattern that should be detected but isn't, please report it — either as a security report (if the bypass is dangerous) or as a regular GitHub issue (if it's a new detection you'd like to see added).
