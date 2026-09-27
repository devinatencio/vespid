# Security Policy

Vespid is a security product and we take vulnerabilities seriously. Thank you
for helping keep Vespid and its users safe.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide a description, affected component/version, reproduction steps, and
   any proof-of-concept.

If you cannot use GitHub, contact the maintainers privately and we will
coordinate a secure channel.

Please include as much of the following as possible:

- Component (`vespid` agent, `vespid-server`, or `vespid-agent`).
- Version and installation method (RPM, deb, source).
- A minimal reproduction or proof-of-concept.
- Impact assessment (for example: remote code execution, auth bypass,
  privilege escalation, denial of service).

## What to expect

- We will acknowledge your report as soon as possible.
- We will investigate and keep you informed of our progress.
- We will credit you in the release notes unless you prefer to remain
  anonymous.

## Scope

This policy covers the code in this repository. Third-party dependencies and
the operating system itself are out of scope; please report those upstream.
