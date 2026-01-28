# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in the Vigil Guard Python SDK, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

**security@vigilguard.com**

### What to Include

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (optional)
- Your contact information for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Target**: Within 30 days for critical issues

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
2. **Investigation**: Our security team will investigate and validate the vulnerability.
3. **Resolution**: We will work on a fix and coordinate disclosure timing with you.
4. **Credit**: With your permission, we will credit you in our security advisories.

### Scope

This security policy applies to:

- The `vigil-guard` Python SDK package
- Official SDK documentation and examples
- SDK-related infrastructure (PyPI releases, GitHub Actions)

### Out of Scope

- Vigil Guard API server vulnerabilities (report to main project)
- Third-party dependencies (report to respective maintainers)
- Social engineering attacks
- Denial of service attacks against our infrastructure

## Security Best Practices

When using the Vigil Guard SDK:

1. **API Keys**: Never hardcode API keys in source code. Use environment variables.
2. **TLS Verification**: Always enable TLS verification in production (`verify=True`).
3. **Logging**: Be cautious about logging request/response data that may contain sensitive information.
4. **Dependencies**: Keep the SDK and its dependencies up to date.

## Vulnerability Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We validate and assess severity
3. We develop and test a fix
4. We release a patched version
5. We publish a security advisory (if applicable)
6. Reporter may publish details after patch release

## Security Updates

Security updates are released as patch versions (e.g., 1.0.1, 1.0.2).

Subscribe to releases on GitHub to receive notifications about security updates.
