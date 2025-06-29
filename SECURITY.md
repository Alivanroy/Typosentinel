# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of TypoSentinel seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT report security vulnerabilities through public GitHub issues.

Instead, please report them via email to: **security@typosentinel.dev**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include in Your Report

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

* Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
* Full paths of source file(s) related to the manifestation of the issue
* The location of the affected source code (tag/branch/commit or direct URL)
* Any special configuration required to reproduce the issue
* Step-by-step instructions to reproduce the issue
* Proof-of-concept or exploit code (if possible)
* Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

### Preferred Languages

We prefer all communications to be in English.

## Security Update Process

1. **Report received**: We acknowledge receipt of your vulnerability report
2. **Initial assessment**: We perform an initial assessment of the report
3. **Verification**: We work to verify and reproduce the vulnerability
4. **Impact assessment**: We assess the impact and severity of the vulnerability
5. **Fix development**: We develop and test a fix for the vulnerability
6. **Coordinated disclosure**: We coordinate the disclosure timeline with the reporter
7. **Release**: We release the security update
8. **Public disclosure**: We publicly disclose the vulnerability details

## Security Best Practices for Users

### General Security

- Always use the latest version of TypoSentinel
- Regularly update your dependencies
- Use TypoSentinel in a secure environment
- Follow the principle of least privilege

### Configuration Security

- Protect configuration files containing sensitive information
- Use environment variables for sensitive configuration
- Regularly rotate API keys and tokens
- Enable logging and monitoring

### Network Security

- Use HTTPS when possible
- Implement proper firewall rules
- Monitor network traffic for anomalies
- Use VPNs for remote access

## Known Security Considerations

### Package Repository Access

- TypoSentinel makes requests to public package repositories
- Network traffic may reveal which packages you're checking
- Consider using a proxy or VPN if privacy is a concern

### Local File Access

- TypoSentinel reads local files to analyze dependencies
- Ensure proper file permissions on sensitive directories
- Run TypoSentinel with minimal required privileges

### Data Handling

- TypoSentinel processes package names and versions
- No sensitive data should be included in package names
- Consider the privacy implications of logging package information

## Security Features

### Input Validation

- All user inputs are validated and sanitized
- Package names are checked against known patterns
- File paths are validated to prevent directory traversal

### Error Handling

- Errors are handled gracefully without exposing sensitive information
- Stack traces are not exposed in production builds
- Logging is configurable to avoid sensitive data exposure

### Dependencies

- We regularly audit our dependencies for vulnerabilities
- Dependencies are kept up to date
- We use tools like `go mod audit` to check for known vulnerabilities

## Vulnerability Disclosure Timeline

We aim to follow this timeline for vulnerability disclosure:

- **Day 0**: Vulnerability report received
- **Day 1-2**: Initial acknowledgment and assessment
- **Day 3-7**: Verification and impact assessment
- **Day 8-30**: Fix development and testing
- **Day 31-45**: Coordinated disclosure preparation
- **Day 46+**: Public disclosure (after fix is released)

This timeline may vary depending on the complexity and severity of the vulnerability.

## Security Hall of Fame

We maintain a list of security researchers who have responsibly disclosed vulnerabilities to us:

<!-- This section will be updated as we receive and address security reports -->

*No security vulnerabilities have been reported yet.*

## Contact

For any questions about this security policy, please contact us at:

- Email: **[INSERT SECURITY EMAIL]**
- GitHub: Create an issue with the "security" label (for non-sensitive security questions only)

## Legal

We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and disruptions to others
- Only interact with accounts you own or with explicit permission of the account holder
- Do not access, modify, or delete data belonging to others
- Contact us first before disclosing the vulnerability publicly
- Give us reasonable time to address the vulnerability before any disclosure

We reserve the right to modify this policy at any time.