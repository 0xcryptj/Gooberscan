# Security Standards and Tooling

AgentSec is standards-led and tool-assisted.

The security standard defines what good looks like. A scanner or vendor product provides evidence. Do not let one product's finding taxonomy become AgentSec's threat model.

## Primary application-security baseline

### OWASP ASVS 5.0.0

Use the OWASP Application Security Verification Standard as the primary requirements baseline for application controls.

ASVS is useful for reviewing requirements around validation, authentication, session management, authorization, cryptography, data protection, communications, APIs, configuration, logging, files, and other application controls.

When a finding maps cleanly to ASVS, include the versioned requirement identifier when practical.

Official project:
https://owasp.org/www-project-application-security-verification-standard/

### OWASP Top 10:2025

Use the OWASP Top 10 as a high-level risk taxonomy and communication layer, not as a complete audit checklist.

The 2025 categories include broken access control, security misconfiguration, software supply-chain failures, cryptographic failures, injection, insecure design, authentication failures, software/data integrity failures, logging and alerting failures, and mishandling of exceptional conditions.

Official project:
https://owasp.org/Top10/

### OWASP Web Security Testing Guide

Use the WSTG to structure web testing methodology. Prefer the stable release for repeatable reporting and consult the latest material for newly added testing guidance.

Relevant areas include attack-surface mapping, configuration testing, identity, authentication, authorization, sessions, input validation, error handling, cryptography, business logic, client-side behavior, APIs, and deployment configuration.

Official project:
https://owasp.org/www-project-web-security-testing-guide/

## Weakness classification

### CWE

Map confirmed implementation weaknesses to CWE when a useful match exists. CWE identifiers make findings easier to correlate across scanners and engineering systems.

Do not force a CWE mapping when the issue is primarily architectural, operational, or provider-specific.

Official project:
https://cwe.mitre.org/

## Infrastructure hardening

### CIS Benchmarks

For servers, operating systems, containers, databases, cloud platforms, web servers, and other supported technologies, use the relevant CIS Benchmark as a hardening reference when available.

Do not blindly apply every benchmark setting. Respect workload requirements and AgentSec's KISS principle. Prefer controls that materially reduce risk without making the service brittle or unusable.

Official project:
https://www.cisecurity.org/cis-benchmarks

## Secure development lifecycle

### NIST SSDF

Use NIST SP 800-218 Secure Software Development Framework as a high-level SDLC reference for protecting software, producing well-secured software, responding to vulnerabilities, and reducing recurrence.

AgentSec should use SSDF concepts when reviewing CI/CD, dependency governance, release practices, vulnerability response, provenance, and organizational development controls.

Official publication:
https://csrc.nist.gov/pubs/sp/800/218/final

## Tool interoperability

Tools are evidence sources. AgentSec should normalize their results into its own finding model:

- confirmed vulnerability
- security design gap
- security opportunity
- review needed

Never duplicate the same root cause simply because several scanners reported it.

### Burp Suite / Burp Scanner

Burp is a DAST and manual web-testing evidence source. AgentSec may consume Burp findings or use Burp during explicitly authorized web assessment.

Useful evidence includes:

- crawl and application-map coverage
- request/response behavior
- authentication/session observations
- injection findings
- XSS, SSRF, traversal, request smuggling, and related web findings
- manual validation notes

Active Burp scanning remains subject to AgentSec's authorization and scope rules.

Official documentation:
https://portswigger.net/burp/documentation/scanner

### SonarQube

SonarQube is a static-analysis evidence source. AgentSec should distinguish between confirmed security vulnerabilities and Security Hotspots that require review.

Useful evidence includes:

- injection and taint-flow findings
- security configuration rules
- security hotspots
- code-quality issues that materially affect security or maintainability

Do not automatically treat every hotspot as a vulnerability. Review the data flow and actual application context.

Official documentation:
https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules

### Snyk

Snyk can provide SCA, dependency, vulnerability, license, and code-analysis evidence depending on the products available to the user.

Useful evidence includes:

- direct and transitive dependency paths
- vulnerable package versions
- fix/upgrade advice
- Snyk Code findings
- supply-chain and package-risk context

AgentSec should still verify that a recommended dependency upgrade is compatible and should never use a force-upgrade strategy blindly.

Official documentation:
https://docs.snyk.io/scan-with-snyk/snyk-open-source

## Correlation rules

When multiple sources find related issues:

1. normalize them to one root cause
2. preserve the original evidence/source names
3. map to OWASP/CWE/ASVS where useful
4. assess exploitability and affected trust boundary in the actual architecture
5. propose the smallest safe root-cause fix
6. retest with the most relevant deterministic tool

Example:

- SonarQube reports a SQL injection flow
- Snyk Code reports the same sink
- Burp confirms exploitability in an authorized staging environment

AgentSec should report one SQL injection vulnerability with correlated evidence, not three unrelated findings.

## KISS still wins

Standards and scanners are guidance, not a contest to enable the most controls.

If a simple server-side authorization check, least-privilege database role, dependency upgrade, or safe framework API fixes the root problem, prefer that over an elaborate custom security subsystem.
