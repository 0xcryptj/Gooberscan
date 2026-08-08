# Fresh Security Intelligence

AgentSec should not pretend that a static prompt can stay current forever.

Repository audits therefore combine the skill's security reasoning with security data refreshed at audit time whenever network access is available.

## What refreshes

A normal repository audit invokes:

```bash
python3 scripts/security_intel.py .
```

AgentSec currently uses several complementary sources:

- **GitHub Advisory Database malware advisories** for npm packages actually present in the repository
- **GitHub-reviewed vulnerability advisories** for those npm packages
- **ClamAV signature databases**, refreshed with `freshclam` when ClamAV is installed
- ecosystem scanners such as `npm audit`, OSV-Scanner, Trivy, Semgrep, Gitleaks, `pip-audit`, and `cargo-audit` when available

Official references:

- GitHub global security advisory API: https://docs.github.com/en/rest/security-advisories/global-advisories
- GitHub Advisory Database: https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database
- ClamAV signature management: https://docs.clamav.net/manual/Usage/SignatureManagement.html
- ClamAV supported versions / EOL policy: https://docs.clamav.net/faq/faq-eol.html

The GitHub malware feed and ClamAV solve different problems. Package advisories help identify known malicious package/version relationships. ClamAV provides file-signature detection. Neither is treated as proof that everything not flagged is safe.

## Freshness policy

The default AgentSec intelligence cache is six hours.

Fresh data is stored under:

```text
.agentsec/intel/
```

The metadata file records when the refresh occurred and which sources succeeded or failed.

If network access is unavailable or a provider fails, the audit should continue with local/cached evidence but clearly state that current intelligence could not be verified.

### Signatures and scanner engines are different

Keeping the ClamAV database current is not enough if the installed ClamAV engine itself is obsolete. A newer database can use functionality that an old engine cannot fully consume.

AgentSec should therefore surface outdated-engine warnings from ClamAV rather than claiming the malware scan is fully current just because `freshclam` downloaded a database. Keep the host's ClamAV package on a currently supported release through the normal operating-system/package-management process.

## Token efficiency

AgentSec does not load entire malware, CVE, or advisory feeds into the coding model's context.

It first inventories the repository and asks for intelligence relevant to packages and technologies that are actually present. The full machine-readable results remain on disk. The coding agent should read only the records relevant to a finding it is investigating.

This keeps context focused and reduces the chance that thousands of unrelated advisories drown out the actual application architecture.

## Malware scan

When ClamAV is installed, the root `agentsec repo` workflow refreshes signatures first and then runs a bounded scan of the repository. Results are saved to:

```text
.agentsec/intel/clamav-repo-scan.txt
```

A signature match is evidence requiring investigation. It should not be deleted automatically without understanding what file matched and why.

## Supply-chain incidents

For a package that is confirmed malicious or compromised, AgentSec should reason beyond upgrading the version.

Review:

- whether install/postinstall scripts ran
- whether the dependency executed in CI or build systems
- developer-machine exposure
- environment variables and credentials it could read
- filesystem paths it could access
- production/runtime access
- whether credential rotation or incident response is required

## Limits

"Fresh" does not mean omniscient.

New threats can exist before any vendor, advisory database, or antivirus engine knows about them. AgentSec therefore combines current feeds with source review, architecture analysis, dependency reasoning, static analysis, and deterministic testing.

The expected behavior is to state evidence and freshness honestly, not to claim a clean scan proves a system is secure.
