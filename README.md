# Gooberscan

A comprehensive security scanning tool that automates multiple security testing tools including Nmap, GoBuster/ffuf, Nikto, sqlmap, WPScan, and OWASP ZAP via Docker. Features advanced exposed endpoint detection, sensitive endpoint categorization, and professional security reporting. All outputs are written to organized reports for easy analysis.

## Quick start

```bash
# clone repo
git clone https://github.com/0xcryptj/gooberscan.git
cd gooberscan

# make installer + script executable (first time)
chmod +x install-deps.sh gooberscan

# Run the script (it will offer to auto-install missing deps)
./gooberscan
```

The script will prompt for a target URL and run a sequence of scanners (Nmap, GoBuster/ffuf, Nikto, sqlmap, WPScan, OWASP ZAP via Docker). All outputs are written to reports/<domain>-<timestamp>/. If you want the installer to run ahead of time:

```bash
sudo ./install-deps.sh
```

**⚠️ Use GooberScan only on systems you own or are explicitly authorized to test.**

## Notes, caveats & security / UX considerations

- **Sudo required**: `install-deps.sh` needs `sudo` because it installs system packages and modifies groups. The script avoids installing gems as root (it installs user gems for the actual user via `su - $SUDO_USER`), which is safer.  
- **Docker group**: `install-deps.sh` adds the user to `docker` group; that change requires logout/login (or `newgrp docker`) to take effect.  
- **OS support**: This installer is tailored to Debian/Ubuntu. For other distros (Arch, Fedora) you'll need to adapt package manager commands.  
- **WPScan**: The script installs WPScan via Ruby gems into the user gem directory; Docker fallback is available in the main script if gem not present.  
- **ffuf over wfuzz**: `wfuzz` has compatibility problems with Python 3.12; `ffuf` is fast, Go-based, and simpler to install/use. GooberScan uses `ffuf` by default.  
- **Idempotency**: The installer checks and is safe to re-run; apt will skip already-installed packages.  
- **Permissions**: `install-deps.sh` writes `~/.profile` to ensure user gem path exists for interactive shells. If CI runs, you may want different behavior.

## 🚨 Advanced Security Features

### Exposed Endpoint Detection

Gooberscan now identifies **actually accessible endpoints** by analyzing HTTP response codes and provides **full URLs** for direct testing:

```bash
# Standalone exposed endpoint analysis
python3 scripts/exposed_endpoints.py reports/example.com-20250917_123456 https://example.com

# Enhanced aggregation with exposure analysis
python3 scripts/enhanced_aggregate_reports.py --reports reports/example.com-20250917_123456
```

**Categorizes endpoints by risk:**
- **🚨 CRITICAL EXPOSED**: Sensitive endpoints with 200 OK (fully accessible)
- **🟠 HIGH EXPOSED**: Sensitive endpoints with redirects/auth codes
- **🟡 MEDIUM EXPOSED**: Non-sensitive endpoints with 200 OK
- **🔒 PROTECTED**: Endpoints requiring authentication (401/403)

### Sensitive Endpoint Categorization

Automatically detects and categorizes sensitive endpoints by risk level:

- **🔴 CRITICAL**: Admin panels, login pages, database interfaces (`/admin`, `/phpmyadmin`, `/login`)
- **🟠 HIGH**: API endpoints, file uploads, configuration files (`/api`, `/upload`, `/config`)
- **🟡 MEDIUM**: Development/testing endpoints (`/test`, `/dev`, `/debug`)
- **🟢 LOW**: Demo/legacy endpoints (`/demo`, `/old`, `/archive`)

### Comprehensive Security Summary

```bash
# Generate comprehensive security analysis
python3 scripts/security_summary.py worklists/example.com-20250917_123456
```

Provides detailed analysis with:
- Risk-based recommendations
- Prioritized security findings
- Clear next steps for remediation
- Professional reporting format

## Advanced Post-Processing

Gooberscan includes advanced post-processing capabilities to extract actionable intelligence from scan results:

### Enhanced Report Aggregation

```bash
# Aggregate scan results with exposed endpoint detection
python3 scripts/enhanced_aggregate_reports.py --reports reports/example.com-20250917_123456
```

This creates organized worklists in `worklists/<domain-timestamp>/`:
- **hosts.txt**: IP addresses and open ports (from nmap)
- **urls.txt**: Discovered URLs and endpoints (from ffuf/gobuster/ZAP)
- **params.txt**: URLs with query parameters (for sqlmap/Burp testing)
- **cves.txt**: CVE numbers and vulnerability hints (from nikto/wpscan/nmap)
- **exposed_critical_exposed.txt**: Critical exposed endpoints with full URLs
- **exposed_high_exposed.txt**: High-risk exposed endpoints
- **exposed_medium_exposed.txt**: Medium-risk exposed endpoints
- **exposed_low_exposed.txt**: Low-risk exposed endpoints
- **exposed_protected_endpoints.txt**: Protected endpoints (401/403)

### ZAP Follow-up Scanning

```bash
# Run ZAP baseline scans on all discovered URLs
./zap_followup.sh worklists/example.com-20250917_123456
```

### SearchSploit Integration

```bash
# Search for exploits based on discovered CVEs and versions
./searchsploit_integration.sh worklists/example.com-20250917_123456
```

### Enhanced Pipeline with Security Analysis

```bash
# Run enhanced pipeline with exposed endpoint detection
scripts/pipeline.sh reports/example.com-20250917_123456
```

This automatically:
1. Aggregates all scan results with exposed endpoint detection
2. Displays critical findings in ASCII alert boxes
3. Fixes Docker permissions automatically
4. Generates targeted Metasploit RC (only when CVEs found)
5. Creates comprehensive security summary
6. Runs ZAP follow-up scans
7. Searches for exploits

### Docker Permission Fixes

```bash
# Automated Docker permission fixes
./fix-docker.sh
```

This script will:
- Check Docker installation and permissions
- Add user to docker group
- Start Docker service
- Install ZAP locally as backup
- Test Docker functionality

### Feature Demonstrations

```bash
# Demo all enhanced features
./demo_enhanced_features.sh

# Demo exposed endpoints feature specifically
./demo_exposed_endpoints.sh
```

## Integration with External Tools

### Burp Suite Integration
- Import `worklists/*/urls.txt` into Burp Target → Site map
- Use `worklists/*/params.txt` for Intruder/Repeater testing
- Leverage Burp Extensions for automated vulnerability scanning

### Metasploit Integration
- Use `exploit-results/*/` files to identify potential exploits
- Generated `audit/<domain>-auto.rc` files contain targeted modules (only when CVEs detected)
- Manually test exploits in msfconsole (authorized targets only)
- Example: `msfconsole -q` → `use exploit/...` → `set RHOSTS` → `exploit`

## 📁 Output Files

### Enhanced Worklist Files
- **exposed_critical_exposed.txt**: Critical exposed endpoints with full URLs (ready for testing)
- **exposed_high_exposed.txt**: High-risk exposed endpoints
- **exposed_medium_exposed.txt**: Medium-risk exposed endpoints  
- **exposed_low_exposed.txt**: Low-risk exposed endpoints
- **exposed_protected_endpoints.txt**: Protected endpoints (401/403)
- **sensitive_critical.txt**: Critical sensitive endpoints
- **sensitive_high.txt**: High-risk sensitive endpoints
- **sensitive_medium.txt**: Medium-risk sensitive endpoints
- **sensitive_low.txt**: Low-risk sensitive endpoints

### Audit Files
- **audit/<domain>-auto.rc**: Targeted Metasploit RC (only when CVEs found)
- **audit/<domain>-summary.md**: Comprehensive audit summary
- **audit/<domain>-zap/**: ZAP scan results with Docker fixes

### Configuration Files
- **burp/<domain>_config.json**: BurpSuite configuration
- **burp/<domain>_urls.txt**: URLs for BurpSuite import

## 📖 Documentation

- **SECURITY_ENHANCEMENTS.md**: Complete documentation of all new features
- **demo_enhanced_features.sh**: Comprehensive feature demonstration
- **demo_exposed_endpoints.sh**: Exposed endpoints feature demonstration

**⚠️ WARNING**: Active scanning and exploitation should only be performed on systems you own or have explicit authorization to test.
