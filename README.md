# Gooberscan

A comprehensive security scanning tool that automates multiple security testing tools including Nmap, GoBuster/ffuf, Nikto, sqlmap, WPScan, and OWASP ZAP via Docker. All outputs are written to organized reports for easy analysis.

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

## Advanced Post-Processing

Gooberscan includes advanced post-processing capabilities to extract actionable intelligence from scan results:

### Automated Report Aggregation

```bash
# Aggregate scan results into organized worklists
python3 aggregate_reports.py --reports reports/example.com-20250917_123456
```

This creates organized worklists in `worklists/<domain-timestamp>/`:
- **hosts.txt**: IP addresses and open ports (from nmap)
- **urls.txt**: Discovered URLs and endpoints (from ffuf/gobuster/ZAP)
- **params.txt**: URLs with query parameters (for sqlmap/Burp testing)
- **cves.txt**: CVE numbers and vulnerability hints (from nikto/wpscan/nmap)

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

### End-to-End Automation

```bash
# Run complete post-processing pipeline
./gooberscan_advanced.sh
```

This automatically:
1. Aggregates all scan results
2. Runs ZAP follow-up scans
3. Searches for exploits
4. Generates comprehensive summary

## Integration with External Tools

### Burp Suite Integration
- Import `worklists/*/urls.txt` into Burp Target → Site map
- Use `worklists/*/params.txt` for Intruder/Repeater testing
- Leverage Burp Extensions for automated vulnerability scanning

### Metasploit Integration
- Use `exploit-results/*/` files to identify potential exploits
- Manually test exploits in msfconsole (authorized targets only)
- Example: `msfconsole -q` → `use exploit/...` → `set RHOSTS` → `exploit`

**⚠️ WARNING**: Active scanning and exploitation should only be performed on systems you own or have explicit authorization to test.
