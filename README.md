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
