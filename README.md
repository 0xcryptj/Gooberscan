# Gooberscan

Gooberscan is a **security scanning orchestrator** that automates common web-app recon and vulnerability checks by chaining tools like **Nmap**, **ffuf/GoBuster**, **Nikto**, **sqlmap**, **WPScan**, and **OWASP ZAP (Docker)**. It also generates organized, timestamped reports to speed up review.

> **Authorized use only.** Run this only against systems you own or have explicit permission to test.

## What it does

- Runs a repeatable scanning pipeline against a target URL/domain
- Writes outputs to `reports/<domain>-<timestamp>/`
- Adds higher-level summaries (endpoint categorization, “interesting findings”, etc.)

## Quick start

```bash
git clone https://github.com/0xcryptj/Gooberscan.git
cd Gooberscan

# first time only
chmod +x install-deps.sh gooberscan

# optional: install dependencies (Debian/Ubuntu)
sudo ./install-deps.sh

# run the scanner
./gooberscan
```

## Output

Reports are written to:

- `reports/<domain>-<timestamp>/`

That folder is intentionally **gitignored** (scan results often contain sensitive data).

## Notes / caveats

- The included installer is tailored to **Debian/Ubuntu**. Other distros will need manual dependency setup.
- Some tools require elevated privileges depending on scan type.
- If Docker is used, you may need to re-login after adding your user to the `docker` group.

## Disclaimer

This repository is provided for educational and authorized testing purposes. You are responsible for complying with laws and rules that apply to your use.
