#!/usr/bin/env bash
set -euo pipefail

# AgentSec dependency installer for Debian / Ubuntu / WSL.
# Installs the baseline deterministic tools used by AgentSec.
# Optional cross-ecosystem scanners are installed when a clean package path exists.

if [ "${EUID}" -ne 0 ]; then
  echo "Run with sudo: sudo ./install-deps.sh"
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer currently supports Debian/Ubuntu/WSL systems using apt."
  echo "AgentSec itself can still be used elsewhere; install the tools manually."
  exit 1
fi

REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
export DEBIAN_FRONTEND=noninteractive

echo "[AgentSec] Updating package metadata..."
apt-get update

echo "[AgentSec] Installing baseline audit tools..."
apt-get install -y \
  ca-certificates \
  curl \
  wget \
  unzip \
  jq \
  git \
  build-essential \
  python3 \
  python3-venv \
  python3-pip \
  pipx \
  nodejs \
  npm \
  nmap \
  nikto \
  gobuster \
  sqlmap \
  lynis \
  docker.io \
  ruby-full

# ffuf is packaged by many current Debian/Ubuntu releases. Keep it optional so
# one missing package does not break the entire AgentSec setup.
if ! command -v ffuf >/dev/null 2>&1; then
  echo "[AgentSec] Attempting to install ffuf..."
  apt-get install -y ffuf 2>/dev/null || echo "[AgentSec] ffuf is unavailable from this apt repository; Gobuster will be used instead."
fi

# SecLists provides the conservative common web-content list used by AgentSec.
if [ ! -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
  echo "[AgentSec] Installing SecLists..."
  if apt-cache show seclists >/dev/null 2>&1; then
    apt-get install -y seclists
  else
    rm -rf /usr/share/seclists.tmp
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists.tmp
    mv /usr/share/seclists.tmp /usr/share/seclists
    chmod -R a+rX /usr/share/seclists
  fi
fi

# Install Python CLI scanners in the actual user's isolated pipx environment.
if [ "$REAL_USER" != "root" ]; then
  echo "[AgentSec] Installing isolated Python scanners for $REAL_USER..."
  sudo -H -u "$REAL_USER" pipx ensurepath >/dev/null 2>&1 || true
  sudo -H -u "$REAL_USER" pipx install semgrep 2>/dev/null || sudo -H -u "$REAL_USER" pipx upgrade semgrep 2>/dev/null || true
  sudo -H -u "$REAL_USER" pipx install pip-audit 2>/dev/null || sudo -H -u "$REAL_USER" pipx upgrade pip-audit 2>/dev/null || true
else
  pipx ensurepath >/dev/null 2>&1 || true
  pipx install semgrep 2>/dev/null || pipx upgrade semgrep 2>/dev/null || true
  pipx install pip-audit 2>/dev/null || pipx upgrade pip-audit 2>/dev/null || true
fi

# Docker is used for OWASP ZAP. Group membership is a high-privilege capability,
# so AgentSec does NOT automatically add users to the docker group.
echo "[AgentSec] Enabling Docker service when systemd is available..."
systemctl enable --now docker 2>/dev/null || true

if command -v docker >/dev/null 2>&1; then
  echo "[AgentSec] Pulling OWASP ZAP image (best effort)..."
  docker pull ghcr.io/zaproxy/zaproxy:stable 2>/dev/null || true
fi

# Make repository entry points executable when the installer is run from the repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/agentsec" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/scripts/agentsec.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/scripts/architecture_inventory.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/scripts/local_server_audit.sh" 2>/dev/null || true

cat <<EOF

AgentSec baseline installation complete.

Installed/attempted:
  - Python 3 + pipx
  - Node.js + npm
  - Nmap
  - Nikto
  - Gobuster / ffuf when packaged
  - sqlmap
  - Lynis
  - Docker + OWASP ZAP image
  - Semgrep (pipx)
  - pip-audit (pipx)
  - SecLists

Optional tools AgentSec can also consume if you install them:
  - OSV-Scanner
  - Trivy
  - Gitleaks
  - cargo-audit

Security note:
  Docker group membership is effectively root-equivalent on typical Docker hosts.
  This installer intentionally does not add $REAL_USER to the docker group.

Test AgentSec:
  cd "$SCRIPT_DIR"
  ./agentsec --help
  ./agentsec repo .

If pipx-installed commands are not visible yet, start a new shell or add:
  $REAL_HOME/.local/bin

to your PATH.
EOF
