#!/usr/bin/env bash
set -euo pipefail

# Simple idempotent installer for Ubuntu/Debian environments.
# RUN THIS WITH SUDO: sudo ./install-deps.sh
# It will:
# - apt install system packages
# - install pipx & ffuf & seclists
# - create a Python venv at ~/secenv for optional Python tools
# - configure gem to install user gems (wpScan)
# - pull Docker images for ZAP and WPScan (optional)
#
# Notes:
# - Run on Ubuntu/Debian systems. On other distros adjust package manager lines.
# - You will be added to docker group (log out/in to apply).

# ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run with sudo: sudo $0"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "Updating apt..."
apt update -y

echo "Installing core packages..."
apt install -y \
  build-essential \
  curl \
  wget \
  unzip \
  jq \
  git \
  python3 \
  python3-venv \
  python3-pip \
  nmap \
  nikto \
  gobuster \
  dirb \
  sqlmap \
  lynis \
  ruby-full \
  libcurl4-openssl-dev \
  openjdk-17-jre-headless \
  docker.io

# Install ffuf (Go-based web fuzzer)
echo "Installing ffuf..."
if ! command -v ffuf >/dev/null 2>&1; then
  FFUF_VERSION="2.1.0"
  wget -O /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"
  tar -xzf /tmp/ffuf.tar.gz -C /tmp/
  mv /tmp/ffuf /usr/local/bin/
  chmod +x /usr/local/bin/ffuf
  rm /tmp/ffuf.tar.gz
fi

# Install SecLists
echo "Installing SecLists..."
if [ ! -d "/usr/share/seclists" ]; then
  git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
  chmod -R 755 /usr/share/seclists
fi

# Ensure docker service running
systemctl enable --now docker || true

# add current user to docker group (note: needs logout/login)
if [ -n "${SUDO_USER:-}" ]; then
  usermod -aG docker "$SUDO_USER" || true
fi

# pipx (preferred for Python CLI tools)
echo "Installing pipx and ensuring path..."
# Install pipx via apt to avoid externally-managed environment issues
apt install -y pipx
python3 -m pipx ensurepath

# create Python venv for optional Python tools and common libs
VENV_DIR="/home/${SUDO_USER:-root}/secenv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python venv at $VENV_DIR..."
  sudo -u "${SUDO_USER:-root}" python3 -m venv "$VENV_DIR"
  sudo -u "${SUDO_USER:-root}" "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
fi

# Ruby gem: install WPScan into user's gem home (avoid sudo gem)
echo "Configuring user gem directory for ${SUDO_USER:-root}..."
USER_HOME=$(eval echo "~${SUDO_USER:-root}")
GEM_HOME="${USER_HOME}/.gem"
mkdir -p "$GEM_HOME"
chown -R "${SUDO_USER:-root}":"${SUDO_USER:-root}" "$GEM_HOME"
# Write into the user's shell profile so gem binaries are in PATH for interactive shells
PROFILE_FILE="${USER_HOME}/.profile"
grep -q 'GEM_HOME' "$PROFILE_FILE" 2>/dev/null || cat >> "$PROFILE_FILE" <<'EOF'

# Ruby gems installed to user gem dir
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
EOF

# Install wpscan (user gem) as the non-root user
echo "Installing WPScan (user gem) — this may take a moment..."
# Use su to run gem install as the non-root user if available
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  su - "${SUDO_USER}" -c "gem install wpscan --no-document" || echo "Warning: gem install wpscan failed for ${SUDO_USER}"
else
  gem install wpscan --no-document || echo "Warning: gem install wpscan failed (if running in container, consider running as real user)"
fi

# Docker images for ZAP and WPScan (speeds up first run)
echo "Pulling Docker images (owasp/zap2docker-stable, wpscanteam/wpscan)..."
docker pull owasp/zap2docker-stable:latest || true
docker pull wpscanteam/wpscan || true

echo "Installation finished."
echo "If you were not previously in the docker group, log out and back in to use docker without sudo."
echo "Python venv available at $VENV_DIR (activate with: source $VENV_DIR/bin/activate)"
echo "If wpscan command is not found in a new shell, ensure ~/.gem/bin is in your PATH (restart shell)."
