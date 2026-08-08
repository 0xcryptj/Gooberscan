#!/usr/bin/env bash
set -euo pipefail

# AgentSec dependency installer for Debian / Ubuntu / WSL.
# Installs baseline deterministic tools used by AgentSec.

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RESET=$'\033[0m'
  BOLD=$'\033[1m'
  CYAN=$'\033[36m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
else
  RESET=''
  BOLD=''
  CYAN=''
  GREEN=''
  YELLOW=''
  RED=''
  DIM=''
fi

printf '%s\n' "${CYAN}${BOLD}"
cat <<'EOF'
    _                    _    ____
   / \   __ _  ___ _ __ | |_ / ___|  ___  ___
  / _ \ / _` |/ _ \ '_ \| __|\___ \ / _ \/ __|
 / ___ \ (_| |  __/ | | | |_  ___) |  __/ (__
/_/   \_\__, |\___|_| |_|\__||____/ \___|\___|
        |___/
EOF
printf '%s\n\n' "${RESET}"

if [[ ${EUID} -ne 0 ]]; then
  printf '%s\n' "${RED}✗ AgentSec setup needs administrator privileges.${RESET}"
  printf '%s\n' "  Run: ${BOLD}sudo ./install-deps.sh${RESET}"
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  printf '%s\n' "${RED}✗ This installer supports Debian, Ubuntu, and WSL systems using apt.${RESET}"
  printf '%s\n' "  AgentSec itself can still be used elsewhere; install the tools manually."
  exit 1
fi

REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6 || true)"
REAL_HOME="${REAL_HOME:-/root}"
export DEBIAN_FRONTEND=noninteractive

LOG_FILE="$(mktemp /tmp/agentsec-install.XXXXXX.log)"
trap 'rm -f -- "$LOG_FILE"' EXIT

STEP=0
TOTAL=8

step() {
  STEP=$((STEP + 1))
  printf '%s[%d/%d] %s%s\n' "${CYAN}${BOLD}" "$STEP" "$TOTAL" "$1" "$RESET"
}

ok() {
  printf '      %s✓%s %s\n' "$GREEN" "$RESET" "$1"
}

warn() {
  printf '      %s!%s %s\n' "$YELLOW" "$RESET" "$1"
}

fail() {
  printf '      %s✗%s %s\n' "$RED" "$RESET" "$1"
  printf '%s\n' "${DIM}      Last installer output:${RESET}"
  tail -n 20 "$LOG_FILE" | sed 's/^/      /'
  exit 1
}

run_required() {
  local label="$1"
  shift
  if "$@" >"$LOG_FILE" 2>&1; then
    ok "$label"
  else
    fail "$label failed"
  fi
}

run_optional() {
  local label="$1"
  shift
  if "$@" >"$LOG_FILE" 2>&1; then
    ok "$label"
  else
    warn "$label skipped; AgentSec will continue with the available tools"
  fi
}

pipx_install_or_upgrade() {
  local package="$1"
  pipx install "$package" 2>/dev/null || pipx upgrade "$package"
}

pipx_install_or_upgrade_for_user() {
  local package="$1"
  sudo -H -u "$REAL_USER" bash -c 'pipx install "$1" 2>/dev/null || pipx upgrade "$1"' -- "$package"
}

step "Preparing package sources"
run_required "Package metadata updated" apt-get update

step "Installing the defensive-tool baseline"
run_required "Core audit tools installed" apt-get install -y \
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
  clamav \
  clamav-freshclam \
  docker.io \
  ruby-full

step "Adding optional discovery tooling"
if command -v ffuf >/dev/null 2>&1; then
  ok "ffuf already available"
elif apt-get install -y ffuf >"$LOG_FILE" 2>&1; then
  ok "ffuf installed"
else
  warn "ffuf is unavailable from this apt repository; Gobuster will be used instead"
fi

if [[ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]]; then
  ok "SecLists already available"
elif apt-cache show seclists >"$LOG_FILE" 2>&1; then
  run_required "SecLists installed" apt-get install -y seclists
else
  rm -rf -- /usr/share/seclists.tmp
  run_required "SecLists downloaded" git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists.tmp
  run_required "SecLists placed" mv /usr/share/seclists.tmp /usr/share/seclists
  chmod -R a+rX /usr/share/seclists
  ok "SecLists permissions set"
fi

step "Installing isolated Python security utilities"
if [[ "$REAL_USER" != root ]]; then
  run_optional "pipx path prepared for $REAL_USER" sudo -H -u "$REAL_USER" pipx ensurepath
  run_optional "Semgrep installed for $REAL_USER" pipx_install_or_upgrade_for_user semgrep
  run_optional "pip-audit installed for $REAL_USER" pipx_install_or_upgrade_for_user pip-audit
else
  run_optional "pipx path prepared" pipx ensurepath
  run_optional "Semgrep installed" pipx_install_or_upgrade semgrep
  run_optional "pip-audit installed" pipx_install_or_upgrade pip-audit
fi

step "Enabling local security services"
run_optional "ClamAV signature updates enabled" systemctl enable --now clamav-freshclam
run_optional "Docker service enabled" systemctl enable --now docker

step "Preparing the OWASP ZAP integration"
if command -v docker >/dev/null 2>&1; then
  run_optional "OWASP ZAP image pulled" docker pull ghcr.io/zaproxy/zaproxy:stable
else
  warn "Docker is unavailable; OWASP ZAP image was not pulled"
fi

step "Making AgentSec tools executable"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/agentsec" \
  "$SCRIPT_DIR/scripts/agentsec.py" \
  "$SCRIPT_DIR/scripts/architecture_inventory.py" \
  "$SCRIPT_DIR/scripts/security_intel.py" \
  "$SCRIPT_DIR/scripts/local_server_audit.sh"
ok "CLI and audit helpers are executable"

step "Running the post-install check"
COMMANDS=(python3 pipx node npm nmap nikto gobuster sqlmap lynis clamav freshclam docker)
AVAILABLE=0
for command_name in "${COMMANDS[@]}"; do
  if command -v "$command_name" >/dev/null 2>&1; then
    AVAILABLE=$((AVAILABLE + 1))
  fi
done
ok "$AVAILABLE/${#COMMANDS[@]} baseline commands are available"

printf '\n%s%sAgentSec is ready.%s\n\n' "$GREEN" "$BOLD" "$RESET"
printf '%sNext steps%s\n' "$BOLD" "$RESET"
printf '  cd %q\n' "$SCRIPT_DIR"
printf '  ./agentsec --help\n'
printf '  ./agentsec repo .\n\n'

printf '%sSecurity note:%s Docker group membership is root-equivalent on typical hosts.\n' "$BOLD" "$RESET"
printf 'This installer intentionally does not add %s to the docker group.\n' "$REAL_USER"

if [[ ! ":${PATH}:" == *":$REAL_HOME/.local/bin:"* ]]; then
  printf '\n%sIf pipx commands are not visible yet:%s\n' "$YELLOW" "$RESET"
  printf '  export PATH="%s:$PATH"\n' "$REAL_HOME/.local/bin"
fi
