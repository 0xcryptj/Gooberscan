#!/usr/bin/env bash
set -euo pipefail

RESET=''
BOLD=''
CYAN=''
GREEN=''
YELLOW=''
RED=''
DIM=''
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RESET=$'\033[0m'
  BOLD=$'\033[1m'
  CYAN=$'\033[36m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
fi

USER_HOME="$(getent passwd "$(id -u)" | cut -d: -f6 || true)"
USER_HOME="${USER_HOME:-/tmp}"
AGENT="*"
GLOBAL=true

usage() {
  cat <<EOF
AgentSec installer

Usage:
  ./install.sh                 Install globally for all supported agents
  ./install.sh --agent codex   Install globally for one agent
  ./install.sh --local         Install only in the current project

Options:
  --agent NAME   Target one agent (default: all supported agents)
  --local        Install in the current project instead of globally
  --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      [[ $# -ge 2 ]] || { printf '%s\n' "${RED}✗ --agent requires a value${RESET}" >&2; exit 2; }
      AGENT="$2"
      shift 2
      ;;
    --local)
      GLOBAL=false
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf '%s\n' "${RED}✗ Unknown option: $1${RESET}" >&2
      usage >&2
      exit 2
      ;;
  esac
done

printf '%s\n' "${CYAN}${BOLD}"
cat <<'EOF'
     _                    _    ____
    / \   __ _  ___ _ __ | |_ / ___|  ___  ___
   / _ \ / _` |/ _ \ '_ \| __|\___ \ / _ \/ __|
  / ___ \ (_| |  __/ | | | |_  ___) |  __/ (__
 /_/   \_\__, |\___|_| |_|\__||____/ \___|\___|
         |___/
EOF
printf '%s\n' "${RESET}"
printf '%sDefensive security for AI-built software.%s\n\n' "$BOLD" "$RESET"

if ! command -v npx >/dev/null 2>&1; then
  printf '%s\n' "${RED}✗ Node.js and npm are required, but npx was not found.${RESET}"
  printf '%s\n' "  Install Node.js, then run this installer again."
  exit 1
fi

if [[ "$GLOBAL" == true ]]; then
  SCOPE="global"
  DESTINATION="$USER_HOME/.agents/skills/agentsec"
else
  SCOPE="project-local"
  DESTINATION="./.agents/skills/agentsec"
fi

printf '%s  ◇ Checking prerequisites%s\n' "$CYAN" "$RESET"
printf '%s  ✓ npx is available%s\n' "$GREEN" "$RESET"
printf '%s  ◇ Installing AgentSec (%s, %s)%s\n' "$CYAN" "$SCOPE" "agent: $AGENT" "$RESET"

INSTALL_ARGS=(skills add 0xcryptj/AgentSec --skill agentsec --agent "$AGENT" -y)
if [[ "$GLOBAL" == true ]]; then
  INSTALL_ARGS+=(-g)
fi

if ! npx --yes "${INSTALL_ARGS[@]}"; then
  printf '%s\n' "${RED}✗ AgentSec installation failed.${RESET}"
  printf '%s\n' "  Re-run with the direct command from the README for diagnostic output."
  exit 1
fi

if [[ "$GLOBAL" == true && -f "$DESTINATION/SKILL.md" ]]; then
  printf '%s  ✓ AgentSec skill is installed at %s%s\n' "$GREEN" "$DESTINATION" "$RESET"
else
  printf '%s  ✓ Installation command completed%s\n' "$GREEN" "$RESET"
  printf "%s    Verify the skill from your agent's installed-skill list.%s\n" "$DIM" "$RESET"
fi

printf '\n%s%sAgentSec is ready.%s\n' "$GREEN" "$BOLD" "$RESET"
printf 'Ask your coding agent:\n\n'
printf '  %sUse AgentSec to audit this project and propose the simplest safe fixes.%s\n\n' "$BOLD" "$RESET"
printf "%sReview the skill before use; it runs with the permissions granted to your coding agent.%s\n" "$DIM" "$RESET"
