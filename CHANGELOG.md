# Changelog

All notable AgentSec changes are documented here.

## Unreleased

- Added a branded one-line `install.sh` for global or project-local skill installation.
- Added explicit installation examples for Codex, Claude Code and Cursor while preserving wildcard support for all compatible agents.
- Improved the Debian/Ubuntu/WSL dependency installer with phased output, idempotent optional installs and post-install verification.
- Added CI smoke coverage for installer help and CLI executability.
- Pinned GitHub Actions to immutable commits in CI.
