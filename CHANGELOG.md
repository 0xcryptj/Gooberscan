# Changelog

## Unreleased

- Added modular capability playbooks with searchable discovery metadata,
  framework mappings, validation tooling, and generated catalog output.
- Added `agentsec capabilities [query]` for capability discovery.
- Added a contributor `Makefile`, CLI reference, citation metadata, code of
  conduct, and editor configuration.
- Added normalized Trivy, Semgrep, and npm-audit vulnerability/misconfiguration
  records with severity, locations, remediation, CVE/CWE metadata, deduplication,
  CSV/JSON/Markdown artifacts, and an executive report.
- Added Strix-style `scan` target orchestration, target-list files, instructions,
  diff-scope metadata, non-interactive execution, and severity-based CI gating.
- Added top-level interruption and expected I/O/runtime error handling so failed
  audits return actionable messages without an unnecessary traceback.

All notable AgentSec changes are documented here.

## 1.2.1 — 2026-08-08

- Added `agentsec --version` and `agentsec update` for CLI-driven skill maintenance.
- Added global and project-local update scopes through the `skills` CLI.

## 1.2.0 — 2026-08-08

- Added a branded one-line `install.sh` for global or project-local skill installation.
- Added explicit installation examples for Codex, Claude Code and Cursor while preserving wildcard support for all compatible agents.
- Improved the Debian/Ubuntu/WSL dependency installer with phased output, idempotent optional installs and post-install verification.
- Added CI smoke coverage for installer help and CLI executability.
- Pinned GitHub Actions to immutable commits in CI.
