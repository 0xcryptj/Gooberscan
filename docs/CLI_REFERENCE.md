# AgentSec CLI reference

The CLI is intentionally usable without optional scanners. Missing tools are
recorded as skipped evidence rather than treated as vulnerabilities.

## Commands

| Command | Purpose |
| --- | --- |
| `agentsec capabilities [query]` | List or search modular AgentSec playbooks |
| `agentsec repo [path]` | Review source, dependencies, secrets, and deployment configuration |
| `agentsec web <url>` | Run a passive or authorized web application audit |
| `agentsec api <spec>` | Inventory an OpenAPI/Swagger contract and optionally probe it safely |
| `agentsec server --local` | Review local Linux hardening evidence |
| `agentsec server --target <host> --authorized` | Review authorized external server exposure |
| `agentsec scan` | Audit multiple local repositories or authorized web targets |
| `agentsec view` | Open the private local report viewer |
| `agentsec update` | Update the installed AgentSec skill |

## Safe defaults

Remote targets require `--authorized`. Active web validation additionally
requires `--active`; it is never implied by a URL. Baseline-only mode is useful
for low-impact first-pass checks:

```bash
./agentsec web https://example.com --authorized --baseline-only
```

Do not use AgentSec against systems you do not own or have written permission
to assess.

## Repository profiles

```bash
./agentsec repo . --scan-mode quick
./agentsec repo . --scan-mode standard
./agentsec repo . --scan-mode deep
```

`quick` emphasizes architecture, sensitive artifacts, and package evidence.
`standard` adds available SCA, SAST, and secret scanners. `deep` also requests
license analysis from supported scanners.

## Report output

Each run is saved under `.agentsec/reports/<run>/` and may include:

- `summary.md` and `summary.json` — human and machine summaries
- `findings.json` and `findings.sarif` — normalized review queue
- `run.json`, `events.jsonl`, and `agents.json` — execution trace
- raw scanner output — preserved evidence for correlation

Scanner output is evidence, not a verdict. Confirm findings against source,
configuration, runtime behavior, and the relevant trust boundary.
