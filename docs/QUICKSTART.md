# AgentSec Quick Start

## 1. Install

Open your coding agent and paste:

```bash
npx skills add 0xcryptj/AgentSec --skill agentsec --agent '*' -g -y
```

## 2. Use it

```text
Use AgentSec to audit this project, explain the biggest security risks, and propose the simplest safe fixes.
```

That's the normal workflow.

## More examples

```text
Use AgentSec to check our dependencies for vulnerable or compromised packages.
```

```text
Use AgentSec to review authentication, authorization, least privilege and MFA.
```

```text
Use AgentSec to review this project, implement the safe high-priority fixes, and retest them.
```

## Direct CLI

You can also run the bundled tools directly:

```bash
./agentsec repo .
./agentsec server --local
./agentsec web https://staging.example.com --authorized
```

For deeper configuration and active authorized testing, see [Usage](USAGE.md) and [Getting Started](GETTING_STARTED.md).
