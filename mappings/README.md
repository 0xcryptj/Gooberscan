# AgentSec capability mappings

AgentSec uses framework mappings as navigation metadata, not as a claim that a
single automated check proves compliance. Each capability declares the standards
that help an agent choose relevant evidence and explain risk.

The current catalog covers:

- MITRE ATT&CK technique context for common attack surfaces.
- NIST CSF 2.0 functions and categories for defensive outcomes.
- OWASP ASVS, WSTG, and API Security references for application testing.

Run `python3 tools/build_skill_index.py` after changing a capability. The
generated catalog lives at `skills/index.json` and includes the current counts.
