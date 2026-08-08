## Summary

Describe the change and the security/developer problem it solves.

## Security rationale

Explain why the change improves security, correctness, portability, evidence quality, or false-positive behavior.

## Type of change

- [ ] Security reasoning / reference update
- [ ] Deterministic scanner or CLI change
- [ ] Architecture detection
- [ ] Remediation behavior
- [ ] Documentation
- [ ] Tests / CI
- [ ] Bug fix

## Validation

List the checks you ran.

- [ ] Python syntax
- [ ] Shell syntax
- [ ] Unit tests
- [ ] CLI smoke test
- [ ] Agent Skills validation
- [ ] Relevant security check rerun

## False-positive / safety review

Describe possible false positives, external configuration assumptions, or safety implications.

## Screenshots / sample output

Add screenshots or sanitized output when the user-facing behavior changes.

## Checklist

- [ ] I did not weaken authorization gates for remote active testing.
- [ ] I preserved raw evidence where relevant.
- [ ] I documented meaningful new behavior.
- [ ] I added or updated tests when logic changed.
- [ ] I did not add destructive exploitation, credential attacks, persistence, data exfiltration or denial-of-service workflows.
