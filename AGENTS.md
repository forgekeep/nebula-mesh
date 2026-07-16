# Repository Agent Rules

## Security invariants

- Before changing authentication, authorization, secret ingress, cryptography,
  persistence, audit logging, or a public endpoint, read
  `docs/security/invariants.md` and preserve every applicable invariant.
- A change that affects an invariant must add or update a negative regression
  test. Reference the invariant ID in the test name or its adjacent comment.
- Update the invariant document when its rule, scope, exception, or code/test
  anchors change. Do not create branch-specific security review reports in the
  repository unless the user explicitly requests a persistent report.
- Treat `docs/security/threat-model.md` as the architecture and residual-risk
  baseline. Treat `docs/security/invariants.md` as the normative implementation
  contract.

