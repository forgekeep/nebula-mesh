# Security Policy

## Supported versions

nebula-mesh is pre-1.0 and ships from `main`. Security fixes target the latest tagged release; older tags are not patched.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting:
[https://github.com/forgekeep/nebula-mesh/security/advisories/new](https://github.com/forgekeep/nebula-mesh/security/advisories/new)

Include:
- a description of the issue and its impact,
- minimal reproduction steps or a PoC,
- affected versions / commit SHA.

You should get an acknowledgement within 72 hours. A fix and coordinated disclosure timeline will follow based on severity.

## Scope

In scope:
- `nebula-mgmt` server (API, web UI, PKI, store)
- `nebula-agent` (enroll, poll, file writes)
- default configuration shipped in `configs/`

Out of scope:
- upstream `slackhq/nebula` issues (report those upstream)
- misconfiguration in deployments not following the README (e.g. running without TLS in production)
- denial-of-service via legitimate API use behind authentication

## Threat model

The assets, entry points, STRIDE analysis, mitigations, and accepted residual
risks are documented in [docs/security/threat-model.md](docs/security/threat-model.md).

## Hardening guidance

See the "Security notes" section of [README.md](README.md) and the [deployment notes](deploy/) for the baseline we recommend.
