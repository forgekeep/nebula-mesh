# Architecture Decision Records

| ID | Title | Status |
|---|---|---|
| [0001](0001-ca-key-storage.md) | CA key storage: file-system vs database | Superseded by [0002](0002-per-operator-cas.md) |
| [0002](0002-per-operator-cas.md) | Per-operator CAs with in-DB encrypted storage | Accepted |
| [0003](0003-ca-encryption-model.md) | CA key encryption model (operator-derived KEK vs status quo) | Accepted |
| [0004](0004-agent-authorization.md) | Agent authorization model (token TTL, PoP, rotation, revocation) | Accepted |
| [0005](0005-pre-auth-keys.md) | Pre-auth keys (reusable, ephemeral, tag-bound enrollment tokens) | Accepted, implementation deferred |
| [0006](0006-multi-address-overlay.md) | Multiple overlay addresses per network and per host | Accepted |
| [0007](0007-remove-legacy-ca-stack.md) | Remove legacy on-disk CA stack | Accepted |
| [0008](0008-ca-rotation.md) | Hybrid CA rotation | Accepted |
| [0009](0009-scale-and-fuzz-testing.md) | Scale, concurrency, and fuzz testing | Proposed |
