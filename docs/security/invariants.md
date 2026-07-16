# Security invariants

This document defines security properties that every implementation must
preserve. The threat model describes assets, boundaries, attacks, and residual
risks. These invariants define merge-blocking implementation rules.

Each invariant has a stable ID. Code changes that touch its scope must include
a negative regression test referencing that ID. Static analysis and review
support the test; they do not replace it.

## SEC-SECRET-001: mutable cryptographic secret ingress

### Rule

Application code must keep explicitly destructible cryptographic material —
private keys, key-decryption passphrases, seeds, and equivalent plaintext — out
of immutable or unbounded representations. Authentication tokens and ordinary
login passwords require separate lifecycle invariants; this rule does not claim
that the current HTTP authentication stack can zeroize them.

For server and CLI ingress:

- Reject disallowed transport, authentication, and authorization before
  reading a secret-bearing body.
- Do not put plaintext secrets in JSON fields, URLs, command-line arguments,
  Go `string` values, logs, audit records, or error messages.
- Read secrets through globally bounded bodies and per-field limits into
  application-owned `[]byte` buffers. Reject missing, duplicate, unknown,
  malformed, and oversized input.
- Do not use `ParseForm`, `ParseMultipartForm`, `FormValue`, or equivalent APIs
  on secret-bearing fields: they retain extra strings, buffers, or temporary
  files outside the explicit secret lifecycle.
- Zeroize every application-owned mutable secret buffer after its last use on
  both success and error paths. A caller that transfers a buffer to a callee
  must define which layer consumes and zeroizes it.
- Do not follow redirects when a client uploads a secret to a selected origin.

Zeroization is best effort within the Go process. It does not claim control of
kernel, TLS stack, garbage collector, or network-device buffers. This limitation
does not permit avoidable application-level copies.

### Current enforcement

- API CA import accepts bounded `multipart/form-data`, rejects JSON and
  malformed field sets, and zeroizes private-key and passphrase buffers.
- CLI CA import decrypts locally, sends a mutable multipart buffer, refuses
  redirects, and zeroizes key, passphrase, and request buffers.
- Web CA import validates CSRF without populating `Request.MultipartForm` or
  `PostForm`, restores a bounded body for streaming handler parsing, and
  zeroizes both middleware and handler secret buffers.

### Test anchors

- `internal/api/cas_test.go`: JSON rejection, fail-closed multipart parsing,
  transport-before-body, and importer-buffer zeroization.
- `internal/cli/ca_test.go`: local encrypted-key handling and redirect refusal.
- `internal/web/csrf_test.go`:
  `TestCSRF_POST_MultipartSecretFieldsRemainStreamable`.
- `internal/web/cas_test.go`:
  `TestCAImport_WebDoesNotRetainSecretFormCopies` and Web transport/body-limit
  coverage.

### Review checklist

When a change touches secret ingress, verify:

1. Which exact buffers contain plaintext at every layer?
2. Which layer owns and zeroizes each buffer?
3. Can parsing, logging, errors, redirects, retries, or audit create another
   copy?
4. Are transport and identity checks executed before the first body read?
5. Do negative tests prove rejection and cleanup, rather than only a successful
   round trip?
