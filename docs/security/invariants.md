# Security invariants

This document defines security properties that every implementation must
preserve. The threat model describes assets, boundaries, attacks, and residual
risks. These invariants define merge-blocking implementation rules.

Each invariant has a stable ID. Code changes that touch its scope must include
a negative regression test referencing that ID. Static analysis and review
support the test; they do not replace it.

## SEC-TENANT-001: actor-scoped resource access

### Rule

Every operator-facing read and mutation must derive its tenant scope from the
authenticated actor. A request parameter may narrow that scope but must never
broaden it.

- Non-admin object access must verify ownership through the complete resource
  chain before returning data or changing state.
- Collection queries must apply owner scope before filtering, pagination, or
  limits. Foreign filter IDs must not bypass that scope.
- Admin access is an explicit exception. A missing, disabled, or non-admin
  actor must fail closed.
- Cross-tenant failures must not return the foreign resource body.
- Events and managed webhook delivery require a known CA owner scope. Empty or
  unknown scope selects no managed recipients.
- Every new operator-facing GET route must be classified as owner-scoped,
  admin-only, or single-resource before it can pass tests.

### Current enforcement

- API and Web handlers use actor-aware CA, Network, and Host authorization.
- SQL collection queries scope non-admins to CAs owned by the actor before
  applying caller-supplied filters and limits.
- The API route-classification test walks the live chi router, so a new GET
  route without a scoping decision fails CI.
- Managed webhook subscriptions are selected by CA owner; the deployer-owned
  static webhook is intentionally global.
- Mobile profile settings are read and replaced only after authorization through
  the owning Network and CA.

### Test anchors

- `internal/api/scoping_property_test.go`:
  `TestProtectedGETRoutesAreClassified` and `TestListEndpointsScopeToOwner`.
- `internal/api/scoping_boundary_test.go`: foreign filters and response-body
  non-disclosure.
- `internal/api/mobile_config_authz_test.go`: foreign mobile profile reads do
  not disclose settings and foreign writes do not mutate them.
- `internal/web/tenant_scope_test.go`: Web read and mutation isolation.
- `internal/webhook/fanout_test.go`:
  `TestDispatcher_ManagedTargetsAreCAOwnerScopedAndStaticTargetIsGlobal`.

### Review checklist

1. Which authenticated actor and ownership chain authorize the operation?
2. Is owner scope applied before every request-controlled filter and limit?
3. Can a foreign identifier change state or appear in a response, event, or
   managed webhook?
4. Has every new operator-facing route received an explicit scope class?

## SEC-REPLAY-001: single-use proofs and atomic consumption

### Rule

Replay-sensitive credentials and proofs — enrollment tokens, poll nonces,
import challenges, and equivalent one-time values — must be purpose-, actor-,
and resource-scoped, TTL-bounded, and accepted at most once.

- Validation and consumption must form one atomic durable operation. Under
  concurrent submissions, exactly one request may succeed.
- A process restart must not reopen a still-valid replay window.
- Rotation, cancel, finalize, and revocation must invalidate outstanding proof
  state in the same transaction as the lifecycle change.
- Retry recovery may accept only an explicitly defined idempotent result for
  the exact prior payload. A payload conflict must remain a failure.

### Current enforcement

- Enrollment consumes a host-bound token in the same transaction that enrolls
  the Host; failed enrollment does not burn the token.
- Poll nonces are keyed by Host and stored in SQLite until expiry.
- Mesh import challenges bind the session, certificate fingerprint, signing
  key, and payload hash. Challenge use and Host registration are serialized.
- Mesh import token rotation and terminal state changes delete challenges
  transactionally.

### Test anchors

- `internal/store/sqlite_enroll_token_test.go`: rollback and concurrent
  exactly-once enrollment.
- `internal/store/sqlite_pop_nonces_test.go`: replay rejection, restart
  durability, tenant namespacing, and concurrent exactly-once acceptance.
- `internal/api/agent_import_test.go`:
  `TestAgentImportChallengeExpiryReplayAndIdempotency`.
- `internal/store/sqlite_mesh_import_test.go`: atomic rotation, challenge use,
  registration, cancel, and finalize coverage.

### Review checklist

1. What actor, purpose, resource, payload, and expiry does the proof bind?
2. Can validation race consumption or disappear on restart?
3. Which lifecycle changes revoke outstanding proofs, and are they atomic?
4. Does retry handling distinguish an exact replay from a conflicting payload?

## SEC-CREDENTIAL-001: keyed persisted credential verifiers

### Rule

Persisted verifiers for operator API keys, operator sessions, enrollment
tokens, mesh-import tokens, and TOTP recovery codes must use a live,
purpose-separated keyed HMAC derived from the configured
`NEBULA_MGMT_MASTER_KEY`. A verifier must use the versioned canonical storage
format; unkeyed SHA-256 credential digests and caller-supplied verifiers must
not be accepted.

- Each credential family has a fixed purpose domain. The same plaintext in two
  families must not produce the same accepted verifier.
- The hasher must fail closed for absent, invalid, or destroyed key material.
  It must not fall back to an unkeyed digest.
- Credential migrations must invalidate legacy verifiers atomically. They must
  reject active collecting mesh imports before destructive writes and must not
  offer legacy read, dual-write, or downgrade compatibility.
- A server must verify that the configured master key decrypts existing CA
  material before applying the cutover or restoring an archive forward.
- Password bcrypt hashes, certificate fingerprints, payload commitments, and
  protocol MACs are outside this invariant unless they become persisted bearer
  credential verifiers.

### Current enforcement

- `internal/credentialhash` derives the credential root with HKDF-SHA-256 and
  produces versioned HMAC-SHA-256 digests for a closed purpose set.
- Runtime key loading builds the CA master and credential hasher from the same
  configured master material.
- SQLite raw-credential operations require a live hasher; migration 027 is the
  clean cutover boundary for legacy state.

### Test anchors

- `internal/credentialhash/hasher_test.go`:
  `TestDigest_SEC_CREDENTIAL_001_SeparatesMasterAndPurpose`,
  `TestDigest_SEC_CREDENTIAL_001_RejectsInvalidInput`, and
  `TestDigest_SEC_CREDENTIAL_001_DestroyDisablesDigest` prove separation and
  fail-closed behavior.
- `internal/cli/runtime_keys_test.go`:
  `TestLoadRuntimeKeys_SEC_CREDENTIAL_001BuildsCredentialHasher` and
  `TestLoadRuntimeKeys_SEC_CREDENTIAL_001RejectsInvalidMaterial` cover the
  shared master-key boundary.
- `internal/store/sqlite_credential_hmac_test.go`:
  `TestSQLiteStore_SEC_CREDENTIAL_001_RejectsRawCredentialOperationsWithoutLiveHasher`
  rejects missing and destroyed hasher use.
- `internal/store/migration_027_test.go` covers atomic refusal for collecting
  imports and master-key guard failures, legacy-verifier invalidation, and
  database rejection of unversioned verifiers.
- `internal/store/sqlite_totp_reset_test.go` covers atomic break-glass reset,
  rollback on audit failure, session revocation, and preservation of disabled
  operator status.

### Review checklist

1. Does every persisted bearer-credential path receive only raw input and a
   live purpose-separated hasher?
2. Can an absent, invalid, or destroyed hasher, or a legacy digest, reach a
   successful lookup or write?
3. Does the migration fail before writes for a collecting import or a
   non-matching master key?
4. Do negative regression tests name `SEC-CREDENTIAL-001` or the applicable
   lifecycle invariant?

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

## SEC-DIAGNOSTIC-001: CLI unclassified argument diagnostics

### Rule

When a CLI rejects an unclassified command word or positional operand, its
diagnostic must describe the error category without copying the supplied value.
It must retain the configured help hint and, for operands after flags, explain
that later flags were ignored.

Recognizer-based redaction is insufficient: arbitrary passwords, API keys,
passphrases, and legacy enrollment tokens may not match a known prefix or
format. The rule is limited to rejected unclassified CLI input; it does not
define credential lifecycle or zeroization requirements.

### Current enforcement

- `internal/cliargs.Guard` reports an unknown command or unexpected positional
  argument by category and retains the binary-specific usage hint without
  interpolating the input value.

### Test anchors

- `internal/cliargs/cliargs_test.go`:
  `TestUnclassifiedArgumentsAreNeverEchoed` covers password-like, API-key-like,
  legacy-token, `nme_`, and `nmi_` values in both guard paths.
- `cmd/nebula-agent/main_test.go`:
  `TestRun_UnknownSubcommandDoesNotEchoUnclassifiedInput` proves errors and
  CLI stdout/stderr do not disclose those values.
- `cmd/nebula-mgmt/main_test.go`:
  `TestManagementCLI_SEC_DIAGNOSTIC_001_DoesNotEchoUnclassifiedInput` covers
  API-key-like subcommands and password-like positional operands.

### Review checklist

When changing rejected CLI argument diagnostics, verify:

1. Does every unclassified command-word or operand error omit its value?
2. Do negative tests cover values that no existing secret recognizer would
   identify?
3. Do the diagnostic category, ignored-flags explanation, and help hint remain
   actionable?

## SEC-PERSIST-001: atomic durable security state

### Rule

Security-relevant state must be authoritative in durable storage and change as
one atomic unit. Errors, conflicts, cancellation, and process restart must not
leave a weaker or partially applied security state.

- Multi-row security transitions must use one transaction and roll back every
  write, including cleanup rows, version changes, and audit-visible state.
- Certificate issuance and credential minting must re-read durable revocation
  and owner status at the point of authorization. Cached or caller-supplied
  state cannot override it.
- A failed transition must preserve the last valid state. Partial data must not
  become externally visible or usable for authorization.
- Security migrations must be repeatable, preserve constraints, and fail
  loudly when legacy data cannot be transformed safely.

### Current enforcement

- Enrollment, revocation, token rotation, and mesh import lifecycle changes use
  transactional SQLite store methods.
- Enrollment compares the certificate-bound Host identity read for signing with
  the durable row inside its consume transaction. If a concurrent edit changed
  `Name`, `NebulaIPs`, or `Groups`, the transaction retains `pending_rekey` so
  the signed stale certificate cannot settle the newer identity.
- Mesh import finalize applies Host state, firewall, blocklist, version, and
  challenge cleanup in one transaction with revision and scope checks.
- Host updates persist Host fields and reset `config_version` in the same
  transaction, so a failed update preserves both the previous firewall state
  and its published version.
- Every certificate-signing path re-checks blocked Host and disabled owning
  Operator state from the store.
- Mobile bundle generation reads the durable CA blocklist and current enrolled
  relay inventory. After the full bundle has been generated, it atomically
  re-checks the durable Host and owner status while persisting the certificate.
- Migration tests exercise upgrade, repeated migrate, rollback, and foreign-key
  enforcement.

### Test anchors

- `internal/store/sqlite_mesh_import_test.go`:
  `TestFinalizeMeshImportRollsBackAllWrites` and
  `TestFinalizeMeshImportRollsBackChallengeCleanup`.
- `internal/api/durable_revocation_test.go`: blocked Host and disabled owner
  prevent enrollment, renewal, re-enrollment, and mobile bundle issuance.
- `internal/mobilebundle/mobile_profile_test.go`:
  `TestBuild_SEC_PERSIST_001IncludesCurrentBlocklistAndEnrolledRelays` and
  `TestBuild_SEC_PERSIST_001InvalidSettingsDoNotEnrollOrRotateCertificate`, and
  `TestBuild_SEC_PERSIST_001ConcurrentBlockCannotBeUndone`.
- `internal/store/sqlite_mobile_certificate_test.go`: the certificate write
  rejects blocked Hosts and disabled owners.
- `internal/store/sqlite_enroll_token_test.go`:
  `TestConsumeTokenAndEnrollHost_NoBurnOnEnrollFailure` and
  `TestConsumeTokenAndEnrollHostWithProfile_SEC_PERSIST_001_PreservesRekeyAfterIdentityChange`.
- `internal/store/sqlite_update_host_atomic_test.go`:
  `TestUpdateHost_ResetsConfigVersion` and
  `TestUpdateHost_SECPERSIST001_RollbackIsAtomic`.
- `internal/store/migration_023_test.go`, `migration_024_test.go`, and
  `migration_pinned_conn_test.go`: migration repeatability and constraints.

### Review checklist

1. Which rows form the security transition, and are all writes transactional?
2. What remains after each error or conflict path?
3. Is revocation and owner status read from durable storage at the final
   authorization point?
4. Can restart, migration, retry, or concurrent mutation expose partial state?
