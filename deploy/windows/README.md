# Windows installer

Two front ends over the same logic:

| | |
|---|---|
| **`nebula-mesh-setup.exe`** | Graphical wizard (Inno Setup). Handles UAC, asks for the server URL and token on its own page, has checkboxes for the services, and registers an entry in Add/Remove Programs. Built from [`nebula-mesh-setup.iss`](nebula-mesh-setup.iss). |
| **`Install-NebulaMesh.ps1`** | The engine. Usable on its own for unattended installs, images and CI. The wizard shells out to it, so both paths run identical code. |

Either way the host ends up with Nebula and `nebula-agent` downloaded and
checksum-verified, installed under `%ProgramFiles%` with hardened ACLs, enrolled
against your management server, and both services registered.

This replaces the manual sequence in [`docs/agent.md`](../../docs/agent.md#3-as-a-windows-service);
that section is still the reference for what each step does.

## Graphical installer

Run `nebula-mesh-setup-<version>.exe` and accept the UAC prompt. The wizard asks
for the install folder, the components (Nebula is optional if the host already
has one), the services to register, and then:

- **Server URL** — validated as an absolute http(s) URL; plaintext `http` to a
  non-loopback host asks for confirmation before continuing.
- **Enrollment token** — masked, and handed to `nebula-agent enroll` through a
  temporary file whose ACL is restricted to SYSTEM and Administrators. It is
  never placed on a command line, and it is deleted when the run ends.
- **Skip enrollment** — ticked automatically on a host that already has an
  `agent.yml`, so an upgrade never replaces the host's identity by accident.

The install step streams the PowerShell output into the wizard's status line and
saves the whole run to `C:\ProgramData\Nebula Mesh\install.log`.

### When something is wrong with the address or the token

Before downloading anything — and long before the single-use token is spent —
the installer calls `GET <server>/healthz`, which a management server answers
unauthenticated. A mistyped address therefore fails in seconds, saying which
part is wrong, instead of after a 20 MB download and a burnt token.

Failures are classified rather than dumped. Each one gets a short code, a
translated headline, and the specifics:

| Code | Means |
|---|---|
| `server-unreachable` | The host name does not resolve, nothing is listening on that port, or it timed out. The message names the address and suggests `nslookup`. |
| `server-tls` | The server's TLS certificate is not trusted by this machine. |
| `server-not-mgmt` | Something answered, but it is not a management server (wrong port, a proxy, another service). |
| `server-rejected-profile` | The server refused this host's Windows paths — it predates the OS-agnostic path check and needs updating. The token is not spent. |
| `token-invalid` / `token-used` / `token-expired` | The server did not accept the token, it was already used, or it has expired. |
| `already-enrolled` | The host already has a Nebula identity; re-run with `-ImportExisting` or `-Force`. |
| `enroll-failed` | Anything else — the agent's own last lines are shown. |

On the command line these appear as `!!` lines at the end of the run. The
wizard lifts them into a dialog with a translated headline, and says explicitly
when nothing was changed and the token is still usable.

Uninstalling from Add/Remove Programs stops and unregisters both services, drops
the firewall rule and the PATH entry, and asks whether to delete this host's
certificates and private key (default: keep them).

### Unattended, from the .exe

```bat
nebula-mesh-setup-0.14.0.exe /VERYSILENT /SUPPRESSMSGBOXES /SERVERURL=https://mgmt.example.com:8080 /TOKENFILE=C:\provision\enroll.token
```

There is deliberately no `/TOKEN=`: a token on a command line is visible to every
process on the box, which is exactly what the file hand-off avoids. With no
`/SERVERURL=` a silent run installs everything and leaves the agent in standby.
Inno's own `/DIR=`, `/COMPONENTS=` and `/TASKS=` work as usual; add
`/PURGEDATA=1` to a silent uninstall to also delete the host's identity.

### Building it

Needs Inno Setup 6 on the build machine:

```powershell
winget install --id JRSoftware.InnoSetup
.\build-installer.ps1 -Version 0.14.0
```

The result lands in `dist\windows-installer\`. Pass `-AgentVersion` /
`-NebulaVersion` to pin exactly which releases the built installer deploys;
by default it resolves `latest` at install time. The `.iss` is UTF-8 **with
BOM** — Inno Setup 6 needs that to read the Spanish messages correctly, and
without it the compile still succeeds, it just renders mojibake, so CI asserts
the BOM rather than trusting review to catch it.

You rarely need to build it by hand. The `Windows installer` job in
[`ci.yml`](../../.github/workflows/ci.yml) parses both scripts, compiles the
`.iss` on every PR — the only thing that ever executes the wizard's Pascal —
and uploads the result as a workflow artifact. On a `v*` tag,
[`release.yml`](../../.github/workflows/release.yml) rebuilds it with the tag's
version, pins `-AgentVersion` to that same tag so the installer deploys the
agent it shipped with, and attaches `nebula-mesh-setup-<version>.exe` plus a
`.sha256` to the GitHub release.

## PowerShell installer

From an **elevated** PowerShell session:

```powershell
.\Install-NebulaMesh.ps1
```

It asks for three things and does the rest:

1. the management server URL (`https://mgmt.example.com:8080`);
2. the single-use enrollment token (typed hidden, never echoed, never written to
   the command line);
3. which services to register — both, `nebula-agent` only, `nebula` only, or none.

Unattended, for an image or a deployment system:

```powershell
.\Install-NebulaMesh.ps1 -ServerUrl https://mgmt.example.com:8080 -TokenFile C:\provision\enroll.token -Unattended
```

## What it installs

| Path | Contents |
|---|---|
| `%ProgramFiles%\Nebula Mesh` | `nebula-agent.exe`, `nebula.exe`, `nebula-cert.exe`, `wintun.dll`, `dist\` |
| `%ProgramData%\Nebula Mesh\Agent` | `agent.yml`, `host.signing.key` |
| `%ProgramData%\Nebula` | `config.yml`, `ca.crt`, `host.crt`, `host.key` |

Services:

| Service | Registered by | Runs |
|---|---|---|
| `NebulaMeshAgent` | `nebula-agent.exe service install` | `LocalSystem`, automatic start, restart 5 s after a fatal exit |
| `nebula` | `nebula.exe -service install` | `LocalSystem`, automatic start |

All three directories get `icacls /inheritance:r` with only `SYSTEM` and the
local `Administrators` group retaining full control. Both services run as
`LocalSystem`, so a binary or config a normal user could write would be a local
privilege-escalation path.

Directories and files are hardened separately, and never with `icacls /T`:
`(OI)(CI)` ACEs make sense on a directory (so files written later inherit them)
but on a leaf file they are inherit-only, leaving an **empty DACL that denies
everyone including SYSTEM** — and `icacls` reports that as success. After
hardening, the installer opens and runs the agent binary to prove the ACLs did
not lock it out.

Before replacing anything, the installer checks that it can actually write every
file already in those directories. If it cannot — an interrupted run, a botched
ACL, files owned by another admin account — it hands ownership to
`Administrators` and restores inheritance, then re-hardens after the copy. That
matters because such a file cannot simply be deleted and rewritten: deleting
needs `DELETE` on the file itself, and Full Control on the parent directory is
not enough to work around a DACL that grants nobody anything.

A file held open by a running service is a sharing violation, not a permissions
problem, and does not trigger that repair — the install path stops the services
before replacing their binaries.

If an installation is ever damaged badly enough that the installer gives up, an
elevated shell can recover it by hand:

```powershell
takeown /F "C:\Program Files\Nebula Mesh" /R /A
icacls "C:\Program Files\Nebula Mesh" /reset /T /C
```

Because Windows has no `SIGHUP`, the installer rewrites `agent.yml` to reload
Nebula through its service instead of a PID file:

```yaml
nebula_pid_file: ""
nebula_reload_command: '%SystemRoot%\System32\net.exe stop nebula & %SystemRoot%\System32\net.exe start nebula'
```

`net stop` waits for the stop to complete, and `&` (rather than `&&`) still
starts Nebula when it was not already running.

The executable is deliberately left unquoted: the agent runs the hook as
`cmd /C <line>`, and `cmd` only preserves the quotes of a line holding exactly
two of them — with four it strips the line's first and last quote instead,
which would leave the `&` inside an unterminated quote. `net.exe` sits at a
path with no spaces, so it needs none. A service name containing a space is
quoted on its own, which keeps the first character of the line out of that
rule's way.

## Options

| Parameter | Effect |
|---|---|
| `-ServerUrl <url>` | Management server. Prompted when omitted. Plaintext `http` to a non-loopback host is refused unless `-AllowInsecureHttp` is given. |
| `-TokenFile <path>` / `-Token <token>` | Enrollment token. Prefer `-TokenFile`: `-Token` lands in shell history. Prompted (hidden) when neither is given. |
| `-Services Both\|Agent\|Nebula\|None` | Which services to register. Prompted when omitted in an interactive run. |
| `-NoStart` | Register the services but leave them stopped. |
| `-AgentVersion` / `-NebulaVersion` | `latest` (default) or a tag, e.g. `v0.14.0` / `v1.11.1`. |
| `-SkipNebula` | Agent only — the host already has a Nebula you manage yourself. |
| `-SkipEnroll` | Install and register without enrolling. The agent idles in standby and picks up a later `enroll` within ~10 s, no restart needed. |
| `-ImportExisting` | Adopt an existing Nebula installation found on the host (passes `--yes` to `enroll`). |
| `-Force` | Re-enroll a host that is already enrolled, replacing its identity. |
| `-AddFirewallRule` | Inbound UDP allow rule for `nebula.exe`. Needed on lighthouses, relays, and anything that must accept unsolicited handshakes. |
| `-AddToPath` | Put the install directory on the machine `PATH` (for `nebula-cert`). |
| `-Unattended` | Never prompt; fail on a missing value. |
| `-Uninstall` / `-PurgeData` | Remove services and binaries; `-PurgeData` also deletes the data directories, **including this host's private key**. |
| `-KeepInstallDir` | With `-Uninstall`: unregister the services but leave the install folder. Used by the graphical uninstaller, which is running from that folder. |

## Air-gapped installs

Stage the archives on a machine with internet access (no elevation needed):

```powershell
.\Install-NebulaMesh.ps1 -DownloadOnly -StageDir C:\stage
```

Then install from them on the target host:

```powershell
.\Install-NebulaMesh.ps1 -AgentZip C:\stage\nebula-agent_0.14.0_windows_amd64.zip -NebulaZip C:\stage\nebula-windows-amd64.zip -ServerUrl https://mgmt.example.com:8080 -TokenFile C:\provision\enroll.token -Unattended
```

## Verification

Every downloaded archive is checked against the SHA-256 published in its
release (`checksums.txt` for `nebula-agent`, `SHASUM256.txt` for Nebula) before
anything is extracted. `-SkipChecksum` disables that; do not use it in
production.

Behind a shared NAT the anonymous GitHub API limit (60 requests/hour) can bite
when resolving `latest`. Set `GITHUB_TOKEN`, or pass explicit tags with
`-AgentVersion` / `-NebulaVersion`.

## After installing

```powershell
Get-Service NebulaMeshAgent, nebula
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='NebulaMeshAgent'} -MaxEvents 20
& "$env:ProgramFiles\Nebula Mesh\nebula.exe" -config "$env:ProgramData\Nebula\config.yml" -test
```

Re-running the installer upgrades the binaries in place and re-registers the
services. Enrollment is left alone unless `-Force` is given, so an upgrade never
touches the host's identity.

## Architecture support

`nebula-agent` publishes Windows builds for `amd64` only. On an ARM64 host the
installer uses the `amd64` agent (it runs under x64 emulation) together with the
native `arm64` Nebula build.
