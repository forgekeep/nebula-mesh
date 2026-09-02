<#
.SYNOPSIS
    Downloads and installs Nebula and nebula-agent on Windows, enrolls the host
    against a management server, and registers both as Windows services.

.DESCRIPTION
    One-shot installer for a Windows host that should join a Nebula Mesh network:

      1. downloads nebula-agent (forgekeep/nebula-mesh) and Nebula
         (slackhq/nebula) release archives and verifies their SHA-256 checksums;
      2. installs the binaries below %ProgramFiles% and hardens the ACLs so only
         SYSTEM and local Administrators can write them (the services run as
         LocalSystem, so a user-writable binary would be a local privilege
         escalation path);
      3. prompts for the management server URL and the one-time enrollment
         token, hands the token to `nebula-agent enroll` through an owner-only
         file, and deletes that file afterwards;
      4. points agent.yml's reload hook at the Nebula service (Windows has no
         SIGHUP, so nebula_pid_file cannot be used);
      5. registers and starts the NebulaMeshAgent and nebula services.

    Re-running the installer over an existing installation upgrades the binaries
    and re-registers the services; enrollment is skipped unless -Force is given.

.EXAMPLE
    .\Install-NebulaMesh.ps1

    Fully interactive: asks for the server URL, the token, and which services to
    enable.

.EXAMPLE
    .\Install-NebulaMesh.ps1 -ServerUrl https://mgmt.example.com:8080 -TokenFile C:\provision\enroll.token -Unattended

    Unattended install of the latest agent + Nebula with both services enabled.

.EXAMPLE
    .\Install-NebulaMesh.ps1 -DownloadOnly -StageDir C:\stage

    Downloads and verifies the archives without touching the system (no
    elevation required). Feed them back with -AgentZip / -NebulaZip on an
    air-gapped host.

.EXAMPLE
    .\Install-NebulaMesh.ps1 -Uninstall

    Stops and removes both services and the installed binaries. Certificates,
    keys and configuration are kept unless -PurgeData is added.

.LINK
    https://github.com/forgekeep/nebula-mesh/blob/main/docs/agent.md
#>
[CmdletBinding()]
param(
    # Management server URL, e.g. https://mgmt.example.com:8080. Prompted when omitted.
    [string]$ServerUrl,

    # One-time enrollment token. Prefer -TokenFile: -Token lands in shell history.
    [string]$Token,

    # File holding the enrollment token. Read, and left where it is.
    [string]$TokenFile,

    # nebula-agent release to install: "latest" or a tag such as v0.14.0.
    [string]$AgentVersion = 'latest',

    # Nebula release to install: "latest" or a tag such as v1.11.1.
    [string]$NebulaVersion = 'latest',

    # Pre-downloaded archives (offline install). Skips the matching download.
    [string]$AgentZip,
    [string]$NebulaZip,

    [string]$AgentRepo = 'forgekeep/nebula-mesh',
    [string]$NebulaRepo = 'slackhq/nebula',

    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Nebula Mesh'),

    # Nebula's data directory: rendered config.yml, ca.crt, host.crt, host.key.
    [string]$NebulaDataDir = (Join-Path $env:ProgramData 'Nebula'),

    # The agent's own directory: agent.yml and the Ed25519 poll-signing key.
    [string]$AgentDataDir = (Join-Path $env:ProgramData 'Nebula Mesh\Agent'),

    # Which services to register: Both, Agent, Nebula or None. Prompted when omitted.
    [ValidateSet('Both', 'Agent', 'Nebula', 'None')]
    [string]$Services = 'Both',

    # Register the services but leave them stopped.
    [switch]$NoStart,

    # Do not install Nebula itself (the host already has a managed nebula.exe).
    [switch]$SkipNebula,

    # Install binaries and services without enrolling. The agent idles in
    # standby and picks the enrollment up within ~10s once you run it manually.
    [switch]$SkipEnroll,

    # Confirm adoption of an existing Nebula installation found on this host
    # (passes --yes to `nebula-agent enroll`).
    [switch]$ImportExisting,

    # Re-enroll a host that is already enrolled, replacing its identity.
    [switch]$Force,

    # Allow a plaintext http:// server URL. The token and the Nebula config then
    # transit in cleartext - lab use only.
    [switch]$AllowInsecureHttp,

    # Skip SHA-256 verification of the downloaded archives. Not recommended.
    [switch]$SkipChecksum,

    # Add an inbound Windows Firewall rule (UDP, any port) for nebula.exe.
    # Needed on lighthouses, relays, and any host that must accept unsolicited
    # inbound handshakes.
    [switch]$AddFirewallRule,

    # Add the install directory to the machine PATH (nebula-cert, nebula-agent).
    [switch]$AddToPath,

    # Never prompt. Fails instead of asking for a missing value.
    [switch]$Unattended,

    # Download and verify only; do not touch the system. No elevation needed.
    [switch]$DownloadOnly,

    # Where -DownloadOnly writes the verified archives.
    [string]$StageDir = (Get-Location).Path,

    # Remove the services and the installed binaries.
    [switch]$Uninstall,

    # With -Uninstall: unregister the services but leave the install directory
    # in place. Used by the graphical uninstaller, which deletes those files
    # itself - it is running from that directory.
    [switch]$KeepInstallDir,

    # With -Uninstall: also delete the data directories, including this host's
    # private key and certificates. Irreversible.
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$script:AgentServiceName = 'NebulaMeshAgent'
$script:NebulaServiceName = 'nebula'
$script:FirewallRuleName = 'Nebula (nebula-mesh installer)'

# Set when an upgrade had to stop a running service to replace its image, so
# the installer can put it back the way it found it even when it is not
# registering services this run.
$script:AgentServiceWasStopped = $false
$script:NebulaServiceWasStopped = $false

# ---------------------------------------------------------------- output ----

function Write-Section([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Item([string]$Message) { Write-Host "    $Message" }
function Write-Ok([string]$Message) { Write-Host "    $Message" -ForegroundColor Green }
function Write-Note([string]$Message) { Write-Host "    ! $Message" -ForegroundColor Yellow }

# ------------------------------------------------------- failure reporting --
#
# Failures are classified into a short code plus a plain-language explanation
# instead of surfacing a raw PowerShell error record. The graphical installer
# lifts the "!!" lines out of the log and shows those, translating the code
# when it recognises it; on the command line they are simply readable.
$script:FailureCode = ''
$script:FailureLines = @()

function Set-Failure([string]$Code, [string[]]$Lines) {
    $script:FailureCode = $Code
    $script:FailureLines = $Lines
}

function Write-Failure([string]$Fallback) {
    $lines = @($script:FailureLines)
    if ($lines.Count -eq 0) { $lines = @($Fallback) }

    Write-Host ''
    Write-Host '!! INSTALL FAILED' -ForegroundColor Red
    if ($script:FailureCode) {
        Write-Host "!! code: $script:FailureCode" -ForegroundColor Red
    }
    foreach ($line in $lines) {
        Write-Host "!! $line" -ForegroundColor Red
    }
}

# --------------------------------------------------------------- helpers ----

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'Administrator privileges are required. Re-run this script from an elevated PowerShell session.'
    }
}

function Get-HostArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    switch ($arch.ToUpperInvariant()) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        'X86' { return 'x86' }
        default { return 'amd64' }
    }
}

function Get-GitHubRelease([string]$Repo, [string]$Version) {
    $headers = @{ 'User-Agent' = 'Install-NebulaMesh.ps1'; 'Accept' = 'application/vnd.github+json' }
    # Only ever sent to api.github.com, and only to lift the 60 req/h anonymous
    # rate limit that hosts behind a shared NAT run into.
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }

    $candidates = @()
    if ($Version -eq 'latest' -or [string]::IsNullOrWhiteSpace($Version)) {
        $candidates += "https://api.github.com/repos/$Repo/releases/latest"
    } else {
        $candidates += "https://api.github.com/repos/$Repo/releases/tags/$Version"
        if ($Version -notlike 'v*') {
            $candidates += "https://api.github.com/repos/$Repo/releases/tags/v$Version"
        }
    }

    $lastError = 'unknown error'
    foreach ($uri in $candidates) {
        try {
            return Invoke-RestMethod -UseBasicParsing -Uri $uri -Headers $headers
        } catch {
            $lastError = $_.Exception.Message
        }
    }
    throw ("Cannot resolve release '$Version' of ${Repo}: $lastError. Pass an explicit tag " +
        '(-AgentVersion / -NebulaVersion) or a local archive (-AgentZip / -NebulaZip).')
}

function Get-ReleaseAsset($Release, [string]$Pattern) {
    $asset = $Release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) {
        throw "Release $($Release.tag_name) has no asset matching /$Pattern/."
    }
    return $asset
}

function Save-RemoteFile([string]$Uri, [string]$Destination) {
    $previous = $ProgressPreference
    # Invoke-WebRequest's progress bar costs more than the download on PS 5.1.
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination
    } finally {
        $ProgressPreference = $previous
    }
}

function Get-ExpectedSha256([string]$ChecksumFile, [string]$AssetName) {
    foreach ($line in (Get-Content -LiteralPath $ChecksumFile)) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        # A leading "*" is sha256sum's binary-mode marker.
        if ($parts[1].TrimStart('*').Trim() -eq $AssetName) {
            return $parts[0].ToLowerInvariant()
        }
    }
    return $null
}

function Assert-Sha256([string]$Path, [string]$Expected, [string]$Label) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "SHA-256 mismatch for ${Label}: expected $Expected, got $actual."
    }
}

# Downloads the asset matching $AssetPattern from $Repo@$Version into $WorkDir
# and verifies it against the release's checksum file. Returns the archive path.
function Get-VerifiedArchive {
    param(
        [string]$Repo,
        [string]$Version,
        [string]$AssetPattern,
        [string]$WorkDir,
        [string]$Label
    )

    $release = Get-GitHubRelease -Repo $Repo -Version $Version
    $asset = Get-ReleaseAsset -Release $release -Pattern $AssetPattern
    $archive = Join-Path $WorkDir $asset.name

    Write-Item "$Label $($release.tag_name): downloading $($asset.name) ..."
    Save-RemoteFile -Uri $asset.browser_download_url -Destination $archive

    if ($SkipChecksum) {
        Write-Note "checksum verification skipped for $($asset.name)"
        return $archive
    }

    $checksumAsset = $release.assets |
        Where-Object { $_.name -match '(?i)^(checksums\.txt|shasum256\.txt|sha256sums?(\.txt)?)$' } |
        Select-Object -First 1
    if (-not $checksumAsset) {
        throw ("Release $($release.tag_name) of $Repo publishes no checksum file; " +
            're-run with -SkipChecksum to accept the archive unverified.')
    }

    $checksumFile = Join-Path $WorkDir "$Label-$($checksumAsset.name)"
    Save-RemoteFile -Uri $checksumAsset.browser_download_url -Destination $checksumFile
    $expected = Get-ExpectedSha256 -ChecksumFile $checksumFile -AssetName $asset.name
    if (-not $expected) {
        throw "$($checksumAsset.name) has no entry for $($asset.name)."
    }
    Assert-Sha256 -Path $archive -Expected $expected -Label $asset.name
    Write-Ok "$($asset.name) verified (sha256 $($expected.Substring(0, 16))...)"
    return $archive
}

function Expand-ArchiveTo([string]$Archive, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Expand-Archive -LiteralPath $Archive -DestinationPath $Destination -Force
}

# Strips inherited ACEs so only SYSTEM and local Administrators keep write
# access. Mirrors the hardening documented in docs/agent.md.
#
# Directories take (OI)(CI) ACEs so that files created later - the agent's
# certificates and rendered configs - inherit them. Files must NOT: an
# object-inherit/container-inherit ACE on a leaf file is inherit-only, so it
# grants nobody anything, and the file ends up with an empty DACL that denies
# everyone including SYSTEM. icacls reports that as success, so the exit code
# cannot be relied on to catch it either - hence the separate file form below,
# and Assert-Readable afterwards.
function Protect-Directory([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot restrict permissions on $Path (icacls exit $LASTEXITCODE)." }
}

function Protect-File([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot restrict permissions on $Path (icacls exit $LASTEXITCODE)." }
}

# Hardens a directory and everything already inside it. Deliberately not
# `icacls /T`: that applies the directory-shaped ACEs to files too, which is
# the empty-DACL trap described above.
function Protect-Tree([string]$Path) {
    Protect-Directory $Path
    foreach ($entry in (Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
        if ($entry.PSIsContainer) {
            Protect-Directory $entry.FullName
        } else {
            Protect-File $entry.FullName
        }
    }
}

# True when every file below Path can be opened for writing, i.e. the installer
# can replace what a previous run left behind.
function Test-TreeWritable([string]$Path) {
    try {
        $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction Stop)
    } catch {
        return $false
    }
    foreach ($file in $files) {
        try {
            [IO.File]::Open($file.FullName, 'Open', 'ReadWrite').Dispose()
        } catch [System.UnauthorizedAccessException] {
            return $false
        } catch {
            # A running service holds its own image open, which is a sharing
            # violation, not a permissions problem - the install path stops the
            # services before replacing them. Only a denied ACL means repair.
        }
    }
    return $true
}

# Puts an unwritable installation back under this installer's control before
# replacing its files: hand ownership to Administrators, then drop the explicit
# ACEs so everything inherits from the parent again. Protect-Tree re-applies the
# hardening after the new files are in place.
#
# Needed because an interrupted or faulty earlier run can leave files that even
# an elevated process cannot open or delete - deleting a file needs DELETE on
# the file itself, and Full Control on the parent directory is not enough to
# work around a DACL that grants nobody anything.
#
# The icacls calls here legitimately hit files they cannot touch, and icacls
# reports success for cases it did not actually fix, so neither its exit code
# nor its stderr is trusted: the outcome is re-tested instead. Their stderr is
# deliberately not redirected - "2>$null" on a native command makes PowerShell
# wrap each line in an ErrorRecord, which $ErrorActionPreference = 'Stop' then
# turns into a terminating error. Letting it through puts it in the install log
# instead, where it is useful.
function Restore-TreeAccess([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (Test-TreeWritable $Path) { return }

    Write-Note "$Path holds files this installer cannot write - repairing ownership and permissions"
    foreach ($arguments in @(
            @($Path, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q'),
            @($Path, '/reset', '/T', '/C', '/Q'))) {
        try {
            & icacls.exe @arguments | Out-Null
        } catch {
            # Best effort; Test-TreeWritable below decides whether it worked.
        }
    }

    if (-not (Test-TreeWritable $Path)) {
        throw ("Cannot regain write access to $Path. From an elevated prompt run: " +
            "takeown /F `"$Path`" /R /A   and then   icacls `"$Path`" /reset /T /C   " +
            'or delete the folder, then run this installer again.')
    }
    Write-Ok "$Path permissions repaired"
}

# Post-condition for the hardening: a file the installer just locked down must
# still be openable by this (elevated) process. A silent ACL mistake otherwise
# only surfaces later as "access denied" from a service that will not start.
function Assert-Readable([string]$Path) {
    try {
        [IO.File]::OpenRead($Path).Dispose()
    } catch {
        throw ("$Path is unreadable after hardening its permissions: $($_.Exception.Message). " +
            'Reset it with: icacls "<path>" /reset /T /C')
    }
}

function Get-ServiceOrNull([string]$Name) {
    return Get-Service -Name $Name -ErrorAction SilentlyContinue
}

function Wait-ServiceStatus([string]$Name, [string]$Expected, [int]$TimeoutSeconds = 45) {
    for ($attempt = 0; $attempt -lt $TimeoutSeconds; $attempt++) {
        $service = Get-ServiceOrNull $Name
        if ($service -and [string]$service.Status -eq $Expected) { return }
        Start-Sleep -Seconds 1
    }
    throw "Service $Name did not reach state $Expected within ${TimeoutSeconds}s."
}

function Invoke-Native([string]$Exe, [string[]]$Arguments, [string]$What, [switch]$IgnoreFailure) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        if ($IgnoreFailure) {
            Write-Note "$What failed (exit $LASTEXITCODE), continuing"
            return $false
        }
        throw "$What failed (exit $LASTEXITCODE)."
    }
    return $true
}

# Nebula registers itself as "nebula", but an installation this script did not
# create may use another name; fall back to matching the service ImagePath.
function Find-NebulaServiceName([string]$NebulaExe) {
    if (Get-ServiceOrNull $script:NebulaServiceName) { return $script:NebulaServiceName }
    $match = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and $_.PathName -like "*$NebulaExe*"
    } | Select-Object -First 1
    if ($match) { return $match.Name }
    return $null
}

function ConvertFrom-SecureStringPlain([Security.SecureString]$Secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Read-RequiredValue([string]$Prompt) {
    if ($Unattended) { throw "$Prompt is required in unattended mode." }
    while ($true) {
        $value = (Read-Host $Prompt).Trim()
        if ($value) { return $value }
    }
}

function Assert-ServerUrl([string]$Url) {
    $parsed = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed)) {
        throw "'$Url' is not an absolute URL (expected e.g. https://mgmt.example.com:8080)."
    }
    if ($parsed.Scheme -eq 'https') { return }
    if ($parsed.Scheme -eq 'http') {
        if (-not $parsed.IsLoopback -and -not $AllowInsecureHttp) {
            throw ("'$Url' is plaintext http. The enrollment token and the Nebula config " +
                'would transit in cleartext; use https, or pass -AllowInsecureHttp if this is a lab.')
        }
        return
    }
    throw "'$Url' must use http or https."
}

# Digs a WebException out of whatever PowerShell wrapped it in, so the same
# code classifies failures on 5.1 and 7.
function Get-WebException($ErrorRecord) {
    $exception = $ErrorRecord.Exception
    for ($depth = 0; $exception -and $depth -lt 5; $depth++) {
        if ($exception -is [Net.WebException]) { return $exception }
        $exception = $exception.InnerException
    }
    return $null
}

# Confirms the URL really points at a management server, before anything is
# downloaded and long before the single-use token is spent. /healthz is
# unauthenticated and answers {"status":"ok"}, so a mistyped address, an
# unreachable host and an untrusted certificate all become distinct, named
# failures instead of one opaque error at enrollment time.
function Assert-ManagementServerReachable([string]$Url) {
    $probe = $Url.TrimEnd('/') + '/healthz'
    Write-Item "checking $probe ..."

    $response = $null
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $probe -TimeoutSec 20
    } catch {
        # Captured before the switch: inside it $_ is the switch's input (the
        # status string), not this catch's ErrorRecord, and under
        # Set-StrictMode -Version 3.0 reading .Exception off a string throws
        # PropertyNotFoundException on top of the failure being reported.
        $record = $_
        $web = Get-WebException $record
        $status = ''
        if ($web) { $status = [string]$web.Status }

        switch ($status) {
            'NameResolutionFailure' {
                Set-Failure 'server-unreachable' @(
                    "The host name in $Url cannot be resolved.",
                    'Check the address for a typo, and that this machine can resolve it:',
                    "  nslookup $(([Uri]$Url).Host)")
            }
            'ConnectFailure' {
                Set-Failure 'server-unreachable' @(
                    "Nothing accepted a connection at $(([Uri]$Url).Authority).",
                    'Check the port in the URL, that the management server is running,',
                    'and that no firewall blocks the way out of this machine.')
            }
            'Timeout' {
                Set-Failure 'server-unreachable' @(
                    "$(([Uri]$Url).Authority) did not answer within 20 seconds.",
                    'The address may be wrong, or a firewall may be dropping the connection.')
            }
            { $_ -in @('TrustFailure', 'SecureChannelFailure') } {
                Set-Failure 'server-tls' @(
                    "The TLS certificate presented by $(([Uri]$Url).Authority) is not trusted by this machine.",
                    'Install the issuing CA in the Local Machine trust store, or use the host name',
                    'the certificate was issued for.')
            }
            'ProtocolError' {
                $code = 'unknown'
                if ($web.Response) { $code = [int]$web.Response.StatusCode }
                Set-Failure 'server-not-mgmt' @(
                    "$probe answered HTTP $code.",
                    'A Nebula Mesh management server answers 200 there. Something else is',
                    'listening on that address, or the URL needs a different port or path.')
            }
            default {
                Set-Failure 'server-unreachable' @(
                    "Cannot reach $probe.",
                    $record.Exception.Message)
            }
        }
        throw 'management server pre-flight failed'
    }

    if ($response.Content -notmatch '"status"\s*:\s*"ok"') {
        Set-Failure 'server-not-mgmt' @(
            "$probe answered, but not like a Nebula Mesh management server.",
            'Check that the URL points at nebula-mgmt and not at another service or a proxy.')
        throw 'management server pre-flight failed'
    }

    Write-Ok "management server answered at $probe"
}

function Read-ServiceSelection {
    Write-Host ''
    Write-Host '    Which services should be registered?' -ForegroundColor Cyan
    Write-Host '      [B] both nebula and nebula-agent (default)'
    Write-Host '      [A] nebula-agent only'
    Write-Host '      [N] nebula only'
    Write-Host '      [S] none - install the files, register nothing'
    while ($true) {
        $answer = (Read-Host '    Choice [B/A/N/S]').Trim().ToUpperInvariant()
        switch ($answer) {
            '' { return 'Both' }
            'B' { return 'Both' }
            'A' { return 'Agent' }
            'N' { return 'Nebula' }
            'S' { return 'None' }
        }
    }
}

# ------------------------------------------------------------- uninstall ----

function Remove-AgentService([string]$AgentExe) {
    $service = Get-ServiceOrNull $script:AgentServiceName
    if (-not $service) { return }
    Write-Item "removing service $script:AgentServiceName ..."
    if (Test-Path -LiteralPath $AgentExe) {
        if ([string]$service.Status -ne 'Stopped') {
            Invoke-Native -Exe $AgentExe -Arguments @('service', 'stop') -What 'agent service stop' -IgnoreFailure | Out-Null
        }
        Invoke-Native -Exe $AgentExe -Arguments @('service', 'uninstall') -What 'agent service uninstall' -IgnoreFailure | Out-Null
    }
    if (Get-ServiceOrNull $script:AgentServiceName) {
        & sc.exe stop $script:AgentServiceName | Out-Null
        & sc.exe delete $script:AgentServiceName | Out-Null
    }
    Write-Ok "$script:AgentServiceName removed"
}

function Remove-NebulaService([string]$NebulaExe) {
    $name = Find-NebulaServiceName -NebulaExe $NebulaExe
    if (-not $name) { return }
    Write-Item "removing service $name ..."
    if (Test-Path -LiteralPath $NebulaExe) {
        Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'stop') -What 'nebula service stop' -IgnoreFailure | Out-Null
        Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'uninstall') -What 'nebula service uninstall' -IgnoreFailure | Out-Null
    }
    if (Get-ServiceOrNull $name) {
        & sc.exe stop $name | Out-Null
        & sc.exe delete $name | Out-Null
    }
    Write-Ok "$name removed"
}

function Invoke-Uninstall {
    Assert-Administrator
    Write-Section 'Removing Nebula Mesh'

    $agentExe = Join-Path $InstallDir 'nebula-agent.exe'
    $nebulaExe = Join-Path $InstallDir 'nebula.exe'

    Remove-AgentService -AgentExe $agentExe
    Remove-NebulaService -NebulaExe $nebulaExe

    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        $rule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
        if ($rule) {
            $rule | Remove-NetFirewallRule
            Write-Ok 'firewall rule removed'
        }
    }

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -and ($machinePath -split ';') -contains $InstallDir) {
        $kept = ($machinePath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
        Write-Ok 'install directory removed from PATH'
    }

    if ($KeepInstallDir) {
        Write-Item "$InstallDir left in place (-KeepInstallDir)"
    } elseif (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Ok "$InstallDir deleted"
    }

    if ($PurgeData) {
        if (-not $Unattended) {
            Write-Note "This deletes $AgentDataDir and $NebulaDataDir, including this host's private key and certificates."
            $answer = (Read-Host '    Type DELETE to confirm').Trim()
            if ($answer -cne 'DELETE') {
                Write-Item 'data directories kept'
                Write-Section 'Done'
                return
            }
        }
        foreach ($path in @($AgentDataDir, $NebulaDataDir)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force
                Write-Ok "$path deleted"
            }
        }
    } else {
        Write-Item "kept: $AgentDataDir, $NebulaDataDir (re-run with -PurgeData to delete them)"
    }

    Write-Section 'Done'
}

# --------------------------------------------------------------- install ----

function Install-AgentBinaries([string]$Archive, [string]$WorkDir) {
    $extracted = Join-Path $WorkDir 'agent'
    Expand-ArchiveTo -Archive $Archive -Destination $extracted
    $source = Get-ChildItem -LiteralPath $extracted -Filter 'nebula-agent.exe' -Recurse | Select-Object -First 1
    if (-not $source) { throw 'nebula-agent.exe not found in the agent archive.' }

    $target = Join-Path $InstallDir 'nebula-agent.exe'
    $service = Get-ServiceOrNull $script:AgentServiceName
    if ($service -and (Test-Path -LiteralPath $target) -and [string]$service.Status -ne 'Stopped') {
        # A running service holds its image open; stop it before overwriting.
        Invoke-Native -Exe $target -Arguments @('service', 'stop') -What 'agent service stop' -IgnoreFailure | Out-Null
        Wait-ServiceStatus -Name $script:AgentServiceName -Expected 'Stopped' -TimeoutSeconds 30
        $script:AgentServiceWasStopped = $true
    }
    Copy-Item -LiteralPath $source.FullName -Destination $target -Force

    $example = Get-ChildItem -LiteralPath $extracted -Filter 'agent.example.yml' -Recurse | Select-Object -First 1
    if ($example) {
        Copy-Item -LiteralPath $example.FullName -Destination (Join-Path $InstallDir 'agent.example.yml') -Force
    }
    Write-Ok "nebula-agent.exe -> $target"
    return $target
}

function Install-NebulaBinaries([string]$Archive, [string]$WorkDir, [string]$Arch) {
    $extracted = Join-Path $WorkDir 'nebula'
    Expand-ArchiveTo -Archive $Archive -Destination $extracted

    $nebulaExe = Join-Path $InstallDir 'nebula.exe'
    $existing = Find-NebulaServiceName -NebulaExe $nebulaExe
    if ($existing -and (Test-Path -LiteralPath $nebulaExe)) {
        $service = Get-ServiceOrNull $existing
        if ($service -and [string]$service.Status -ne 'Stopped') {
            Invoke-Native -Exe $nebulaExe -Arguments @('-service', 'stop') -What 'nebula service stop' -IgnoreFailure | Out-Null
            Wait-ServiceStatus -Name $existing -Expected 'Stopped' -TimeoutSeconds 30
            $script:NebulaServiceWasStopped = $true
        }
    }

    foreach ($name in @('nebula.exe', 'nebula-cert.exe')) {
        $source = Get-ChildItem -LiteralPath $extracted -Filter $name -Recurse | Select-Object -First 1
        if (-not $source) { throw "$name not found in the Nebula archive." }
        Copy-Item -LiteralPath $source.FullName -Destination (Join-Path $InstallDir $name) -Force
    }

    # Nebula's tun device is wintun, whose DLL ships inside the archive under
    # dist/windows/wintun/bin/<arch>/. Keep the tree upstream documents and also
    # drop the matching DLL next to nebula.exe, where the loader looks first.
    $dist = Join-Path $extracted 'dist'
    if (Test-Path -LiteralPath $dist) {
        $distTarget = Join-Path $InstallDir 'dist'
        if (Test-Path -LiteralPath $distTarget) { Remove-Item -LiteralPath $distTarget -Recurse -Force }
        Copy-Item -LiteralPath $dist -Destination $distTarget -Recurse -Force
    }
    $wintun = Get-ChildItem -LiteralPath $extracted -Filter 'wintun.dll' -Recurse |
        Where-Object { $_.DirectoryName -like "*\$Arch" } | Select-Object -First 1
    if (-not $wintun) {
        $wintun = Get-ChildItem -LiteralPath $extracted -Filter 'wintun.dll' -Recurse |
            Where-Object { $_.DirectoryName -like '*\amd64' } | Select-Object -First 1
    }
    if ($wintun) {
        Copy-Item -LiteralPath $wintun.FullName -Destination (Join-Path $InstallDir 'wintun.dll') -Force
        Write-Ok "wintun.dll ($Arch) installed next to nebula.exe"
    } else {
        Write-Note 'wintun.dll not found in the archive; Nebula will fail to open its tun device'
    }

    Write-Ok "nebula.exe, nebula-cert.exe -> $InstallDir"
    return $nebulaExe
}

# Turns whatever `nebula-agent enroll` printed into a named, actionable
# failure. The agent reports the server's HTTP status and error body verbatim,
# so the distinct causes - a spent token, an expired one, a server too old for
# this host's paths - can be told apart and explained.
function Set-EnrollFailure {
    param([string[]]$Output, [int]$ExitCode)

    $text = ($Output -join "`n")

    if ($text -match 'invalid agent profile') {
        Set-Failure 'server-rejected-profile' @(
            'The management server refused this host''s file paths (HTTP 400 "invalid agent profile").',
            'Management servers older than the OS-agnostic path check validate an agent''s paths',
            'with their own operating system''s rules, so a Linux server rejects Windows paths like',
            "  $NebulaDataDir\config.yml",
            'Update the management server. The enrollment token was NOT spent - it still works.')
        return
    }
    if ($text -match 'already used' -or $text -match 'HTTP 409') {
        Set-Failure 'token-used' @(
            'That enrollment token has already been used.',
            'Tokens are single-use: issue a fresh one on the management server and run this again.')
        return
    }
    if ($text -match 'expired' -or $text -match 'HTTP 410') {
        Set-Failure 'token-expired' @(
            'That enrollment token has expired.',
            'Issue a fresh one on the management server and run this again.')
        return
    }
    if ($text -match 'HTTP 401' -or $text -match 'invalid enrollment token') {
        Set-Failure 'token-invalid' @(
            'The management server did not accept that enrollment token.',
            'Check it was copied whole, and that it is an enrollment token rather than',
            'another kind of token.')
        return
    }
    if ($text -match 'already enrolled' -or $text -match 'existing Nebula installation') {
        Set-Failure 'already-enrolled' @(
            'This host already has a Nebula identity.',
            'Re-run with -ImportExisting to adopt the existing installation, or with -Force to',
            'replace its identity (the old certificate stops working).')
        return
    }

    $detail = @($Output | Where-Object { $_ -match '\S' } | Select-Object -Last 4)
    Set-Failure 'enroll-failed' (@("Enrollment failed (exit $ExitCode). The agent reported:") + $detail)
}

function Invoke-AgentEnroll {
    param(
        [string]$AgentExe,
        [string]$AgentConfigPath,
        [Security.SecureString]$SecureToken,
        [string]$ExistingTokenFile
    )

    $tokenPath = $ExistingTokenFile
    $temporary = $false
    if (-not $tokenPath) {
        $tokenPath = Join-Path $AgentDataDir 'enroll.token'
        $temporary = $true
        # Create the file empty, lock it down, and only then write the secret,
        # so the token is never readable by a lesser user, not even briefly.
        Set-Content -LiteralPath $tokenPath -Value '' -NoNewline -Force
        Protect-File $tokenPath
        $plain = ConvertFrom-SecureStringPlain $SecureToken
        try {
            [IO.File]::WriteAllText($tokenPath, $plain, (New-Object Text.UTF8Encoding($false)))
        } finally {
            $plain = $null
        }
    }

    try {
        $arguments = @(
            'enroll',
            '--server', $ServerUrl,
            '--token-file', $tokenPath,
            '--config', $AgentConfigPath,
            '--data-dir', $NebulaDataDir
        )
        if ($ImportExisting) { $arguments += '--yes' }
        if ($Force) { $arguments += '--force' }
        if ($AllowInsecureHttp) { $arguments += '--insecure-http' }

        # Capture while echoing, so the failure can be classified. stderr is
        # merged deliberately - that is where the agent reports the server's
        # answer - and $ErrorActionPreference is relaxed for the call because
        # PowerShell turns a native command's redirected stderr into an
        # ErrorRecord, which 'Stop' would raise before the exit code is read.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $AgentExe @arguments 2>&1 | ForEach-Object {
                $line = [string]$_
                Write-Item $line
                $line
            }
        } finally {
            $ErrorActionPreference = $previous
        }

        if ($LASTEXITCODE -ne 0) {
            Set-EnrollFailure -Output $output -ExitCode $LASTEXITCODE
            throw "enrollment failed"
        }
    } finally {
        if ($temporary -and (Test-Path -LiteralPath $tokenPath)) {
            Remove-Item -LiteralPath $tokenPath -Force
        }
    }
    Write-Ok "enrolled against $ServerUrl"
}

# Windows has no SIGHUP, so the agent cannot signal Nebula through a PID file.
# Point nebula_reload_command at the service instead: `net stop` waits for the
# stop to finish, and `&` (not `&&`) still starts Nebula when it was not up.
# agent.yml is a flat YAML map, so rewriting these two keys in place is safe.
function Set-AgentReloadCommand([string]$AgentConfigPath, [string]$NebulaService) {
    if (-not (Test-Path -LiteralPath $AgentConfigPath)) {
        Write-Note ("no agent.yml yet - after enrolling, set nebula_reload_command so config updates " +
            'reach Nebula (see deploy/windows/README.md).')
        return
    }

    # The executable is deliberately unquoted. The agent hands the hook to
    # `cmd /C <line>` verbatim, and cmd only keeps the quotes of a line that
    # holds exactly two of them; with four it falls back to stripping the
    # line's first and last quote (cmd /?), which would leave the `&` inside
    # an unterminated quote and neither half runnable.
    # %SystemRoot%\System32\net.exe has no space to protect. A service name
    # may have one, and quoting only that keeps the line's first character out
    # of the stripping rule's way.
    $net = '%SystemRoot%\System32\net.exe'
    $service = $NebulaService
    if ($service -match '\s') { $service = '"' + $service + '"' }
    $command = "$net stop $service & $net start $service"
    $lines = @(Get-Content -LiteralPath $AgentConfigPath | Where-Object {
            $_ -notmatch '^\s*nebula_pid_file\s*:' -and $_ -notmatch '^\s*nebula_reload_command\s*:'
        })
    $lines += 'nebula_pid_file: ""'
    # A YAML single-quoted scalar escapes its own quote by doubling it, which
    # matters because a discovered service name may contain one.
    $escaped = $command -replace "'", "''"
    $lines += "nebula_reload_command: '$escaped'"
    # No BOM (the file is parsed by gopkg.in/yaml.v3); rewriting in place keeps
    # the ACL the agent's own 0600-equivalent write established.
    [IO.File]::WriteAllLines($AgentConfigPath, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
    Write-Ok "agent.yml reload hook -> restart of service '$NebulaService'"
}

function Install-AgentService([string]$AgentExe, [string]$AgentConfigPath) {
    if (Get-ServiceOrNull $script:AgentServiceName) {
        Invoke-Native -Exe $AgentExe -Arguments @('service', 'stop') -What 'agent service stop' -IgnoreFailure | Out-Null
        Invoke-Native -Exe $AgentExe -Arguments @('service', 'uninstall') -What 'agent service uninstall' -IgnoreFailure | Out-Null
    }
    Invoke-Native -Exe $AgentExe -Arguments @('service', 'install', '--config', $AgentConfigPath) -What 'agent service install' | Out-Null
    if (-not (Get-ServiceOrNull $script:AgentServiceName)) {
        throw "Service $script:AgentServiceName was not registered."
    }
    Write-Ok "$script:AgentServiceName registered (LocalSystem, automatic start)"

    if ($NoStart) {
        Write-Item "not started (-NoStart); start it with: & '$AgentExe' service start"
        return
    }
    Invoke-Native -Exe $AgentExe -Arguments @('service', 'start') -What 'agent service start' | Out-Null
    Wait-ServiceStatus -Name $script:AgentServiceName -Expected 'Running'
    Write-Ok "$script:AgentServiceName running"
}

function Install-NebulaService([string]$NebulaExe, [string]$NebulaConfigPath) {
    $existing = Find-NebulaServiceName -NebulaExe $NebulaExe
    if ($existing) {
        Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'stop') -What 'nebula service stop' -IgnoreFailure | Out-Null
        Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'uninstall') -What 'nebula service uninstall' -IgnoreFailure | Out-Null
    }
    Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'install', '-config', $NebulaConfigPath) -What 'nebula service install' | Out-Null

    $name = Find-NebulaServiceName -NebulaExe $NebulaExe
    if (-not $name) { throw 'The Nebula service was not registered.' }
    $script:NebulaServiceName = $name
    Write-Ok "$name registered with -config $NebulaConfigPath"

    if (-not (Test-Path -LiteralPath $NebulaConfigPath)) {
        Write-Note "$NebulaConfigPath does not exist yet - not starting Nebula. The agent writes it on its first successful poll."
        return
    }
    if ($NoStart) {
        Write-Item "not started (-NoStart); start it with: & '$NebulaExe' -service start"
        return
    }
    Invoke-Native -Exe $NebulaExe -Arguments @('-service', 'start') -What 'nebula service start' | Out-Null
    Wait-ServiceStatus -Name $name -Expected 'Running'
    Write-Ok "$name running"
}

function Add-NebulaFirewallRule([string]$NebulaExe) {
    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-Note 'NetSecurity cmdlets unavailable on this host; add the inbound UDP rule for nebula.exe yourself.'
        return
    }
    $existing = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
    if ($existing) { $existing | Remove-NetFirewallRule }
    New-NetFirewallRule -DisplayName $script:FirewallRuleName -Direction Inbound -Action Allow `
        -Program $NebulaExe -Protocol UDP -Profile Any | Out-Null
    Write-Ok 'inbound UDP firewall rule added for nebula.exe'
}

function Add-InstallDirToPath {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -and ($machinePath -split ';') -contains $InstallDir) { return }
    $updated = $InstallDir
    if ($machinePath) { $updated = "$machinePath;$InstallDir" }
    [Environment]::SetEnvironmentVariable('Path', $updated, 'Machine')
    Write-Ok "$InstallDir added to the machine PATH (visible in new shells)"
}

function Show-Summary {
    param(
        [string]$AgentExe,
        [string]$NebulaExe,
        [string]$AgentConfigPath,
        [string]$NebulaConfigPath,
        [bool]$NebulaInstalled
    )

    Write-Section 'Summary'
    Write-Item "binaries          $InstallDir"
    Write-Item "agent config      $AgentConfigPath"
    Write-Item "nebula config     $NebulaConfigPath"
    Write-Item "certificates      $NebulaDataDir"

    foreach ($name in @($script:AgentServiceName, $script:NebulaServiceName)) {
        $service = Get-ServiceOrNull $name
        if ($service) {
            Write-Item ('service {0,-18} {1}' -f $name, $service.Status)
        } else {
            Write-Item ('service {0,-18} not registered' -f $name)
        }
    }

    Write-Host ''
    Write-Item 'Useful commands:'
    Write-Item "  Get-Service $script:AgentServiceName, $script:NebulaServiceName"
    Write-Item "  Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='$script:AgentServiceName'} -MaxEvents 20"
    Write-Item "  & '$AgentExe' service restart"
    if ($NebulaInstalled) {
        Write-Item "  & '$NebulaExe' -config '$NebulaConfigPath' -test"
    }
}

# ------------------------------------------------------------------ main ----

function Invoke-Install {
    $arch = Get-HostArchitecture
    $agentArch = 'amd64'
    if ($arch -eq 'arm64') {
        Write-Note 'nebula-agent publishes no windows/arm64 build; installing the amd64 build (runs under x64 emulation).'
    } elseif ($arch -ne 'amd64') {
        throw "Unsupported architecture: $arch. Windows builds are published for amd64 (and arm64 for Nebula)."
    }
    $nebulaArch = 'amd64'
    if ($arch -eq 'arm64') { $nebulaArch = 'arm64' }

    if (-not $DownloadOnly) { Assert-Administrator }

    # ---- inputs -------------------------------------------------------
    $secureToken = $null
    $resolvedTokenFile = $null
    $wantsEnroll = (-not $SkipEnroll) -and (-not $DownloadOnly)

    if ($wantsEnroll) {
        if (-not $ServerUrl) {
            Write-Section 'Management server'
            $ServerUrl = Read-RequiredValue '    Server URL (e.g. https://mgmt.example.com:8080)'
        }
        Assert-ServerUrl $ServerUrl

        if ($TokenFile) {
            if (-not (Test-Path -LiteralPath $TokenFile)) { throw "Token file not found: $TokenFile" }
            $resolvedTokenFile = (Resolve-Path -LiteralPath $TokenFile).Path
        } elseif ($Token) {
            $secureToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
        } else {
            if ($Unattended) { throw 'An enrollment token is required: pass -TokenFile or -Token, or use -SkipEnroll.' }
            Write-Section 'Enrollment token'
            Write-Item 'Single-use token from the management server. It is not echoed.'
            while ($true) {
                $secureToken = Read-Host '    Token' -AsSecureString
                if ($secureToken.Length -gt 0) { break }
            }
        }
    }

    # Check the address before downloading 20+ MB and before the single-use
    # token is spent: a mistyped URL should fail in seconds, saying so.
    if ($wantsEnroll) {
        Write-Section 'Checking the management server'
        [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Assert-ManagementServerReachable $ServerUrl
    }

    $selectedServices = $Services
    if ((-not $DownloadOnly) -and (-not $PSBoundParameters.ContainsKey('Services')) -and (-not $Unattended)) {
        $selectedServices = Read-ServiceSelection
    }
    if ($SkipNebula -and $selectedServices -eq 'Nebula') {
        throw '-SkipNebula and -Services Nebula are mutually exclusive.'
    }

    # ---- download -----------------------------------------------------
    $workDir = Join-Path ([IO.Path]::GetTempPath()) ('nebula-mesh-install-' + [Guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null

    try {
        Write-Section 'Downloading packages'
        [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        if ($AgentZip) {
            if (-not (Test-Path -LiteralPath $AgentZip)) { throw "Agent archive not found: $AgentZip" }
            $agentArchive = (Resolve-Path -LiteralPath $AgentZip).Path
            Write-Item "agent: using local archive $agentArchive"
        } else {
            $agentArchive = Get-VerifiedArchive -Repo $AgentRepo -Version $AgentVersion `
                -AssetPattern "(?i)^nebula-agent_.*_windows_$agentArch\.zip$" `
                -WorkDir $workDir -Label 'agent'
        }

        $nebulaArchive = $null
        if (-not $SkipNebula) {
            if ($NebulaZip) {
                if (-not (Test-Path -LiteralPath $NebulaZip)) { throw "Nebula archive not found: $NebulaZip" }
                $nebulaArchive = (Resolve-Path -LiteralPath $NebulaZip).Path
                Write-Item "nebula: using local archive $nebulaArchive"
            } else {
                $nebulaArchive = Get-VerifiedArchive -Repo $NebulaRepo -Version $NebulaVersion `
                    -AssetPattern "(?i)^nebula-windows-$nebulaArch\.zip$" `
                    -WorkDir $workDir -Label 'nebula'
            }
        }

        if ($DownloadOnly) {
            New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
            $stageRoot = (Resolve-Path -LiteralPath $StageDir).Path
            $staged = @()
            foreach ($archive in @($agentArchive, $nebulaArchive)) {
                if (-not $archive) { continue }
                $destination = Join-Path $stageRoot (Split-Path -Leaf $archive)
                Copy-Item -LiteralPath $archive -Destination $destination -Force
                $staged += $destination
            }
            Write-Section 'Downloaded (nothing installed)'
            foreach ($path in $staged) { Write-Item $path }
            Write-Item 'Install offline with -AgentZip / -NebulaZip.'
            return
        }

        # ---- install ---------------------------------------------------
        Write-Section 'Installing files'
        New-Item -ItemType Directory -Force -Path $InstallDir, $AgentDataDir, $NebulaDataDir | Out-Null

        # An earlier run can leave files that cannot be overwritten. Recover
        # before touching them rather than failing halfway through the copy.
        foreach ($path in @($InstallDir, $AgentDataDir, $NebulaDataDir)) {
            Restore-TreeAccess $path
        }

        $agentExe = Install-AgentBinaries -Archive $agentArchive -WorkDir $workDir
        $nebulaExe = Join-Path $InstallDir 'nebula.exe'
        if (-not $SkipNebula) {
            $nebulaExe = Install-NebulaBinaries -Archive $nebulaArchive -WorkDir $workDir -Arch $nebulaArch
        }

        Write-Section 'Hardening permissions'
        # Both services run as LocalSystem: a binary or config writable by a
        # normal user would be a local privilege-escalation path.
        foreach ($path in @($InstallDir, $AgentDataDir, $NebulaDataDir)) {
            Protect-Tree $path
            Write-Ok "$path locked to SYSTEM + Administrators"
        }

        Assert-Readable $agentExe
        if (-not $SkipNebula) { Assert-Readable $nebulaExe }
        # Launch it once for real: the binary has to be executable, not just
        # readable, before anything downstream depends on it.
        $reported = & $agentExe version
        if ($LASTEXITCODE -ne 0) { throw "agent smoke check failed (exit $LASTEXITCODE)." }
        Write-Ok "binaries executable after hardening ($($reported -join ' '))"

        $agentConfigPath = Join-Path $AgentDataDir 'agent.yml'
        $nebulaConfigPath = Join-Path $NebulaDataDir 'config.yml'

        # ---- enrollment ------------------------------------------------
        if ($wantsEnroll) {
            Write-Section 'Enrolling host'
            if ((Test-Path -LiteralPath $agentConfigPath) -and (-not $Force)) {
                Write-Note "$agentConfigPath already exists - keeping the current enrollment (use -Force to re-enroll)."
            } else {
                Invoke-AgentEnroll -AgentExe $agentExe -AgentConfigPath $agentConfigPath `
                    -SecureToken $secureToken -ExistingTokenFile $resolvedTokenFile
            }
        } else {
            Write-Section 'Enrollment skipped'
            Write-Item 'Enroll later with:'
            Write-Item "  & '$agentExe' enroll --server <url> --token-file <file> --config '$agentConfigPath' --data-dir '$NebulaDataDir'"
            Write-Item 'The agent stays in idle standby and picks it up within ~10s - no restart needed.'
        }

        # The reload hook is only useful when a Nebula service actually exists:
        # the one this run is about to register, or one already on the host
        # (-SkipNebula, or an agent-only install alongside a managed Nebula).
        $reloadService = Find-NebulaServiceName -NebulaExe $nebulaExe
        if ((-not $SkipNebula) -and ($selectedServices -in @('Both', 'Nebula'))) {
            $reloadService = $script:NebulaServiceName
        }
        if ($reloadService) {
            Set-AgentReloadCommand -AgentConfigPath $agentConfigPath -NebulaService $reloadService
        } else {
            Write-Note 'no Nebula service on this host - leaving nebula_reload_command unset; restart Nebula yourself after config updates.'
        }

        # ---- services --------------------------------------------------
        Write-Section 'Services'
        if ($selectedServices -eq 'None') {
            Write-Item 'nothing registered (-Services None)'
            # An upgrade that had to stop a running service puts it back.
            if ($script:NebulaServiceWasStopped -and -not $NoStart) {
                Invoke-Native -Exe $nebulaExe -Arguments @('-service', 'start') -What 'nebula service start' -IgnoreFailure | Out-Null
            }
            if ($script:AgentServiceWasStopped -and -not $NoStart) {
                Invoke-Native -Exe $agentExe -Arguments @('service', 'start') -What 'agent service start' -IgnoreFailure | Out-Null
            }
        } else {
            if (($selectedServices -in @('Both', 'Nebula')) -and (-not $SkipNebula)) {
                Install-NebulaService -NebulaExe $nebulaExe -NebulaConfigPath $nebulaConfigPath
            }
            if ($selectedServices -in @('Both', 'Agent')) {
                Install-AgentService -AgentExe $agentExe -AgentConfigPath $agentConfigPath
            }
            # Whichever half this run did not re-register but did have to stop
            # for the upgrade goes back to running.
            if ($script:NebulaServiceWasStopped -and ($selectedServices -eq 'Agent') -and -not $NoStart) {
                Invoke-Native -Exe $nebulaExe -Arguments @('-service', 'start') -What 'nebula service start' -IgnoreFailure | Out-Null
            }
            if ($script:AgentServiceWasStopped -and ($selectedServices -eq 'Nebula') -and -not $NoStart) {
                Invoke-Native -Exe $agentExe -Arguments @('service', 'start') -What 'agent service start' -IgnoreFailure | Out-Null
            }
        }

        if ($AddFirewallRule -and (-not $SkipNebula)) {
            Write-Section 'Firewall'
            Add-NebulaFirewallRule -NebulaExe $nebulaExe
        }
        if ($AddToPath) { Add-InstallDirToPath }

        Show-Summary -AgentExe $agentExe -NebulaExe $nebulaExe `
            -AgentConfigPath $agentConfigPath -NebulaConfigPath $nebulaConfigPath `
            -NebulaInstalled (-not $SkipNebula)
    } finally {
        if (Test-Path -LiteralPath $workDir) {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host 'Nebula Mesh - Windows installer' -ForegroundColor Cyan

try {
    if ($Uninstall) {
        Invoke-Uninstall
    } else {
        Invoke-Install
        if (-not $DownloadOnly) { Write-Section 'Done' }
    }
} catch {
    # Report the classified explanation rather than letting PowerShell print
    # the raw error record, which says where the script stopped but not what
    # the operator should do about it.
    Write-Failure $_.Exception.Message
    exit 1
}
