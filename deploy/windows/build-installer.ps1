<#
.SYNOPSIS
    Compiles nebula-mesh-setup.iss into a graphical Windows installer.

.DESCRIPTION
    Requires Inno Setup 6 (https://jrsoftware.org/isdl.php):

        winget install --id JRSoftware.InnoSetup

    The resulting setup.exe downloads Nebula and nebula-agent at install time,
    so the build machine needs no release artifacts.

.EXAMPLE
    .\build-installer.ps1

    Builds dist\windows-installer\nebula-mesh-setup-<version>.exe, pinned to
    nothing: the installed host resolves "latest" for both packages.

.EXAMPLE
    .\build-installer.ps1 -Version 0.14.0 -AgentVersion v0.14.0 -NebulaVersion v1.11.1

    Builds an installer that always deploys those exact releases.
#>
[CmdletBinding()]
param(
    # Version stamped on the installer itself (Add/Remove Programs, filename).
    [string]$Version,

    # nebula-agent release the built installer deploys: "latest" or a tag.
    [string]$AgentVersion = 'latest',

    # Nebula release the built installer deploys: "latest" or a tag.
    [string]$NebulaVersion = 'latest',

    # Inno Setup compiler. Auto-detected when omitted.
    [string]$Iscc
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Find-Iscc {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw 'ISCC.exe not found. Install Inno Setup 6: winget install --id JRSoftware.InnoSetup'
}

# Falls back to the newest agent release so the installer carries a meaningful
# version even when the caller does not pass one.
function Resolve-DefaultVersion {
    try {
        $release = Invoke-RestMethod -UseBasicParsing `
            -Uri 'https://api.github.com/repos/forgekeep/nebula-mesh/releases/latest' `
            -Headers @{ 'User-Agent' = 'build-installer.ps1' }
        return ($release.tag_name -replace '^v', '')
    } catch {
        return '0.0.0-dev'
    }
}

if (-not $Iscc) { $Iscc = Find-Iscc }
if (-not $Version) { $Version = Resolve-DefaultVersion }

# Windows' file-version resource only accepts digits, so a pre-release tag
# (0.14.0-rc1) cannot go in verbatim. Ship the numeric core there and keep the
# full string as the displayed AppVersion.
$versionInfo = if ($Version -match '^\d+(\.\d+){0,3}') { $Matches[0] } else { '0.0.0' }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$issPath = Join-Path $scriptDir 'nebula-mesh-setup.iss'
$outputDir = Join-Path (Split-Path -Parent (Split-Path -Parent $scriptDir)) 'dist\windows-installer'

Write-Host "compiler       $Iscc"
Write-Host "version        $Version"
Write-Host "agent release  $AgentVersion"
Write-Host "nebula release $NebulaVersion"
Write-Host "file version   $versionInfo"
Write-Host ''

& $Iscc "/DAppVersion=$Version" "/DVersionInfo=$versionInfo" `
    "/DAgentVersion=$AgentVersion" "/DNebulaVersion=$NebulaVersion" $issPath
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)." }

$artifact = Join-Path $outputDir "nebula-mesh-setup-$Version.exe"
if (-not (Test-Path -LiteralPath $artifact)) { throw "Expected artifact not produced: $artifact" }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
$size = [Math]::Round((Get-Item -LiteralPath $artifact).Length / 1KB)

Write-Host ''
Write-Host "built  $artifact ($size KB)" -ForegroundColor Green
Write-Host "sha256 $hash"
