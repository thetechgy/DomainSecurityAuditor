<#
.SYNOPSIS
    Installs a specific version of PowerShell on GitHub Actions runners.

.DESCRIPTION
    Cross-platform script that installs a specific minor version of PowerShell
    (e.g., 7.4, 7.5) by querying GitHub releases and installing the latest patch.

.PARAMETER Version
    The PowerShell minor version to install (e.g., "7.4" or "7.5").

.EXAMPLE
    ./Install-PowerShellVersion.ps1 -Version '7.4'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+$')]
    [string]$Version
)

$ErrorActionPreference = 'Stop'

function Get-LatestPatchVersion {
    param([string]$MinorVersion)

    Write-Host "Querying GitHub API for PowerShell releases..."
    $releasesUrl = 'https://api.github.com/repos/PowerShell/PowerShell/releases'
    $headers = @{ 'User-Agent' = 'GitHub-Actions-PowerShell-Installer' }

    try {
        $releases = Invoke-RestMethod -Uri $releasesUrl -Headers $headers -TimeoutSec 30
    }
    catch {
        throw "Failed to query GitHub releases API: $_"
    }

    # Find the latest stable release matching the minor version
    $targetPattern = "^v$MinorVersion\.\d+$"
    $matchingRelease = $releases |
        Where-Object { -not $_.prerelease -and $_.tag_name -match $targetPattern } |
        Sort-Object -Property { [Version]($_.tag_name -replace '^v', '') } -Descending |
        Select-Object -First 1

    if (-not $matchingRelease) {
        throw "No stable release found for PowerShell $MinorVersion"
    }

    $fullVersion = $matchingRelease.tag_name -replace '^v', ''
    Write-Host "Found latest patch version: $fullVersion"
    return @{
        Version = $fullVersion
        Assets  = $matchingRelease.assets
    }
}

function Get-InstalledPwshVersion {
    try {
        $pwshPath = Get-Command pwsh -ErrorAction SilentlyContinue
        if ($pwshPath) {
            $versionOutput = & pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
            return $versionOutput.Trim()
        }
    }
    catch {
        # pwsh not found or error getting version
    }
    return $null
}

function Install-PowerShellLinux {
    param($ReleaseInfo)

    $version = $ReleaseInfo.Version
    $assets = $ReleaseInfo.Assets

    # Find the .deb package for amd64
    $debAsset = $assets | Where-Object { $_.name -match "powershell_$version.*deb_amd64\.deb$" }
    if (-not $debAsset) {
        # Try alternate naming pattern
        $debAsset = $assets | Where-Object { $_.name -match "powershell.*$version.*amd64\.deb$" }
    }

    if (-not $debAsset) {
        throw "Could not find .deb package for PowerShell $version"
    }

    $downloadUrl = $debAsset.browser_download_url
    $tempPath = Join-Path $env:RUNNER_TEMP "powershell-$version.deb"

    Write-Host "Downloading: $($debAsset.name)"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -TimeoutSec 120

    Write-Host "Installing PowerShell $version..."
    # Use bash to run sudo commands
    $installScript = @"
sudo dpkg -i '$tempPath' || true
sudo apt-get install -f -y
"@
    bash -c $installScript

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PowerShell package"
    }

    Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
}

function Install-PowerShellWindows {
    param($ReleaseInfo)

    $version = $ReleaseInfo.Version
    $assets = $ReleaseInfo.Assets

    # Find the .msi package for x64
    $msiAsset = $assets | Where-Object { $_.name -match "PowerShell-$version-win-x64\.msi$" }

    if (-not $msiAsset) {
        throw "Could not find .msi package for PowerShell $version"
    }

    $downloadUrl = $msiAsset.browser_download_url
    $tempPath = Join-Path $env:RUNNER_TEMP "PowerShell-$version-win-x64.msi"

    Write-Host "Downloading: $($msiAsset.name)"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -TimeoutSec 120

    Write-Host "Installing PowerShell $version..."
    $msiArgs = @(
        '/package', $tempPath
        '/quiet'
        '/norestart'
        'ADD_PATH=1'
    )
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw "MSI installation failed with exit code: $($process.ExitCode)"
    }

    Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue

    # Update PATH for current session
    $pwshPath = "C:\Program Files\PowerShell\$($version.Split('.')[0])"
    if (Test-Path $pwshPath) {
        $env:PATH = "$pwshPath;$env:PATH"
        Write-Host "Added $pwshPath to PATH"
    }
}

# Main execution
Write-Host "=== PowerShell Version Installer ==="
Write-Host "Requested version: $Version"

# Check if already installed
$currentVersion = Get-InstalledPwshVersion
if ($currentVersion -and $currentVersion.StartsWith($Version)) {
    Write-Host "PowerShell $currentVersion is already installed (matches requested $Version.x)"
    exit 0
}

# Get latest patch version
$releaseInfo = Get-LatestPatchVersion -MinorVersion $Version

# Install based on platform
if ($IsLinux) {
    Install-PowerShellLinux -ReleaseInfo $releaseInfo
}
elseif ($IsWindows) {
    Install-PowerShellWindows -ReleaseInfo $releaseInfo
}
else {
    throw "Unsupported platform. This script supports Linux and Windows only."
}

# Verify installation
Write-Host "Verifying installation..."
$newVersion = Get-InstalledPwshVersion
if ($newVersion) {
    Write-Host "PowerShell $newVersion installed successfully"
}
else {
    Write-Warning "Could not verify PowerShell version after installation"
}
