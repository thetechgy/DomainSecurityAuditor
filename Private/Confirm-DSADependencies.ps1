<#
.SYNOPSIS
    Validate required modules and optionally install missing dependencies.
.DESCRIPTION
    Uses Test-DSADependency to verify required modules are available, attempts installation when requested, and throws when unmet.
.PARAMETER Name
    Names of modules to validate.
.PARAMETER AttemptInstallation
    Attempt to install missing modules via Install-Module.
.PARAMETER LogFile
    Path to the log file for diagnostic messages.
#>
function Confirm-DSADependencies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [switch]$AttemptInstallation,

        [string]$LogFile
    )

    $dependencyResult = Test-DSADependency -Name $Name -AttemptInstallation:$AttemptInstallation -LogFile $LogFile
    if (-not $dependencyResult.IsCompliant) {
        $missing = $dependencyResult.MissingModules -join ', '
        if ($LogFile) {
            Write-DSALog -Message "Missing dependencies: $missing" -LogFile $LogFile -Level 'ERROR'
        }
        throw "Missing dependencies: $missing"
    }
}

<#
.SYNOPSIS
    Ensure the DomainDetective module is imported once per session.
.DESCRIPTION
    Imports DomainDetective when not already loaded and caches state to avoid redundant imports, logging failures when provided a log path.
.PARAMETER LogFile
    Path to the log file for error reporting.
#>
function Import-DSADomainDetectiveModule {
    [CmdletBinding()]
    param (
        [string]$LogFile
    )

    if (-not (Get-Variable -Name DSADomainDetectiveLoaded -Scope Script -ErrorAction SilentlyContinue)) {
        $script:DSADomainDetectiveLoaded = $false
    }

    if ($script:DSADomainDetectiveLoaded) {
        return
    }

    try {
        if (-not (Get-Module -Name DomainDetective -ErrorAction SilentlyContinue)) {
            $null = Import-Module -Name DomainDetective -ErrorAction Stop
        }
        $script:DSADomainDetectiveLoaded = $true
    }
    catch {
        $message = "DomainDetective module import failed: $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }
}
