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
            Import-Module -Name DomainDetective -ErrorAction Stop | Out-Null
        }
        $script:DSADomainDetectiveLoaded = $true
    } catch {
        $message = "DomainDetective module import failed: $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }
}
