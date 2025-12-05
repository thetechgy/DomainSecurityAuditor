function Invoke-DSADomainDetectiveHealth {
<#
.SYNOPSIS
    Wraps DomainDetective Test-DDDomainOverallHealth to centralize warning capture.
.DESCRIPTION
    Executes the DomainDetective health check with supplied parameters, collecting warnings
    and returning both the raw result and any emitted warnings. This wrapper simplifies mocking
    and error handling within DomainSecurityAuditor.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Parameters
    )

    $invocationParams = $Parameters.Clone()
    $invocationParams['WarningVariable'] = 'localWarnings'
    if (-not $invocationParams.ContainsKey('WarningAction')) {
        $invocationParams['WarningAction'] = 'SilentlyContinue'
    }

    $localWarnings = @()

    $result = Test-DDDomainOverallHealth @invocationParams

    return [pscustomobject]@{
        Result   = $result
        Warnings = @($localWarnings)
    }
}
