<#
.SYNOPSIS
    Construct a standardized domain evidence object.
.DESCRIPTION
    Wraps the collected domain evidence with domain name and classification for baseline evaluation.
.PARAMETER Domain
    Domain name associated with the evidence.
.PARAMETER Classification
    DomainDetective classification for the domain.
.PARAMETER Records
    Evidence payload containing protocol-specific data.
#>
function New-DSADomainEvidenceObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Classification,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Records
    )

    return [pscustomobject]@{
        Domain         = $Domain
        Classification = $Classification
        Records        = $Records
    }
}

function Get-DSAMinPositiveTtl {
    <#
    .SYNOPSIS
        Return the smallest positive TTL from a collection.
    .DESCRIPTION
        Iterates values, converts to integers, and returns the minimum positive entry or null.
    .PARAMETER Values
        Collection of TTL-like values to evaluate.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        $Values
    )

    $positives = @()
    foreach ($value in @($Values)) {
        $converted = $value -as [int]
        if ($converted -and $converted -gt 0) {
            $positives += $converted
        }
    }

    if ($positives.Count -gt 0) {
        return ($positives | Measure-Object -Minimum).Minimum
    }

    return $null
}

function Resolve-DSATtl {
    <#
    .SYNOPSIS
        Resolve an authoritative TTL with resolver fallback and optional logging.
    .DESCRIPTION
        Chooses the minimum positive authoritative TTL when present; otherwise returns the provided resolver TTL while logging fallback.
    .PARAMETER AuthoritativeValues
        Collection of authoritative TTL values to evaluate.
    .PARAMETER ResolverTtl
        Resolver TTL value to use when authoritative values are absent.
    .PARAMETER RecordLabel
        Label used in log messages for clarity.
    .PARAMETER LogFile
        Optional log file path for debug messages.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        $AuthoritativeValues,
        $ResolverTtl,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RecordLabel = 'record',

        [string]$LogFile
    )

    $authoritativeTtl = Get-DSAMinPositiveTtl -Values $AuthoritativeValues
    if ($null -ne $authoritativeTtl) {
        if ($LogFile) {
            Write-DSALog -Message ("Using authoritative {0} TTL {1}" -f $RecordLabel, $authoritativeTtl) -LogFile $LogFile -Level 'DEBUG'
        }
        return $authoritativeTtl
    }

    if ($LogFile) {
        Write-DSALog -Message ("Authoritative {0} TTL unavailable; falling back to resolver TTL." -f $RecordLabel) -LogFile $LogFile -Level 'DEBUG'
    }

    return $ResolverTtl
}
