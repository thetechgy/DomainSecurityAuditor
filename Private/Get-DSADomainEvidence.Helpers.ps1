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
