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

    $minValue = $null
    foreach ($value in @($Values)) {
        $converted = $value -as [int]
        if ($converted -and $converted -gt 0) {
            if ($null -eq $minValue -or $converted -lt $minValue) {
                $minValue = $converted
            }
        }
    }

    return $minValue
}

function Get-DSAClassificationFromHealth {
    <#
    .SYNOPSIS
        Extract classification from health data.
    .DESCRIPTION
        Searches Classification, MailClassification, and MailDomainClassification properties
        in order and returns the first non-empty value found.
    .PARAMETER HealthData
        Health data object from DomainDetective.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [pscustomobject]$HealthData
    )

    if (-not $HealthData) {
        return $null
    }

    $propertyNames = @('Classification', 'MailClassification', 'MailDomainClassification')
    foreach ($name in $propertyNames) {
        if ($HealthData.PSObject -and $HealthData.PSObject.Properties.Name -contains $name) {
            $val = $HealthData.$name
            if ($val -and -not [string]::IsNullOrWhiteSpace("$val")) {
                return "$val".Trim()
            }
        }
    }

    return $null
}

function Get-DSADkimAnalysisResult {
    <#
    .SYNOPSIS
        Process DKIM analysis into standardized output.
    .DESCRIPTION
        Extracts DKIM selector information from analysis results and returns a structured object
        containing selector lists, key lengths, and weak selector counts.
    .PARAMETER DkimAnalysis
        DKIM analysis object from DomainDetective.
    .PARAMETER MinKeyLength
        Minimum acceptable DKIM key length. Defaults to module-scope DSAMinDkimKeyLength.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [pscustomobject]$DkimAnalysis,

        [int]$MinKeyLength = 1024
    )

    # Use module-scope variable if available
    if ((Get-Variable -Name DSAMinDkimKeyLength -Scope Script -ErrorAction SilentlyContinue)) {
        $MinKeyLength = $script:DSAMinDkimKeyLength
    }

    $dkimList = [System.Collections.Generic.List[object]]::new()
    $dkimFound = [System.Collections.Generic.List[object]]::new()

    if ($DkimAnalysis -and $DkimAnalysis.AnalysisResults) {
        foreach ($entry in $DkimAnalysis.AnalysisResults.GetEnumerator()) {
            $selectorName = $entry.Key
            $analysisResult = $entry.Value
            if ($analysisResult -and -not ($analysisResult.PSObject.Properties.Name -contains 'Selector')) {
                $analysisResult | Add-Member -MemberType NoteProperty -Name 'Selector' -Value $selectorName -Force
            }
            if ($analysisResult) {
                $null = $dkimList.Add($analysisResult)
                if ($analysisResult.DkimRecordExists) {
                    $null = $dkimFound.Add($analysisResult)
                }
            }
        }
    }

    $dkimSelectors = @($dkimFound | ForEach-Object { $_.Selector })
    $dkimMinKey = $null
    if ($dkimFound.Count -gt 0) {
        $keyValues = @($dkimFound | ForEach-Object { $_.KeyLength } | Where-Object { $_ })
        if ($keyValues) {
            $dkimMinKey = ($keyValues | Measure-Object -Minimum).Minimum
        }
    }

    $dkimWeakCount = 0
    foreach ($selector in $dkimList) {
        if (-not $selector.DkimRecordExists -or
            -not $selector.ValidPublicKey -or
            -not $selector.ValidRsaKeyLength -or
            $selector.WeakKey -or
            (($selector.KeyLength -as [int]) -lt $MinKeyLength)) {
            $dkimWeakCount++
        }
    }

    return [pscustomobject]@{
        DkimList      = @($dkimList)
        DkimFound     = @($dkimFound)
        DkimSelectors = $dkimSelectors
        DkimMinKey    = $dkimMinKey
        DkimWeakCount = $dkimWeakCount
    }
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
