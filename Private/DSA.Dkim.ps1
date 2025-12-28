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
            if ($analysisResult -and -not (Test-DSAProperty -InputObject $analysisResult -Name 'Selector')) {
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

<#
.SYNOPSIS
    Evaluate DKIM selector status for a specific check.
.DESCRIPTION
    Determines pass/fail status for a single selector based on the check type (presence, key strength, TTL).
    Returns a hashtable with Status and metadata for the selector.
.PARAMETER Selector
    Selector object containing DNS lookup results.
.PARAMETER Check
    Baseline check definition driving evaluation.
.OUTPUTS
    Hashtable with Selector name, Status, and relevant metadata (KeyLength, Ttl, Found).
#>
function Get-DSADkimSelectorStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Selector,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check
    )

    $selectorName = if (Test-DSAProperty -InputObject $Selector -Name 'Name') { $Selector.Name } else { $Selector.Selector }
    $found = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('DkimRecordExists', 'Found') -Default $true -As ([bool])
    $keyLength = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('KeyLength') -Default $null
    $ttl = Get-DSATtlValue -InputObject $Selector
    $validPublicKey = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('ValidPublicKey', 'IsValid') -Default $null
    $validRsaKeyLength = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('ValidRsaKeyLength') -Default $null
    $isValid = [bool]((($null -eq $validPublicKey) -or $validPublicKey) -and (($null -eq $validRsaKeyLength) -or $validRsaKeyLength))
    $weakKey = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('WeakKey') -Default $false -As ([bool])

    $status = switch ($Check.Id) {
        'DKIMSelectorPresence' {
            if ($found) { 'Pass' } else { 'Fail' }
        }
        { $_ -in @('DKIMKeyStrength', 'DKIMSelectorHealth') } {
            $min = if ((Test-DSAProperty -InputObject $Check -Name 'ExpectedValue') -and $Check.ExpectedValue) {
                $Check.ExpectedValue
            }
            else {
                $script:DSAMinDkimKeyLength
            }
            $passesKey = ($keyLength -as [int]) -ge $min -and -not $weakKey
            if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' }
        }
        'DKIMTtl' {
            $min = $null
            $max = $null
            if ((Test-DSAProperty -InputObject $Check -Name 'ExpectedValue') -and $Check.ExpectedValue) {
                $min = $Check.ExpectedValue.Min
                $max = $Check.ExpectedValue.Max
            }
            $ttlNumber = $ttl -as [int]
            $passTtl = ($ttlNumber -and $min -and $max -and $ttlNumber -ge $min -and $ttlNumber -le $max)
            if ($passTtl) { 'Pass' } else { 'Fail' }
        }
        default {
            if ($found -and $isValid -and -not $weakKey) { 'Pass' } else { 'Fail' }
        }
    }

    return @{
        Selector  = $selectorName
        Status    = $status
        Found     = $found
        KeyLength = $keyLength
        Ttl       = $ttl
    }
}

<#
.SYNOPSIS
    Compute DKIM check results with selector-level breakdown.
.DESCRIPTION
    Evaluates all selectors for a DKIM check and returns the effective status plus per-selector results.
    This is the single point of DKIM status calculation - results should be cached on the check object.
.PARAMETER Check
    Baseline check result to evaluate.
.PARAMETER Selectors
    Selector details from domain evidence.
.OUTPUTS
    Hashtable with EffectiveStatus and SelectorStatuses array.
#>
function Get-DSADkimCheckResult {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check,

        [pscustomobject[]]$Selectors
    )

    $baseStatus = $Check.Status
    $selectorStatuses = @()

    # Only process DKIM-specific checks with selectors
    if ($Selectors -and $Check.Area -eq 'DKIM' -and ($Check.Id -in @('DKIMKeyStrength', 'DKIMTtl', 'DKIMSelectorHealth', 'DKIMSelectorPresence'))) {
        $selectorStatuses = @($Selectors | ForEach-Object {
            Get-DSADkimSelectorStatus -Selector $_ -Check $Check
        })

        # Determine effective status from selector results
        $statuses = @($selectorStatuses | ForEach-Object { $_.Status })
        if ($statuses -contains 'Fail') {
            $baseStatus = 'Fail'
        }
        elseif ($statuses -contains 'Warning') {
            $baseStatus = 'Warning'
        }
        elseif ($statuses -contains 'Pass') {
            $baseStatus = 'Pass'
        }
    }

    return @{
        EffectiveStatus  = $baseStatus
        SelectorStatuses = $selectorStatuses
    }
}

<#
.SYNOPSIS
    Apply DKIM selector awareness to check results, caching computed values.
.DESCRIPTION
    Processes checks and attaches pre-computed DKIM selector statuses to each DKIM check.
    Non-DKIM checks pass through unchanged. Returns checks with Status updated and
    SelectorStatuses property added for DKIM checks.
.PARAMETER Checks
    Baseline check results to process.
.PARAMETER SelectorDetails
    Optional DKIM selector detail collection.
.OUTPUTS
    Array of check objects with DKIM results pre-computed.
#>
function Get-DSAEffectiveChecks {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        $Checks = @(),

        [pscustomobject[]]$SelectorDetails
    )

    if (-not $Checks) {
        return @()
    }

    $checkList = @($Checks | Where-Object { $_ })
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($check in $checkList) {
        $clone = if ($check.PSObject) { $check.PSObject.Copy() } else { $check }
        if (-not $clone) {
            continue
        }

        # Check if already processed (has SelectorStatuses)
        if ($SelectorDetails -and (Test-DSAProperty -InputObject $clone -Name 'Area') -and $clone.Area -eq 'DKIM') {
            if (-not (Test-DSAProperty -InputObject $clone -Name 'SelectorStatuses')) {
                $dkimResult = Get-DSADkimCheckResult -Check $clone -Selectors $SelectorDetails
                if ($clone.PSObject) {
                    $clone | Add-Member -NotePropertyName 'Status' -NotePropertyValue $dkimResult.EffectiveStatus -Force
                    $clone | Add-Member -NotePropertyName 'SelectorStatuses' -NotePropertyValue $dkimResult.SelectorStatuses -Force
                }
            }
        }

        $null = $results.Add($clone)
    }

    return [object[]]$results.ToArray()
}
