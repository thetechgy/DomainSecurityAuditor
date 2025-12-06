<#
.SYNOPSIS
    Determine DKIM selector status relative to a specific check.
.DESCRIPTION
    Evaluates selector health based on presence, key length, TTL, and validity for a given DKIM check Id.
.PARAMETER Selector
    Selector object containing DNS lookup results.
.PARAMETER Check
    Baseline check definition driving evaluation.
#>
function Get-DSADkimSelectorStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Selector,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check
    )

    $found = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('DkimRecordExists', 'Found') -Default $true -As ([bool])
    $keyLength = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('KeyLength') -Default $null
    $ttl = Get-DSATtlValue -InputObject $Selector
    $validPublicKey = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('ValidPublicKey', 'IsValid') -Default $null
    $validRsaKeyLength = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('ValidRsaKeyLength') -Default $null

    $isValid = [bool]((($null -eq $validPublicKey) -or $validPublicKey) -and (($null -eq $validRsaKeyLength) -or $validRsaKeyLength))
    $weakKey = Get-DSAPropertyValue -InputObject $Selector -PropertyName @('WeakKey') -Default $false -As ([bool])

    switch ($Check.Id) {
        'DKIMSelectorPresence' {
            return $(if ($found) { 'Pass' } else { 'Fail' })
        }
        'DKIMKeyStrength' {
            $min = if ($Check.PSObject.Properties.Name -contains 'ExpectedValue' -and $Check.ExpectedValue) { $Check.ExpectedValue } else { $script:DSAMinDkimKeyLength }
            $passesKey = ($keyLength -as [int]) -ge $min -and -not $weakKey
            return $(if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' })
        }
        'DKIMSelectorHealth' {
            $min = $script:DSAMinDkimKeyLength
            $passesKey = ($keyLength -as [int]) -ge $min -and -not $weakKey
            return $(if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' })
        }
        'DKIMTtl' {
            $min = $null
            $max = $null
            if ($Check.PSObject.Properties.Name -contains 'ExpectedValue' -and $Check.ExpectedValue) {
                $min = $Check.ExpectedValue.Min
                $max = $Check.ExpectedValue.Max
            }
            $ttlNumber = $ttl -as [int]
            $passTtl = ($ttlNumber -and $min -and $max -and $ttlNumber -ge $min -and $ttlNumber -le $max)
            return $(if ($passTtl) { 'Pass' } else { 'Fail' })
        }
        default {
            return $(if ($found -and $isValid -and -not $weakKey) { 'Pass' } else { 'Fail' })
        }
    }
}

<#
.SYNOPSIS
    Compute effective DKIM check status considering selector breakdowns.
.DESCRIPTION
    Overrides the base check status with selector-level results when applicable to ensure failures/warnings propagate correctly.
.PARAMETER Check
    Baseline check result to adjust.
.PARAMETER Selectors
    Selector details associated with the domain evidence.
#>
function Get-DSADkimEffectiveStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check,

        [pscustomobject[]]$Selectors
    )

    $effectiveStatus = $Check.Status
    if ($Selectors -and $Check.Area -eq 'DKIM' -and ($Check.Id -in @('DKIMKeyStrength', 'DKIMTtl', 'DKIMSelectorHealth', 'DKIMSelectorPresence'))) {
        $selectorStatuses = @($Selectors | ForEach-Object { Get-DSADkimSelectorStatus -Selector $_ -Check $Check })
        if ($selectorStatuses -contains 'Fail') {
            $effectiveStatus = 'Fail'
        }
        elseif ($selectorStatuses -contains 'Warning') {
            $effectiveStatus = 'Warning'
        }
        elseif ($selectorStatuses -contains 'Pass') {
            $effectiveStatus = 'Pass'
        }
    }

    return $effectiveStatus
}

<#
.SYNOPSIS
    Produce effective check results with DKIM selector awareness.
.DESCRIPTION
    Clones incoming checks and recalculates DKIM statuses based on selector details, returning a new array of results.
.PARAMETER Checks
    Baseline check results to process.
.PARAMETER SelectorDetails
    Optional DKIM selector detail collection to incorporate.
#>
function Get-DSAEffectiveChecks {
    [CmdletBinding()]
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

        $effectiveStatus = $clone.Status
        if ($SelectorDetails -and $clone.PSObject -and $clone.PSObject.Properties.Name -contains 'Area' -and $clone.Area -eq 'DKIM') {
            $effectiveStatus = Get-DSADkimEffectiveStatus -Check $clone -Selectors $SelectorDetails
        }

        if ($clone.PSObject) {
            $clone | Add-Member -NotePropertyName 'Status' -NotePropertyValue $effectiveStatus -Force
        }

        $null = $results.Add($clone)
    }

    return $results.ToArray()
}

