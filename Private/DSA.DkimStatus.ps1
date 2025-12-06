function Get-DSADkimSelectorStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Selector,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check
    )

    $found = [bool]$Selector.DkimRecordExists
    $keyLength = $Selector.KeyLength
    $ttl = $Selector.DnsRecordTtl
    $isValid = [bool]($Selector.ValidPublicKey -and $Selector.ValidRsaKeyLength)
    $weakKey = [bool]$Selector.WeakKey

    switch ($Check.Id) {
        'DKIMSelectorPresence' {
            return $(if ($found) { 'Pass' } else { 'Fail' })
        }
        'DKIMKeyStrength' {
            $min = if ($Check.PSObject.Properties.Name -contains 'ExpectedValue' -and $Check.ExpectedValue) { $Check.ExpectedValue } else { 1024 }
            $passesKey = ($keyLength -as [int]) -ge $min -and -not $weakKey
            return $(if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' })
        }
        'DKIMSelectorHealth' {
            $min = 1024
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

function Get-DSADkimEffectiveStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Check,

        [pscustomobject[]]$Selectors
    )

    $effectiveStatus = $Check.Status
    if ($Selectors -and $Check.Area -eq 'DKIM' -and ($Check.Id -in @('DKIMKeyStrength','DKIMTtl','DKIMSelectorHealth','DKIMSelectorPresence'))) {
        $selectorStatuses = @($Selectors | ForEach-Object { Get-DSADkimSelectorStatus -Selector $_ -Check $Check })
        if ($selectorStatuses -contains 'Fail') {
            $effectiveStatus = 'Fail'
        } elseif ($selectorStatuses -contains 'Warning') {
            $effectiveStatus = 'Warning'
        } elseif ($selectorStatuses -contains 'Pass') {
            $effectiveStatus = 'Pass'
        }
    }

    return $effectiveStatus
}
