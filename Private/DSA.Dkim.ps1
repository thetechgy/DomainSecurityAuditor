function Test-DSADkimSelectorName {
    param (
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $trimmed = $Value.Trim()
    $blocked = @('KeyLength', 'TTL', 'Ttl', 'IsValid', 'ValidPublicKey', 'ValidRsaKeyLength', 'DkimRecordExists', 'StartsCorrectly')
    if ($blocked -contains $trimmed) {
        return $false
    }

    return ($trimmed -match '^[A-Za-z0-9][A-Za-z0-9_-]*$')
}

function ConvertTo-DSADkimAnalysisMap {
    param (
        $Analysis
    )

    if (-not $Analysis -or -not $Analysis.AnalysisResults) {
        return @{}
    }

    $map = @{}
    $results = $Analysis.AnalysisResults

    if ($results -is [System.Collections.IDictionary]) {
        foreach ($entry in $results.GetEnumerator()) {
            $keyText = "$($entry.Key)".Trim()
            $targetKey = $null
            if (Test-DSADkimSelectorName -Value $keyText) {
                $targetKey = $keyText
            } elseif ($entry.Value) {
                $candidate = $null
                if ($entry.Value.PSObject.Properties.Name -contains 'Name') {
                    $candidate = $entry.Value.Name
                } elseif ($entry.Value.PSObject.Properties.Name -contains 'Selector') {
                    $candidate = $entry.Value.Selector
                }
                if (Test-DSADkimSelectorName -Value $candidate) {
                    $targetKey = $candidate.Trim()
                }
            }

            if ($targetKey -and -not $map.ContainsKey($targetKey)) {
                $map[$targetKey] = $entry.Value
            }
        }
    } elseif ($results -is [System.Collections.IEnumerable] -and -not ($results -is [string])) {
        foreach ($item in $results) {
            if (-not $item) { continue }
            $candidate = $null
            if ($item.PSObject.Properties.Name -contains 'Name') {
                $candidate = $item.Name
            } elseif ($item.PSObject.Properties.Name -contains 'Selector') {
                $candidate = $item.Selector
            }

            if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                $keyText = "$candidate".Trim()
                if (-not $map.ContainsKey($keyText)) {
                    $map[$keyText] = $item
                }
            }
        }
    }

    return $map
}

function Get-DSADkimSelectorNames {
    param (
        $Analysis
    )

    $map = ConvertTo-DSADkimAnalysisMap -Analysis $Analysis
    if (-not $map) {
        return @()
    }

    return $map.Keys | Where-Object { Test-DSADkimSelectorName -Value $_ }
}

function Get-DSADkimSelectorDetails {
    param (
        $Analysis,
        [string[]]$Selectors,
        [switch]$IncludeMissing,
        [string[]]$MissingSelectors
    )

    $analysisMap = ConvertTo-DSADkimAnalysisMap -Analysis $Analysis

    $selectorSet = @()
    if ($Selectors) {
        $selectorSet = $Selectors
    } elseif ($analysisMap) {
        $selectorSet = $analysisMap.Keys
    }

    $normalizedSelectors = @($selectorSet | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Where-Object { Test-DSADkimSelectorName -Value $_ } | Sort-Object -Unique)
    if (-not $normalizedSelectors) {
        return @()
    }

    $details = [System.Collections.Generic.List[pscustomobject]]::new()
    $missingSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($missing in (@($MissingSelectors))) {
        if (-not [string]::IsNullOrWhiteSpace($missing)) {
            $null = $missingSet.Add($missing.Trim())
        }
    }

    foreach ($selector in $normalizedSelectors) {
        $data = $null
        if ($analysisMap -and $analysisMap.ContainsKey($selector)) {
            $data = $analysisMap[$selector]
        }

        if (-not $data) {
            if (-not $IncludeMissing -or -not $missingSet.Contains($selector)) {
                continue
            }
        }

        $keyLength = $null
        $ttl = $null
        $isValid = $false

        if ($data) {
            $keyLength = ConvertTo-DSAInt -Value ($data.PSObject.Properties['KeyLength']?.Value)
            $ttl = ConvertTo-DSAInt -Value ($data.PSObject.Properties['Ttl']?.Value ?? $data.PSObject.Properties['TTL']?.Value)

            if ($null -ne $data.PSObject.Properties['IsValid']) {
                $isValid = [bool]$data.IsValid
            } else {
                $isValid = $true
                if ($null -ne $data.PSObject.Properties['ValidPublicKey']) {
                    $isValid = $isValid -and [bool]$data.ValidPublicKey
                }
                if ($null -ne $data.PSObject.Properties['ValidRsaKeyLength']) {
                    $isValid = $isValid -and [bool]$data.ValidRsaKeyLength
                }
                if ($null -ne $data.PSObject.Properties['DkimRecordExists']) {
                    $isValid = $isValid -and [bool]$data.DkimRecordExists
                }
                if ($null -ne $data.PSObject.Properties['StartsCorrectly']) {
                    $isValid = $isValid -and [bool]$data.StartsCorrectly
                }
            }
        }

        $record = [pscustomobject]@{
            Name      = $selector
            KeyLength = $keyLength
            Ttl       = $ttl
            IsValid   = $isValid
            Found     = ($null -ne $data)
        }
        $null = $details.Add($record)
    }

    return $details
}

function Get-DSADkimMinimumKeyLength {
    param (
        $Analysis
    )

    if ($Analysis -is [System.Collections.IEnumerable] -and -not ($Analysis -is [string]) -and -not ($Analysis.PSObject.Properties.Name -contains 'AnalysisResults')) {
        $details = @($Analysis | Where-Object { $_ })
    } else {
        $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    }

    if (@($details).Count -eq 0) {
        return $null
    }

    $lengths = @()
    foreach ($detail in $details) {
        if (-not $detail.Found) { continue }
        if ($null -eq $detail.KeyLength) { continue }
        $parsed = ConvertTo-DSAInt -Value $detail.KeyLength
        if ($null -ne $parsed) {
            $lengths += $parsed
        }
    }
    if (@($lengths).Count -eq 0) {
        return $null
    }

    return ($lengths | Measure-Object -Minimum).Minimum
}

function Get-DSADkimWeakSelectorCount {
    param (
        $Analysis
    )

    if ($Analysis -is [System.Collections.IEnumerable] -and -not ($Analysis -is [string]) -and -not ($Analysis.PSObject.Properties.Name -contains 'AnalysisResults')) {
        $details = @($Analysis | Where-Object { $_ })
    } else {
        $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    }

    if (@($details).Count -eq 0) {
        return 0
    }

    $count = 0
    foreach ($detail in $details) {
        $isWeak = $false
        if (-not $detail.Found) {
            $isWeak = $true
        } elseif ($null -ne $detail.KeyLength) {
            $parsed = ConvertTo-DSAInt -Value $detail.KeyLength
            if ($null -ne $parsed -and $parsed -lt 1024) {
                $isWeak = $true
            }
        }

        if ($detail.IsValid -eq $false) {
            $isWeak = $true
        }

        if ($isWeak) {
            $count++
        }
    }

    return $count
}

function Get-DSADkimSelectorStatus {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$Selector,
        [Parameter(Mandatory = $true)][pscustomobject]$Check
    )

    $found = if ($Selector.PSObject.Properties.Name -contains 'Found') { [bool]$Selector.Found } else { $true }
    $keyLength = $Selector.KeyLength
    $ttl = $Selector.Ttl
    $isValid = if ($Selector.PSObject.Properties.Name -contains 'IsValid') { [bool]$Selector.IsValid } else { $true }

    switch ($Check.Id) {
        'DKIMSelectorPresence' {
            return $(if ($found) { 'Pass' } else { 'Fail' })
        }
        'DKIMKeyStrength' {
            $min = if ($Check.PSObject.Properties.Name -contains 'ExpectedValue') { $Check.ExpectedValue } else { 1024 }
            $passesKey = $keyLength -as [int] -ge $min
            return $(if ($found -and $passesKey -and $isValid) { 'Pass' } else { 'Fail' })
        }
        'DKIMSelectorHealth' {
            $min = 1024
            $passesKey = $keyLength -as [int] -ge $min
            return $(if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' })
        }
        'DKIMTtl' {
            $min = $null
            $max = $null
            if ($Check.PSObject.Properties.Name -contains 'ExpectedValue') {
                $min = $Check.ExpectedValue.Min
                $max = $Check.ExpectedValue.Max
            }
            $ttlNumber = $ttl -as [int]
            $passTtl = $false
            if ($ttlNumber -and $min -and $max) {
                $passTtl = ($ttlNumber -ge $min -and $ttlNumber -le $max)
            }
            return $(if ($passTtl) { 'Pass' } else { 'Fail' })
        }
        default {
            return $(if ($found -and $isValid) { 'Pass' } else { 'Fail' })
        }
    }
}

function Get-DSADkimEffectiveStatus {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$Check,
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
