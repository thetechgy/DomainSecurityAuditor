function Invoke-DSABaselineTest {
<#
.SYNOPSIS
    Evaluates domain evidence against baseline check definitions.
.DESCRIPTION
    Runs each check in the baseline profile against the provided domain evidence,
    evaluating conditions and returning pass/fail/warning results for each check.
.PARAMETER DomainEvidence
    The domain evidence object from Get-DSADomainEvidence containing Records property.
.PARAMETER BaselineDefinition
    Hashtable of baseline profiles keyed by classification name. If omitted, loads default baseline.
.PARAMETER ClassificationOverride
    Optional classification to use instead of the evidence-derived classification.
.OUTPUTS
    PSCustomObject with Domain, Classification, OverallStatus, and Checks array.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscustomobject]$DomainEvidence,

        [Parameter()]
        [hashtable]$BaselineDefinition,

        [string]$ClassificationOverride
    )

    if (-not $BaselineDefinition) {
        $baseline = Get-DSABaseline
        $BaselineDefinition = $baseline.Profiles
    }

    $effectiveClassification = if (-not [string]::IsNullOrWhiteSpace($ClassificationOverride)) {
        $ClassificationOverride
    } else {
        $DomainEvidence.Classification
    }

    $classificationKey = Get-DSAClassificationKey -Classification $effectiveClassification
    if (-not $classificationKey -or -not $BaselineDefinition.ContainsKey($classificationKey)) {
        $classificationKey = 'Default'
    }

    $profileDefinition = $BaselineDefinition[$classificationKey]
    if (-not $profileDefinition -or -not $profileDefinition.Checks) {
        throw "Baseline profile '$classificationKey' is missing or has no checks defined."
    }

    $checkResults = [System.Collections.Generic.List[object]]::new()

    foreach ($check in $profileDefinition.Checks) {
        $expectedValue = $null
        if ($check -is [hashtable]) {
            if ($check.ContainsKey('ExpectedValue')) {
                $expectedValue = $check.ExpectedValue
            }
        } elseif ($check.PSObject -and $check.PSObject.Properties.Name -contains 'ExpectedValue') {
            $expectedValue = $check.ExpectedValue
        }

        $value = Get-DSAEvidenceValue -DomainEvidence $DomainEvidence -Path $check.Target
        $conditionMet = Test-DSABaselineCondition -Condition $check.Condition -Value $value -ExpectedValue $expectedValue
        $status = if ($conditionMet) {
            'Pass'
        } elseif (($check.Enforcement ?? 'Required') -ieq 'Required') {
            'Fail'
        } else {
            'Warning'
        }

        $actualValue = Format-DSAActualValue -Value $value
        $result = [pscustomobject]@{
            Id          = $check.Id
            Area        = $check.Area
            Status      = $status
            Severity    = $check.Severity
            Enforcement = $check.Enforcement
            Expectation = $check.Expectation
            ExpectedValue = $expectedValue
            Actual      = $actualValue
            Remediation = $check.Remediation
            References  = $check.References
        }

        $null = $checkResults.Add($result)
    }

    $overallStatus = Get-DSAOverallStatus -Checks $checkResults
    return [pscustomobject]@{
        Domain                 = $DomainEvidence.Domain
        Classification         = $profileDefinition.Name
        OriginalClassification = $DomainEvidence.Classification
        ClassificationOverride = $ClassificationOverride
        OverallStatus          = $overallStatus
        Checks                 = $checkResults.ToArray()
    }
}

function Get-DSAEvidenceValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$DomainEvidence,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $segments = $Path -split '\.'
    $current = $DomainEvidence

    foreach ($segment in $segments) {
        if ($null -eq $current) {
            return $null
        }

        if ($current.PSObject.Properties.Name -contains $segment) {
            $current = $current.$segment
        } else {
            return $null
        }
    }

    return $current
}

function Test-DSABaselineCondition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Condition,

        [Parameter()]
        $Value,

        [Parameter()]
        [object]$ExpectedValue
    )

    switch ($Condition) {
        'MustExist' {
            return Test-DSAHasValue -Value $Value
        }
        'MustBeNull' {
            return -not (Test-DSAHasValue -Value $Value)
        }
        'MustContain' {
            if (-not (Test-DSAHasValue -Value $Value)) {
                return $false
            }

            $expected = $ExpectedValue ?? ''
            if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
                foreach ($item in $Value) {
                    if (($item ?? '') -match [regex]::Escape($expected)) {
                        return $true
                    }
                }
                return $false
            }

            return (($Value ?? '') -match [regex]::Escape($expected))
        }
        'MustNotContain' {
            if (-not (Test-DSAHasValue -Value $Value)) {
                return $true
            }

            $expectedValues = ConvertTo-DSABaselineArray -Value $ExpectedValue
            foreach ($expected in $expectedValues) {
                if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
                    foreach ($item in $Value) {
                        if (([string]$item) -like "*$expected*") {
                            return $false
                        }
                    }
                } elseif (([string]$Value) -like "*$expected*") {
                    return $false
                }
            }

            return $true
        }
        'MustEqual' {
            if (-not (Test-DSAHasValue -Value $Value)) {
                return $false
            }

            return [string]::Equals($Value, $ExpectedValue, [System.StringComparison]::OrdinalIgnoreCase)
        }
        'MustBeOneOf' {
            if (-not (Test-DSAHasValue -Value $Value)) {
                return $false
            }

            $choices = ConvertTo-DSABaselineArray -Value $ExpectedValue
            $normalizedValue = $Value.ToString()
            foreach ($choice in $choices) {
                if ([string]::Equals($normalizedValue, $choice, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $true
                }
            }

            return $false
        }
        'LessThanOrEqual' {
            $numericValue = ConvertTo-DSADouble -Value $Value
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            if ($null -eq $numericValue -or $null -eq $expectedNumber) {
                return $false
            }

            return $numericValue -le $expectedNumber
        }
        'GreaterThanOrEqual' {
            $numericValue = ConvertTo-DSADouble -Value $Value
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            if ($null -eq $numericValue -or $null -eq $expectedNumber) {
                return $false
            }

            return $numericValue -ge $expectedNumber
        }
        'BetweenInclusive' {
            if (-not (Test-DSAHasValue -Value $Value)) {
                return $false
            }

            $numericValue = ConvertTo-DSADouble -Value $Value
            if ($null -eq $numericValue) {
                return $false
            }

            if ($null -eq $ExpectedValue) {
                return $false
            }

            $min = Get-DSABaselinePropertyValue -InputObject $ExpectedValue -Name 'Min'
            $max = Get-DSABaselinePropertyValue -InputObject $ExpectedValue -Name 'Max'
            if ($null -ne $min -and $numericValue -lt (ConvertTo-DSADouble -Value $min)) {
                return $false
            }

            if ($null -ne $max -and $numericValue -gt (ConvertTo-DSADouble -Value $max)) {
                return $false
            }

            return $true
        }
        'MustBeFalse' {
            return -not [bool]$Value
        }
        'MustBeTrue' {
            return [bool]$Value
        }
        'MustBeEmpty' {
            if ($null -eq $Value) {
                return $true
            }

            if ($Value -is [string]) {
                return [string]::IsNullOrWhiteSpace($Value)
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                $items = @($Value)
                return $items.Count -eq 0
            }

            return $false
        }
        default {
            return $false
        }
    }
}

function Test-DSAHasValue {
    [CmdletBinding()]
    param (
        $Value
    )

    if ($null -eq $Value) {
        return $false
    }

    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $enumerated = @($Value)
        return $enumerated.Count -gt 0
    }

    return $true
}

function Format-DSAActualValue {
    [CmdletBinding()]
    param (
        $Value
    )

    if (-not (Test-DSAHasValue -Value $Value)) {
        return 'None'
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $flattened = @($Value | Where-Object { $_ -ne $null })
        if ($flattened.Count -eq 0) {
            return 'None'
        }
        return ($flattened -join ', ')
    }

    return $Value.ToString()
}

function Get-DSAOverallStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Checks
    )

    $statuses = @($Checks | ForEach-Object { $_.Status })

    # If all checks belong to DKIM and all share the same status, honor that exact status to mirror per-selector breakdowns.
    $dkimOnly = @($Checks | Where-Object { $_.Area -eq 'DKIM' })
    if ($dkimOnly.Count -gt 0 -and $dkimOnly.Count -eq $Checks.Count) {
        if ($statuses -and ($statuses | Where-Object { $_ -eq 'Fail' }).Count -eq $statuses.Count) {
            return 'Fail'
        }
        if ($statuses -and ($statuses | Where-Object { $_ -eq 'Warning' }).Count -eq $statuses.Count) {
            return 'Warning'
        }
        if ($statuses -and ($statuses | Where-Object { $_ -eq 'Pass' }).Count -eq $statuses.Count) {
            return 'Pass'
        }
    }

    if ($statuses -contains 'Fail') {
        return 'Fail'
    }

    if ($statuses -contains 'Warning') {
        return 'Warning'
    }

    return 'Pass'
}

function ConvertTo-DSABaselineArray {
    param (
        $Value
    )

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    if ($null -eq $Value) {
        return @()
    }

    return @($Value)
}

function ConvertTo-DSADouble {
<#
.SYNOPSIS
    Converts a value to a double using culture-invariant parsing.
.DESCRIPTION
    Attempts to parse the input value as a double using invariant culture rules.
    Returns null if parsing fails or input is null.
#>
    param (
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $number = 0.0
    $style = [System.Globalization.NumberStyles]::Float
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ([double]::TryParse($Value.ToString(), $style, $culture, [ref]$number)) {
        return $number
    }

    return $null
}

function Get-DSAClassificationKey {
<#
.SYNOPSIS
    Normalizes a classification string to its canonical key form.
.DESCRIPTION
    Converts classification values like 'sending-only' or 'SendingOnly' to the
    standard key format used in baseline profiles.
#>
    [CmdletBinding()]
    param (
        [string]$Classification
    )

    if ([string]::IsNullOrWhiteSpace($Classification)) {
        return $null
    }

    $normalized = ($Classification -replace '[^a-zA-Z]', '').ToLowerInvariant()
    switch ($normalized) {
        'sendingonly' { return 'SendingOnly' }
        'receivingonly' { return 'ReceivingOnly' }
        'sendingandreceiving' { return 'SendingAndReceiving' }
        'parked' { return 'Parked' }
        default { return $Classification }
    }
}

function Get-DSABaselinePropertyValue {
<#
.SYNOPSIS
    Retrieves a property value from a hashtable or PSCustomObject.
.DESCRIPTION
    Safely extracts a named property from either a hashtable or PSCustomObject,
    returning null if the property doesn't exist or input is null.
#>
    [CmdletBinding()]
    param (
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [hashtable]) {
        if ($InputObject.ContainsKey($Name)) {
            return $InputObject[$Name]
        }
        return $null
    }

    if ($InputObject.PSObject -and $InputObject.PSObject.Properties.Name -contains $Name) {
        return $InputObject.$Name
    }

    return $null
}
