<#
.SYNOPSIS
    Determine whether a value should be treated as populated.
.DESCRIPTION
    Returns true when the value is non-null and, for strings or enumerables, non-empty.
.PARAMETER Value
    The value to evaluate.
#>
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

<#
.SYNOPSIS
    Normalize input into an array for baseline comparisons.
.DESCRIPTION
    Converts null to an empty array and wraps single items in an array while preserving existing enumerables.
.PARAMETER Value
    Input value to normalize.
#>
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

<#
.SYNOPSIS
    Format observed values for display in reports and logs.
.DESCRIPTION
    Returns 'None' for null/empty values, joins enumerables with commas, or converts scalars to string.
.PARAMETER Value
    Value to format.
#>
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

