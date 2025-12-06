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

function ConvertTo-DSAInt {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $parsed = 0
    if ([int]::TryParse($Value.ToString(), [ref]$parsed)) {
        return $parsed
    }

    return $null
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
