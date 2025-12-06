function Get-DSAConditionDefinitions {
    $existing = Get-Variable -Name DSAConditionDefinitions -Scope Script -ErrorAction SilentlyContinue
    if (-not $existing -or -not $script:DSAConditionDefinitions) {
        $script:DSAConditionDefinitions = New-Object 'System.Collections.Generic.Dictionary[string,pscustomobject]' ([System.StringComparer]::OrdinalIgnoreCase)

        $addDefinition = {
            param (
                [Parameter(Mandatory = $true)][string]$Name,
                [Parameter()][ScriptBlock]$Validate,
                [Parameter(Mandatory = $true)][ScriptBlock]$Evaluate
            )

            $script:DSAConditionDefinitions[$Name] = [pscustomobject]@{
                Name     = $Name
                Validate = $Validate
                Evaluate = $Evaluate
            }
        }

        & $addDefinition 'MustExist' {
            param ($ExpectedValue)
            [pscustomobject]@{
                IsValid = $true
                Message = $null
            }
        } {
            param ($Value, $ExpectedValue)
            Test-DSAHasValue -Value $Value
        }

        & $addDefinition 'MustBeNull' {
            param ($ExpectedValue)
            [pscustomobject]@{
                IsValid = $true
                Message = $null
            }
        } {
            param ($Value, $ExpectedValue)
            -not (Test-DSAHasValue -Value $Value)
        }

        & $addDefinition 'MustContain' {
            param ($ExpectedValue)
            $isValid = Test-DSAHasValue -Value $ExpectedValue
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define an ExpectedValue for condition 'MustContain'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

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

        & $addDefinition 'MustNotContain' {
            param ($ExpectedValue)
            $expectedValues = ConvertTo-DSABaselineArray -Value $ExpectedValue
            $isValid = (@($expectedValues)).Count -gt 0
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define one or more ExpectedValue entries for condition 'MustNotContain'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

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

        & $addDefinition 'MustEqual' {
            param ($ExpectedValue)
            $isValid = Test-DSAHasValue -Value $ExpectedValue
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define an ExpectedValue for condition 'MustEqual'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

            if (-not (Test-DSAHasValue -Value $Value)) {
                return $false
            }

            return [string]::Equals($Value, $ExpectedValue, [System.StringComparison]::OrdinalIgnoreCase)
        }

        & $addDefinition 'MustBeOneOf' {
            param ($ExpectedValue)
            $choices = ConvertTo-DSABaselineArray -Value $ExpectedValue
            $isValid = (@($choices)).Count -gt 0
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define one or more ExpectedValue entries for condition 'MustBeOneOf'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

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

        & $addDefinition 'LessThanOrEqual' {
            param ($ExpectedValue)
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            $isValid = $null -ne $expectedNumber
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define a numeric ExpectedValue for condition 'LessThanOrEqual'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

            $numericValue = ConvertTo-DSADouble -Value $Value
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            if ($null -eq $numericValue -or $null -eq $expectedNumber) {
                return $false
            }

            return $numericValue -le $expectedNumber
        }

        & $addDefinition 'GreaterThanOrEqual' {
            param ($ExpectedValue)
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            $isValid = $null -ne $expectedNumber
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define a numeric ExpectedValue for condition 'GreaterThanOrEqual'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

            $numericValue = ConvertTo-DSADouble -Value $Value
            $expectedNumber = ConvertTo-DSADouble -Value $ExpectedValue
            if ($null -eq $numericValue -or $null -eq $expectedNumber) {
                return $false
            }

            return $numericValue -ge $expectedNumber
        }

        & $addDefinition 'BetweenInclusive' {
            param ($ExpectedValue)
            $min = Get-DSABaselinePropertyValue -InputObject $ExpectedValue -Name 'Min'
            $max = Get-DSABaselinePropertyValue -InputObject $ExpectedValue -Name 'Max'
            $isValid = ($null -ne $ExpectedValue) -and ($null -ne $min -or $null -ne $max)
            [pscustomobject]@{
                IsValid = $isValid
                Message = $(if (-not $isValid) { "must define ExpectedValue.Min or ExpectedValue.Max for condition 'BetweenInclusive'." } else { $null })
            }
        } {
            param ($Value, $ExpectedValue)

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

        & $addDefinition 'MustBeFalse' {
            param ($ExpectedValue)
            [pscustomobject]@{
                IsValid = $true
                Message = $null
            }
        } {
            param ($Value, $ExpectedValue)
            -not [bool]$Value
        }

        & $addDefinition 'MustBeTrue' {
            param ($ExpectedValue)
            [pscustomobject]@{
                IsValid = $true
                Message = $null
            }
        } {
            param ($Value, $ExpectedValue)
            [bool]$Value
        }

        & $addDefinition 'MustBeEmpty' {
            param ($ExpectedValue)
            [pscustomobject]@{
                IsValid = $true
                Message = $null
            }
        } {
            param ($Value, $ExpectedValue)

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
    }

    return $script:DSAConditionDefinitions
}

function Get-DSAConditionDefinition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $definitions = Get-DSAConditionDefinitions
    if ($definitions.ContainsKey($Name)) {
        return $definitions[$Name]
    }

    return $null
}

function Test-DSAConditionExpectedValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Condition,

        $ExpectedValue
    )

    $definition = Get-DSAConditionDefinition -Name $Condition
    if (-not $definition) {
        return [pscustomobject]@{
            IsValid = $false
            Message = "uses unsupported condition '$Condition'."
        }
    }

    if (-not $definition.Validate) {
        return [pscustomobject]@{
            IsValid = $true
            Message = $null
        }
    }

    $validation = & $definition.Validate $ExpectedValue
    if ($validation -is [pscustomobject]) {
        return $validation
    }

    $isValid = [bool]$validation
    return [pscustomobject]@{
        IsValid = $isValid
        Message = $(if ($isValid) { $null } else { "has an invalid ExpectedValue for condition '$Condition'." })
    }
}
