function Test-DSABaselineProfile {
<#
.SYNOPSIS
    Validates that a baseline profile file is well-formed.
.DESCRIPTION
    Loads the specified PSD1/JSON baseline and verifies it contains the Profiles collection plus required fields for each check.
.PARAMETER Path
    Path to the baseline profile file (PSD1).
.EXAMPLE
    Test-DSABaselineProfile -Path '.\Baseline.MyOrg.psd1'
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $resolvedPath = Resolve-DSAPath -Path $Path -PathType 'File'
    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $definition = Import-DSABaselineConfig -Path $resolvedPath
    } catch {
        $null = $errors.Add($_.Exception.Message)
        return [pscustomobject]@{
            Path    = $resolvedPath
            IsValid = $false
            Errors  = $errors
        }
    }

    $profiles = Get-DSABaselinePropertyValue -InputObject $definition -Name 'Profiles'
    if (-not $profiles) {
        $null = $errors.Add('Profiles collection is missing.')
    } else {
        foreach ($profileKey in $profiles.Keys) {
            $profile = $profiles[$profileKey]
            $checks = Get-DSABaselinePropertyValue -InputObject $profile -Name 'Checks'
            if (-not $checks) {
                $null = $errors.Add("Profile '$profileKey' does not define any checks.")
                continue
            }

            $checkIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($check in @($checks)) {
                $checkId = Get-DSABaselinePropertyValue -InputObject $check -Name 'Id'
                $checkLabel = if (-not [string]::IsNullOrWhiteSpace($checkId)) { $checkId } else { '<missing Id>' }

                if (-not [string]::IsNullOrWhiteSpace($checkId)) {
                    if (-not $checkIds.Add($checkId)) {
                        $null = $errors.Add("Profile '$profileKey' defines duplicate check Id '$checkId'.")
                    }
                }

                foreach ($required in @('Id', 'Condition', 'Target', 'Area', 'Severity')) {
                    if (-not (Get-DSABaselinePropertyValue -InputObject $check -Name $required)) {
                        $null = $errors.Add("Check '$checkLabel' in profile '$profileKey' is missing required property '$required'.")
                    }
                }

                $condition = Get-DSABaselinePropertyValue -InputObject $check -Name 'Condition'
                $expectedValue = Get-DSABaselinePropertyValue -InputObject $check -Name 'ExpectedValue'
                switch ($condition) {
                    'BetweenInclusive' {
                        $min = Get-DSABaselinePropertyValue -InputObject $expectedValue -Name 'Min'
                        $max = Get-DSABaselinePropertyValue -InputObject $expectedValue -Name 'Max'
                        if ($null -eq $expectedValue -or ($null -eq $min -and $null -eq $max)) {
                            $null = $errors.Add("Check '$checkLabel' in profile '$profileKey' must define ExpectedValue.Min or ExpectedValue.Max for condition '$condition'.")
                        }
                    }
                    'LessThanOrEqual'
                    'GreaterThanOrEqual' {
                        if ($null -eq $expectedValue -or $null -eq (ConvertTo-DSADouble -Value $expectedValue)) {
                            $null = $errors.Add("Check '$checkLabel' in profile '$profileKey' must define a numeric ExpectedValue for condition '$condition'.")
                        }
                    }
                    'MustBeOneOf'
                    'MustNotContain' {
                        $expectedValues = ConvertTo-DSABaselineArray -Value $expectedValue
                        if ($expectedValues.Count -eq 0) {
                            $null = $errors.Add("Check '$checkLabel' in profile '$profileKey' must define one or more ExpectedValue entries for condition '$condition'.")
                        }
                    }
                    'MustContain'
                    'MustEqual' {
                        if (-not (Test-DSAHasValue -Value $expectedValue)) {
                            $null = $errors.Add("Check '$checkLabel' in profile '$profileKey' must define an ExpectedValue for condition '$condition'.")
                        }
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        Path    = $resolvedPath
        IsValid = ($errors.Count -eq 0)
        Errors  = $errors
    }
}
