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

            foreach ($check in @($checks)) {
                foreach ($required in @('Id', 'Condition', 'Target')) {
                    if (-not (Get-DSABaselinePropertyValue -InputObject $check -Name $required)) {
                        $null = $errors.Add("Check '$($check.Id)' in profile '$profileKey' is missing required property '$required'.")
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
