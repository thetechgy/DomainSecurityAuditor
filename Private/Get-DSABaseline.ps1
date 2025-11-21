function Get-DSABaseline {
<#
.SYNOPSIS
    Loads baseline profile definitions from a configuration file.
.DESCRIPTION
    Resolves and imports baseline checks from either a named built-in profile or a custom file path.
    Returns a hashtable of profile definitions keyed by classification name.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ProfilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileName = 'Default'
    )

    if ($PSBoundParameters.ContainsKey('ProfilePath')) {
        $resolvedProfile = Resolve-DSAPath -Path $ProfilePath -PathType 'File'
    } else {
        $profileFileName = "Baseline.$ProfileName.psd1"
        $defaultProfile = Join-Path -Path $script:ModuleRoot -ChildPath "Configs/$profileFileName"
        if (-not (Test-Path -Path $defaultProfile)) {
            throw "Baseline profile '$ProfileName' not found at '$defaultProfile'."
        }

        $resolvedProfile = Resolve-DSAPath -Path $defaultProfile -PathType 'File'
    }

    $definition = Import-DSABaselineConfig -Path $resolvedProfile
    $profiles = Get-DSABaselinePropertyValue -InputObject $definition -Name 'Profiles'
    if (-not $profiles) {
        throw "Baseline profile '$resolvedProfile' is missing the 'Profiles' collection."
    }

    return @{
        Name     = Get-DSABaselinePropertyValue -InputObject $definition -Name 'Name'
        Version  = Get-DSABaselinePropertyValue -InputObject $definition -Name 'Version'
        Profiles = $profiles
    }
}
