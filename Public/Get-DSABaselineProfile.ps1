function Get-DSABaselineProfile {
<#
.SYNOPSIS
    Lists built-in baseline profiles available to the Domain Security Auditor module.
.DESCRIPTION
    Enumerates the profile data files stored under the module's Configs directory. Use this to discover profile names
    that can be supplied to -Baseline on Invoke-DomainSecurityBaseline or as the source for New-DSABaselineProfile.
.PARAMETER Name
    Optional profile name (for example, 'Default'). When specified, only the matching profile metadata is returned.
.EXAMPLE
    Get-DSABaselineProfile
    Lists every profile shipped with the module.
.EXAMPLE
    Get-DSABaselineProfile -Name 'Default'
    Returns the path to the Default baseline definition.
#>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $configRoot = Join-Path -Path $script:ModuleRoot -ChildPath 'Configs'
    if (-not (Test-Path -Path $configRoot)) {
        return @()
    }

    $pattern = if ($Name) { "Baseline.$Name.psd1" } else { 'Baseline.*.psd1' }
    $files = Get-ChildItem -Path $configRoot -Filter $pattern -File -ErrorAction SilentlyContinue
    return $files | ForEach-Object {
        $profileName = $_.BaseName -replace '^Baseline\.', ''
        [pscustomobject]@{
            Name = $profileName
            Path = $_.FullName
        }
    }
}
