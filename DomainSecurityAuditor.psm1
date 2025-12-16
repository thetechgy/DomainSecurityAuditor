<#
.SYNOPSIS
    Domain Security Auditor module orchestrates domain and email security baseline validation.
.DESCRIPTION
    DomainSecurityAuditor builds on DomainDetective and Pester with native PowerShell HTML rendering to collect DNS posture data, execute repeatable compliance tests, and emit machine-readable artifacts for CI/CD pipelines.
.REQUIRES
    Modules: DomainDetective, Pester, PSScriptAnalyzer
.NOTES
    Module: DomainSecurityAuditor
    Author: Travis McDade
    Date: 11/16/2025
    Version: 0.2.0
    Requestor: DomainSecurityAuditor Stakeholders
    Purpose: Provide a structured baseline for automated domain and email security evidence collection.

Release Notes:
      0.2.0 - 11/22/2025 - BREAKING: Rename entry point to Invoke-DomainSecurityAuditor and align report naming (timestamp after report name).
      0.1.2 - 11/21/2025 - BREAKING: Default output writes summary by default; add -PassThru; capture DomainDetective warnings.
      0.1.1 - 11/20/2025 - Added CSV and CLI classification overrides with validation.
      0.1.0 - 11/16/2025 - Initial scaffolding with dependency enforcement and entry-point stub.

Resources:
      - https://github.com/EvotecIT/DomainDetective
      - https://github.com/pester/Pester
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ModuleInitialization
$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ConfigRoot = Join-Path -Path $script:ModuleRoot -ChildPath 'Configs'
$script:DSAMinDkimKeyLength = 1024
$script:DSAConditionDefinitions = $null
$script:DSADomainDetectiveLoaded = $false
$script:DSAKnownReferenceLinks = @{}
#endregion ModuleInitialization

#region PrivateHelpers
$privatePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Private'
if (Test-Path -Path $privatePath) {
    $privateFiles = @(Get-ChildItem -Path $privatePath -Filter '*.ps1' -File | Sort-Object -Property Name)
    $valueHelpers = @($privateFiles | Where-Object { $_.BaseName -eq 'DSA.ValueHelpers' })
    $remaining = @($privateFiles | Where-Object { $_.BaseName -ne 'DSA.ValueHelpers' })

    foreach ($file in $valueHelpers + $remaining) {
        . $file.FullName
    }
}

# Pre-warm condition definitions cache to avoid lazy initialization overhead during first domain run.
$null = Get-DSAConditionDefinitions
#endregion PrivateHelpers

#region PublicFunctions
$publicPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public'
$publicFunctions = @()
if (Test-Path -Path $publicPath) {
    $publicFunctions = @(
        Get-ChildItem -Path $publicPath -Filter '*.ps1' -File |
            Sort-Object -Property Name |
            ForEach-Object {
                . $_.FullName
                $_.BaseName
            }
    )
}

if ($publicFunctions.Count -gt 0) {
    Export-ModuleMember -Function $publicFunctions
}
else {
    Export-ModuleMember -Function @()
}
#endregion PublicFunctions
