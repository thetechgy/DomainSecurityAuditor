<#
.SYNOPSIS
    Domain Security Auditor module orchestrates domain and email security baseline validation.
.DESCRIPTION
    DomainSecurityAuditor builds on DomainDetective, Pester, and PSWriteHTML to collect DNS posture data, execute repeatable compliance tests, and emit HTML or machine-readable artifacts for CI/CD pipelines.
.REQUIRES
    Modules: DomainDetective, PSWriteHTML, Pester, PSScriptAnalyzer
.NOTES
    Module: DomainSecurityAuditor
    Author: Travis McDade
    Date: 11/16/2025
    Version: 0.1.0
    Requestor: DomainSecurityAuditor Stakeholders
    Purpose: Provide a structured baseline for automated domain and email security evidence collection.

Release Notes:
      0.1.0 - 11/16/2025 - Initial scaffolding with dependency enforcement and entry-point stub.

Resources:
      - https://github.com/EvotecIT/DomainDetective
      - https://github.com/pester/Pester
      - https://github.com/EvotecIT/PSWriteHTML
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ModuleInitialization
$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:DefaultLogRoot = Join-Path -Path $script:ModuleRoot -ChildPath 'Logs'
$script:DefaultOutputRoot = Join-Path -Path $script:ModuleRoot -ChildPath 'Output'
#endregion ModuleInitialization

#region PrivateHelpers
$privatePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Private'
if (Test-Path -Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -File | Sort-Object -Property Name | ForEach-Object {
        . $_.FullName
    }
}
#endregion PrivateHelpers

#region PublicFunctions
$publicPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public'
$publicFunctions = @()
if (Test-Path -Path $publicPath) {
    $publicFunctions = Get-ChildItem -Path $publicPath -Filter '*.ps1' -File | Sort-Object -Property Name | ForEach-Object {
        . $_.FullName
        $_.BaseName
    }
}

if ($publicFunctions.Count -gt 0) {
    Export-ModuleMember -Function $publicFunctions
} else {
    Export-ModuleMember -Function @()
}
#endregion PublicFunctions
