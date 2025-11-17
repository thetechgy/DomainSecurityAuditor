#requires -Version 7.0

#region ModuleImport
$moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force
#endregion ModuleImport

#region Execution
Invoke-DomainSecurityBaseline -Domain 'example.com' -DryRun
#endregion Execution
