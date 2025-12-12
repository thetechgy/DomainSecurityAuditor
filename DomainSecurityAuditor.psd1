@{
    RootModule        = 'DomainSecurityAuditor.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = 'a5c3892b-1b29-4050-9dac-11a5d737da38'
    Author            = 'Travis McDade'
    CompanyName       = 'DomainSecurityAuditor'
    Copyright         = '(c) 2025 DomainSecurityAuditor. All rights reserved.'
    Description       = 'PowerShell module for auditing domain and email security baselines via DomainDetective, Pester, and native HTML rendering.'
    PowerShellVersion = '7.0'
    CompatiblePSEditions = @('Core')
    RequiredModules   = @(
        'DomainDetective'
        'Pester'
        'PSScriptAnalyzer'
    )
    FunctionsToExport = @(
        'Invoke-DomainSecurityAuditor',
        'Get-DSABaselineProfile',
        'New-DSABaselineProfile',
        'Test-DSABaselineProfile'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FileList          = @(
        'DomainSecurityAuditor.psm1',
        'DomainSecurityAuditor.psd1',
        'Configs/ReferenceLinks.psd1'
    )
    PrivateData       = @{
        PSData = @{
            Tags         = @('Domain', 'Security', 'Compliance', 'Pester', 'Reporting')
            LicenseUri   = 'https://www.apache.org/licenses/LICENSE-2.0'
            ProjectUri   = 'https://github.com/thetechgy/DomainSecurityAuditor'
            ReleaseNotes = @'
0.2.0 - 2025-11-22 - BREAKING: Rename entry point to Invoke-DomainSecurityAuditor; align report title/filenames to Domain Security Auditor with timestamp appended after the report name.
0.1.2 - 2025-11-21 - BREAKING: Default output now writes a summary; add -PassThru; capture DomainDetective warnings.
0.1.1 - 2025-11-20 - Add CSV and CLI classification overrides with validation.
0.1.0 - 2025-11-16 - Initial scaffolding of module structure and public entry point stub.
'@
        }
    }
}
