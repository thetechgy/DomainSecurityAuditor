<#
.SYNOPSIS
    Create a reusable evidence payload for tests.
.DESCRIPTION
    Builds a customizable DomainDetective-like evidence object for use across test scenarios.
#>
function global:New-TestEvidence {
    param (
        [string]$Domain = 'example.com',
        [string]$Classification = 'SendingAndReceiving',
        [ScriptBlock]$Adjust
    )

    $records = [pscustomobject]@{
        MX                    = @('mx1.example.com')
        MXRecordCount         = 1
        MXHasNull             = $false
        MXMinimumTtl          = 3600
        SPFRecord             = 'v=spf1 include:_spf.example.com -all'
        SPFRecords            = @('v=spf1 include:_spf.example.com -all')
        SPFRecordCount        = 1
        SPFLookupCount        = 2
        SPFTerminalMechanism  = '-all'
        SPFHasPtrMechanism    = $false
        SPFRecordLength       = 40
        SPFTtl                = 3600
        SPFIncludes           = @('_spf.example.com')
        SPFWildcardRecord     = 'v=spf1 -all'
        SPFWildcardConfigured = $true
        SPFUnsafeMechanisms   = @()
        DKIMSelectors         = @('selector1')
        DKIMSelectorDetails   = @(
            [pscustomobject]@{
                Selector          = 'selector1'
                DkimRecordExists  = $true
                KeyLength         = 2048
                ValidPublicKey    = $true
                ValidRsaKeyLength = $true
                WeakKey           = $false
                DnsRecordTtl      = 3600
            }
        )
        DKIMMinKeyLength      = 2048
        DKIMWeakSelectors     = 0
        DKIMMinimumTtl        = 3600
        DMARCRecord           = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
        DMARCPolicy           = 'reject'
        DMARCRuaAddresses     = @('dmarc@example.com')
        DMARCRufAddresses     = @()
        DMARCTtl              = 3600
        MTASTSRecordPresent   = $true
        MTASTSPolicyValid     = $true
        MTASTSMode            = 'enforce'
        MTASTSTtl             = 86400
        TLSRPTRecordPresent   = $true
        TLSRPTAddresses       = @('tls@example.com')
        TLSRPTTtl             = 86400
    }

    $evidence = [pscustomobject]@{
        Domain         = $Domain
        Classification = $Classification
        Records        = $records
    }

    if ($Adjust) {
        & $Adjust -ArgumentList $evidence
    }

    return $evidence
}

BeforeAll {
    $stubModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Stubs'
    if (Test-Path -Path $stubModuleRoot) {
        $env:PSModulePath = "{0}{1}{2}" -f $stubModuleRoot, [System.IO.Path]::PathSeparator, $env:PSModulePath
    }

    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force
}

AfterAll {
    Remove-Item -Path Function:\New-TestEvidence -ErrorAction SilentlyContinue
}

Describe 'Invoke-DomainSecurityAuditor' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }
    It 'is exported by the module' {
        $command = Get-Command -Name Invoke-DomainSecurityAuditor -Module DomainSecurityAuditor -ErrorAction Stop
        $command | Should -Not -BeNullOrEmpty
    }

    It 'includes required parameters' {
        $command = Get-Command -Name Invoke-DomainSecurityAuditor -Module DomainSecurityAuditor
        $command.Parameters.Keys | Should -Contain 'ShowProgress'
        $command.Parameters.Keys | Should -Contain 'SkipDependencies'
        $command.Parameters.Keys | Should -Contain 'DkimSelector'
        $command.Parameters.Keys | Should -Contain 'DNSEndpoint'
        $command.Parameters.Keys | Should -Contain 'Baseline'
        $command.Parameters.Keys | Should -Contain 'BaselineProfilePath'
    }

    Context 'baseline evaluation' {
        BeforeEach {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Test-DSADependency -MockWith {
                    [pscustomobject]@{
                        MissingModules = @()
                        IsCompliant    = $true
                    }
                }

                Mock -CommandName Start-Transcript -MockWith { }
                Mock -CommandName Stop-Transcript -MockWith { }
                Mock -CommandName Invoke-DSALogRetention -MockWith { }
                Mock -CommandName Write-DSALog -MockWith { }
                Mock -CommandName Publish-DSAHtmlReport -MockWith { 'C:\Reports\domain_report.html' }
                Mock -CommandName Open-DSAReport -MockWith { }
                Mock Get-DSABaseline {
                    $baselineFile = Join-Path -Path $script:ModuleRoot -ChildPath 'Configs/Baseline.Default.psd1'
                    $definition = Import-PowerShellDataFile -Path $baselineFile
                    [pscustomobject]@{
                        Name     = $definition.Name
                        Version  = $definition.Version
                        Profiles = $definition.Profiles
                    }
                }
            }
        }

        It 'returns structured compliance data' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence }

                $result = Invoke-DomainSecurityAuditor -Domain 'example.com' -SkipReportLaunch -PassThru
                $result | Should -Not -BeNullOrEmpty

                $auditProfile = $result | Select-Object -First 1
                $auditProfile.Domain | Should -Be 'example.com'
                $auditProfile.Checks.Count | Should -BeGreaterThan 0
                $auditProfile.OverallStatus | Should -Be 'Pass'
                $auditProfile.ReportPath | Should -Be 'C:\Reports\domain_report.html'

                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'uses DomainDetective default DKIM selectors when none are provided' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence }

                $null = Invoke-DomainSecurityAuditor -Domain 'example.com' -SkipReportLaunch -PassThru

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { -not $DkimSelector }
            }
        }

        It 'passes custom DKIM selectors from parameters' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                $null = Invoke-DomainSecurityAuditor -Domain 'example.com' -DkimSelector 'sel1', 'sel2' -SkipReportLaunch -PassThru

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $DkimSelector -and $DkimSelector -contains 'sel1' -and $DkimSelector -contains 'sel2' }
            }
        }

        It 'passes DNSEndpoint through to evidence collection' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                $null = Invoke-DomainSecurityAuditor -Domain 'example.com' -DNSEndpoint 'udp://1.1.1.1:53' -SkipReportLaunch -PassThru

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $DNSEndpoint -eq 'udp://1.1.1.1:53' }
            }
        }

        It 'honors per-domain DKIM selectors from CSV metadata' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                $csvPath = Join-Path -Path $TestDrive -ChildPath 'domain-selectors.csv'
                @"
Domain,DKIMSelectors
example.com,alpha;beta
contoso.com,
"@ | Set-Content -Encoding UTF8 -Path $csvPath

                $null = Invoke-DomainSecurityAuditor -InputFile $csvPath -SkipReportLaunch -PassThru

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $Domain -eq 'example.com' -and $DkimSelector -and $DkimSelector -contains 'alpha' -and $DkimSelector -contains 'beta' }
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $Domain -eq 'contoso.com' -and -not $DkimSelector }
            }
        }

        It 'filters empty entries from malformed DKIM selector values' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                $csvPath = Join-Path -Path $TestDrive -ChildPath 'malformed-selectors.csv'
                @"
Domain,DKIMSelectors
example.com,"selector1,,selector2"
contoso.com,;alpha;;beta;
"@ | Set-Content -Encoding UTF8 -Path $csvPath

                $null = Invoke-DomainSecurityAuditor -InputFile $csvPath -SkipReportLaunch -PassThru

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $Domain -eq 'example.com' -and $DkimSelector -contains 'selector1' -and $DkimSelector -contains 'selector2' }
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $Domain -eq 'contoso.com' -and $DkimSelector -contains 'alpha' -and $DkimSelector -contains 'beta' }
            }
        }

        It 'flags missing MX records for active domains' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $evidence = New-TestEvidence
                    $evidence.Records.MX = @()
                    $evidence.Records.MXRecordCount = 0
                    $evidence
                }

                $result = Invoke-DomainSecurityAuditor -Domain 'example.com' -PassThru
                $auditProfile = $result | Select-Object -First 1
                $auditProfile.OverallStatus | Should -Be 'Fail'

                $mxCheck = $auditProfile.Checks | Where-Object { $_.Id -eq 'MXPresence' }
                $mxCheck.Status | Should -Be 'Fail'
                $auditProfile.ReportPath | Should -Be 'C:\Reports\domain_report.html'

                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
                Assert-MockCalled -CommandName Open-DSAReport -Times 1 -Scope It
            }
        }

        It 'enforces SPF lookup limits' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $evidence = New-TestEvidence
                    $evidence.Records.SPFLookupCount = 15
                    $evidence
                }

                $result = Invoke-DomainSecurityAuditor -Domain 'example.com' -PassThru
                $auditProfile = $result | Select-Object -First 1

                $spfLookup = $auditProfile.Checks | Where-Object { $_.Id -eq 'SPFLookupLimit' }
                $spfLookup.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
                Assert-MockCalled -CommandName Open-DSAReport -Times 1 -Scope It
            }
        }

        It 'requires Null MX for parked domains' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $evidence = New-TestEvidence -Classification 'Parked'
                    $evidence.Records.MXHasNull = $false
                    $evidence
                }

                $result = Invoke-DomainSecurityAuditor -Domain 'example.com' -PassThru
                $auditProfile = $result | Select-Object -First 1
                $auditProfile.Classification | Should -Match 'Parked'

                $nullMxCheck = $auditProfile.Checks | Where-Object { $_.Id -eq 'MXNullForParked' }
                $nullMxCheck.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
                Assert-MockCalled -CommandName Open-DSAReport -Times 1 -Scope It
            }
        }

        It 'accepts custom baseline files' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $evidence = New-TestEvidence
                    $evidence.Records.SPFLookupCount = 6
                    $evidence
                }

                $profilePath = Join-Path -Path $TestDrive -ChildPath 'custom-baseline.psd1'
                $psd1Content = @"
@{
    Name = 'Custom Test Baseline'
    Version = '1.0'
    Profiles = @{
        SendingAndReceiving = @{
            Name = 'SendingAndReceiving'
            Checks = @(
                @{
                    Id = 'SPFLookupLimit'
                    Area = 'SPF'
                    Condition = 'LessThanOrEqual'
                    Target = 'Records.SPFLookupCount'
                    ExpectedValue = 5
                    Expectation = 'SPF lookups must remain under five.'
                    Remediation = 'Reduce include chains.'
                    Severity = 'High'
                    Enforcement = 'Required'
                    References = @()
                }
            )
        }
    }
}
"@
                Set-Content -Path $profilePath -Value $psd1Content -Encoding UTF8

                # Override the BeforeEach mock to load the custom baseline file
                Mock Get-DSABaseline {
                    param($ProfilePath, $ProfileName)
                    $definition = Import-PowerShellDataFile -Path $ProfilePath
                    [pscustomobject]@{
                        Name     = $definition.Name
                        Version  = $definition.Version
                        Profiles = $definition.Profiles
                    }
                } -ParameterFilter { $ProfilePath -eq $profilePath }

                $result = Invoke-DomainSecurityAuditor -Domain 'example.com' -BaselineProfilePath $profilePath -SkipReportLaunch -PassThru
                $auditProfile = $result | Select-Object -First 1
                $spfLookup = $auditProfile.Checks | Where-Object { $_.Id -eq 'SPFLookupLimit' }
                $spfLookup.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'skips report launch when requested' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence }

                $null = Invoke-DomainSecurityAuditor -Domain 'example.com' -SkipReportLaunch -PassThru
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'processes multiple domains' {
            InModuleScope DomainSecurityAuditor {
                $queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
                $queue.Enqueue((New-TestEvidence -Domain 'contoso.com'))
                $queue.Enqueue((New-TestEvidence -Domain 'example.com'))
                Mock -CommandName Get-DSADomainEvidence -MockWith { $queue.Dequeue() }

                $result = Invoke-DomainSecurityAuditor -Domain 'contoso.com', 'example.com' -SkipReportLaunch -PassThru
                $result.Count | Should -Be 2
                ($result | Select-Object -ExpandProperty Domain) | Should -Contain 'example.com'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 2 -Scope It
                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
            }
        }

        It 'accepts domains from input files' {
            InModuleScope DomainSecurityAuditor {
                $csvPath = Join-Path -Path $TestDrive -ChildPath 'domains.csv'
                @'
Domain
alpha.example
beta.example
'@ | Set-Content -Path $csvPath

                $queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
                $queue.Enqueue((New-TestEvidence -Domain 'alpha.example'))
                $queue.Enqueue((New-TestEvidence -Domain 'beta.example'))
                Mock -CommandName Get-DSADomainEvidence -MockWith { $queue.Dequeue() }

                $result = Invoke-DomainSecurityAuditor -InputFile $csvPath -SkipReportLaunch -PassThru
                $result.Count | Should -Be 2
                ($result | Select-Object -ExpandProperty Domain) | Should -Contain 'beta.example'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 2 -Scope It
            }
        }

        It 'falls back to newline-delimited lists when CSV headers are absent' {
            InModuleScope DomainSecurityAuditor {
                $txtPath = Join-Path -Path $TestDrive -ChildPath 'domains.txt'
                @'
gamma.example
delta.example
'@ | Set-Content -Path $txtPath

                $queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
                $queue.Enqueue((New-TestEvidence -Domain 'gamma.example'))
                $queue.Enqueue((New-TestEvidence -Domain 'delta.example'))
                Mock -CommandName Get-DSADomainEvidence -MockWith { $queue.Dequeue() }

                $result = Invoke-DomainSecurityAuditor -InputFile $txtPath -SkipReportLaunch -PassThru
                $result.Count | Should -Be 2
                ($result | Select-Object -ExpandProperty Domain) | Should -Contain 'gamma.example'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 2 -Scope It
            }
        }

        It 'honors classification overrides sourced from CSV metadata' {
            InModuleScope DomainSecurityAuditor {
                $csvPath = Join-Path -Path $TestDrive -ChildPath 'domains-with-metadata.csv'
                @'
Domain,Classification
override.example,SendingOnly
'@ | Set-Content -Path $csvPath

                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain 'override.example' -Classification 'Parked' }
                Mock -CommandName Invoke-DSABaselineTest -MockWith {
                    param(
                        $DomainEvidence,
                        $BaselineDefinition,
                        $ClassificationOverride
                    )

                    [pscustomobject]@{
                        Domain                 = $DomainEvidence.Domain
                        Classification         = if ($ClassificationOverride) { "Profile:$ClassificationOverride" } else { 'Profile:Default' }
                        OriginalClassification = $DomainEvidence.Classification
                        ClassificationOverride = $ClassificationOverride
                        OverallStatus          = 'Pass'
                        Checks                 = @()
                    }
                }

                $result = Invoke-DomainSecurityAuditor -InputFile $csvPath -SkipReportLaunch -PassThru
                $result.Count | Should -Be 1
                $result[0].ClassificationOverride | Should -Be 'SendingOnly'
                $result[0].OriginalClassification | Should -Be 'Parked'

                Assert-MockCalled -CommandName Invoke-DSABaselineTest -Times 1 -Scope It -ParameterFilter { $ClassificationOverride -eq 'SendingOnly' }
            }
        }

        It 'supports command-line classification overrides for direct domains' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain 'solo.example' -Classification 'ReceivingOnly' }
                Mock -CommandName Invoke-DSABaselineTest -MockWith {
                    param(
                        $DomainEvidence,
                        $BaselineDefinition,
                        $ClassificationOverride
                    )

                    [pscustomobject]@{
                        Domain                 = $DomainEvidence.Domain
                        Classification         = if ($ClassificationOverride) { "Profile:$ClassificationOverride" } else { 'Profile:Default' }
                        OriginalClassification = $DomainEvidence.Classification
                        ClassificationOverride = $ClassificationOverride
                        OverallStatus          = 'Pass'
                        Checks                 = @()
                    }
                }

                $result = Invoke-DomainSecurityAuditor -Domain 'solo.example' -Classification SendingOnly -SkipReportLaunch -PassThru
                $result.Count | Should -Be 1
                $result[0].ClassificationOverride | Should -Be 'SendingOnly'
                Assert-MockCalled -CommandName Invoke-DSABaselineTest -Times 1 -Scope It -ParameterFilter { $ClassificationOverride -eq 'SendingOnly' }
            }
        }

        It 'errors when CSV classification overrides contain unsupported values' {
            InModuleScope DomainSecurityAuditor {
                $csvPath = Join-Path -Path $TestDrive -ChildPath 'domains-invalid-metadata.csv'
                @'
Domain,Classification
invalid.example,Unknown
'@ | Set-Content -Path $csvPath

                Mock -CommandName Get-DSADomainEvidence -MockWith { throw 'Should not execute for invalid CSV override' }

                { Invoke-DomainSecurityAuditor -InputFile $csvPath -SkipReportLaunch } | Should -Throw -ExpectedMessage '*Allowed values*'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 0 -Scope It
            }
        }

        It 'errors when the command-line classification override is invalid' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { throw 'Should not execute for invalid CLI override' }

                { Invoke-DomainSecurityAuditor -Domain 'solo.example' -Classification 'InvalidType' -SkipReportLaunch } | Should -Throw -ExpectedMessage '*Allowed values*'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 0 -Scope It
            }
        }

        Context 'console output' {
            It 'emits pass, warning, and fail counts to the information stream' {
                InModuleScope DomainSecurityAuditor {
                    $originalPreference = $InformationPreference
                    $originalRendering = if ($PSStyle) { $PSStyle.OutputRendering } else { $null }
                    try {
                        $InformationPreference = 'SilentlyContinue'
                        if ($PSStyle) {
                            $PSStyle.OutputRendering = 'PlainText'
                        }
                        $auditProfile = [pscustomobject]@{
                            Domain                 = 'example.com'
                            Classification         = 'SendingAndReceiving'
                            OriginalClassification = 'SendingAndReceiving'
                            ClassificationOverride = $null
                            OverallStatus          = 'Warning'
                            Checks                 = @(
                                [pscustomobject]@{ Id = 'CheckPass'; Status = 'Pass'; Area = 'SPF' }
                                [pscustomobject]@{ Id = 'CheckWarn'; Status = 'Warning'; Area = 'DMARC' }
                                [pscustomobject]@{ Id = 'CheckFail'; Status = 'Fail'; Area = 'MX' }
                            )
                            Evidence               = [pscustomobject]@{
                                DKIMSelectorDetails = @()
                            }
                        }

                        $infoOutput = & {
                            Write-DSABaselineConsoleSummary -Profiles @($auditProfile) -ReportPath 'C:\Reports\domain_report.html'
                        } 6>&1

                        $stripAnsi = {
                            param($Value)
                            if (-not $Value) { return '' }
                            return ($Value.ToString() -replace "`e\\[[0-9;]*[A-Za-z]", '')
                        }

                        $infoMessages = @($infoOutput | ForEach-Object { & $stripAnsi $_ })

                        $infoMessages | Should -Contain 'Baselines complete (1 domain)'
                        $infoMessages | Should -Contain '  [WARN] example.com (Pass 1 | Warn 1 | Fail 1)'
                        $infoMessages | Should -Contain 'Report:'
                        $infoMessages | Should -Contain '  C:\Reports\domain_report.html'
                        $infoMessages | Should -Contain ''
                    }
                    finally {
                        if ($PSStyle -and $null -ne $originalRendering) {
                            $PSStyle.OutputRendering = $originalRendering
                        }
                        $InformationPreference = $originalPreference
                    }
                }
            }
        }
    }
}

Describe 'Get-DSADomainEvidence' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'collects evidence via Test-DDDomainOverallHealth and forwards DNS endpoint' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith { $null }
            Mock -CommandName Import-Module -MockWith { }

            $script:capturedDnsEndpoint = $null
            $script:capturedHealthChecks = @()
            $spf = [pscustomobject]@{
                SpfRecord         = 'v=spf1 -all'
                SpfRecords        = @('v=spf1 -all')
                DnsLookupsCount   = 0
                UnknownMechanisms = @()
                AllMechanism      = '-all'
                HasPtrType        = $false
                IncludeRecords    = @()
                DnsRecordTtl      = 1200
            }
            $dkimResult = [pscustomobject]@{
                DkimRecordExists  = $true
                Selector          = 'selector1'
                KeyLength         = 2048
                WeakKey           = $false
                ValidPublicKey    = $true
                ValidRsaKeyLength = $true
                DnsRecordTtl      = 600
            }
            $dkimAnalysis = [pscustomobject]@{
                AnalysisResults = @{ selector1 = $dkimResult }
            }
            $dmarc = [pscustomobject]@{
                DmarcRecord  = 'v=DMARC1; p=reject'
                Policy       = 'reject'
                MailtoRua    = @('rua@example.com')
                HttpRua      = @()
                MailtoRuf    = @()
                HttpRuf      = @()
                DnsRecordTtl = 400
            }
            $mx = [pscustomobject]@{
                MxRecords   = @('mx1.example')
                HasNullMx   = $false
                MinMxTtl    = 1800
            }
            $mtasts = [pscustomobject]@{
                DnsRecordPresent = $true
                PolicyValid      = $true
                Mode             = 'enforce'
                DnsRecordTtl     = 1800
            }
            $tlsrpt = [pscustomobject]@{
                TlsRptRecordExists = $true
                MailtoRua          = @('mailto:tls@example.com')
                HttpRua            = @()
                DnsRecordTtl       = 900
            }
            $ttlAnalysis = [pscustomobject]@{
                ServerTtlTxtSpf     = @{ '1.1.1.1' = 3500 }
                ServerTtlTxtDmarc   = @{ '1.1.1.1' = 4000 }
                ServerTtlTxtPerName = @{
                    'selector1._domainkey.example.com' = @{ '1.1.1.1' = 3200 }
                }
                ServerTtlTxtMtasts  = @{}
                ServerTtlTxtTlsRpt  = @{}
            }

            <#
            .SYNOPSIS
                Stubbed DomainDetective entry point for test validation.
            #>
            function Test-DDDomainOverallHealth {
                [CmdletBinding()]
                param($DomainName, $HealthCheckType, $DnsEndpoint, $DkimSelectors)
                $script:capturedDnsEndpoint = $DnsEndpoint
                $script:capturedHealthChecks = $HealthCheckType
                return [pscustomobject]@{
                    Raw = [pscustomobject]@{
                        SpfAnalysis     = $spf
                        DKIMAnalysis    = $dkimAnalysis
                        DmarcAnalysis   = $dmarc
                        MXAnalysis      = $mx
                        MTASTSAnalysis  = $mtasts
                        TLSRPTAnalysis  = $tlsrpt
                        DnsTtlAnalysis  = $ttlAnalysis
                    }
                }
            }

            <#
            .SYNOPSIS
                Stubbed classification function for test validation.
            #>
            function Test-DDMailDomainClassification {
                [CmdletBinding()]
                param($DomainName, $DnsEndpoint)
                return [pscustomobject]@{ Classification = 'SendingAndReceiving'; Raw = [pscustomobject]@{} }
            }

            $evidence = Get-DSADomainEvidence -Domain 'example.com' -DNSEndpoint 'udp://9.9.9.9:53'
            $evidence | Should -Not -BeNullOrEmpty
            $evidence.Records.SPFTtl | Should -Be 3500
            $evidence.Records.DMARCTtl | Should -Be 4000
            $evidence.Records.DKIMMinimumTtl | Should -Be 3200
            $evidence.Records.MXMinimumTtl | Should -Be 1800
            $evidence.Records.MTASTSMode | Should -Be 'enforce'
            $evidence.Records.TLSRPTAddresses | Should -Contain 'mailto:tls@example.com'

            $script:capturedDnsEndpoint | Should -Be 'udp://9.9.9.9:53'
            $script:capturedHealthChecks | Should -Contain 'TTL'
        }
    }

    It 'passes custom DKIM selectors to DomainOverallHealth and maps classification' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith { $null }
            Mock -CommandName Import-Module -MockWith { }

            $script:capturedSelectors = @()
            <#
            .SYNOPSIS
                Stubbed DomainDetective entry point for DKIM selector tests.
            #>
            function Test-DDDomainOverallHealth {
                [CmdletBinding()]
                param($DomainName, $HealthCheckType, $DnsEndpoint, $DkimSelectors)
                $script:capturedSelectors = $DkimSelectors
                return [pscustomobject]@{
                    Raw = [pscustomobject]@{
                        SpfAnalysis    = [pscustomobject]@{
                            SpfRecord         = 'v=spf1 -all'
                            SpfRecords        = @('v=spf1 -all')
                            DnsLookupsCount   = 0
                            UnknownMechanisms = @()
                            AllMechanism      = '-all'
                            HasPtrType        = $false
                            IncludeRecords    = @()
                            DnsRecordTtl      = 300
                        }
                        DKIMAnalysis   = [pscustomobject]@{
                            AnalysisResults = @{
                                alpha = [pscustomobject]@{
                                    DkimRecordExists  = $true
                                    Selector          = 'alpha'
                                    KeyLength         = 1024
                                    WeakKey           = $false
                                    ValidPublicKey    = $true
                                    ValidRsaKeyLength = $true
                                    DnsRecordTtl      = 500
                                }
                            }
                        }
                        DmarcAnalysis  = [pscustomobject]@{
                            DmarcRecord  = 'v=DMARC1; p=quarantine'
                            Policy       = 'quarantine'
                            MailtoRua    = @('mailto:rua@example.com')
                            HttpRua      = @()
                            MailtoRuf    = @()
                            HttpRuf      = @()
                            DnsRecordTtl = 600
                        }
                        MXAnalysis     = [pscustomobject]@{
                            MxRecords = @('mx1.example')
                            HasNullMx = $false
                            MinMxTtl  = 900
                        }
                        MTASTSAnalysis = [pscustomobject]@{
                            DnsRecordPresent = $false
                            PolicyValid      = $false
                            Mode             = $null
                            DnsRecordTtl     = $null
                        }
                        TLSRPTAnalysis = [pscustomobject]@{
                            TlsRptRecordExists = $false
                            MailtoRua          = @()
                            HttpRua            = @()
                            DnsRecordTtl       = $null
                        }
                        DnsTtlAnalysis = [pscustomobject]@{
                            ServerTtlTxtSpf     = @{ '1.1.1.1' = 300 }
                            ServerTtlTxtDmarc   = @{ '1.1.1.1' = 600 }
                            ServerTtlTxtPerName = @{
                                'alpha._domainkey.example.com' = @{ '1.1.1.1' = 500 }
                            }
                            ServerTtlTxtMtasts  = @{}
                            ServerTtlTxtTlsRpt  = @{}
                        }
                    }
                }
            }

            <#
            .SYNOPSIS
                Stubbed classification function for DKIM selector tests.
            #>
            function Test-DDMailDomainClassification {
                [CmdletBinding()]
                param($DomainName, $DnsEndpoint)
                return [pscustomobject]@{ Classification = 'ReceivingOnly'; Raw = [pscustomobject]@{} }
            }

            $evidence = Get-DSADomainEvidence -Domain 'example.com' -DkimSelector @('alpha', 'beta')
            $evidence.Classification | Should -Be 'ReceivingOnly'
            $evidence.Records.DKIMSelectors | Should -Contain 'alpha'
            $script:capturedSelectors | Should -Contain 'alpha'
            $script:capturedSelectors | Should -Contain 'beta'
        }
    }
}

Describe 'Baseline profile helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }
    It 'lists built-in profiles' {
        InModuleScope DomainSecurityAuditor {
            $profiles = Get-DSABaselineProfile
            ($profiles | Where-Object { $_.Name -eq 'Default' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'validates profile files' {
        InModuleScope DomainSecurityAuditor {
            $defaultProfile = Get-DSABaselineProfile -Name 'Default'
            $result = Test-DSABaselineProfile -Path $defaultProfile.Path
            $result.IsValid | Should -BeTrue
            $result.Errors.Count | Should -Be 0
        }
    }

    It 'creates copies from built-in profiles' {
        InModuleScope DomainSecurityAuditor {
            $target = Join-Path -Path $TestDrive -ChildPath 'Baseline.Copy.psd1'
            New-DSABaselineProfile -Path $target -SourceProfile 'Default' | Should -Be $target
            Test-Path -Path $target | Should -BeTrue
        }
    }

    It 'renders RFC references as clickable links' {
        InModuleScope DomainSecurityAuditor {
            $html = ConvertTo-DSAReferenceHtml -Reference 'RFC 7208 §3.1'
            $html | Should -Match '<a '
            $html | Should -Match 'rfc7208#section-3\.1'
        }
    }

    It 'renders known named references as clickable links' {
        InModuleScope DomainSecurityAuditor {
            $html = ConvertTo-DSAReferenceHtml -Reference 'M3AAWG Email Authentication Best Practices'
            $html | Should -Match '<a '
            $html | Should -Match 'm3aawg'
        }
    }
}

Describe 'Test-DSAProperty' {
    It 'returns true when PSObject has the property' {
        InModuleScope DomainSecurityAuditor {
            $obj = [pscustomobject]@{ Name = 'test'; Value = 42 }
            Test-DSAProperty -InputObject $obj -Name 'Name' | Should -BeTrue
            Test-DSAProperty -InputObject $obj -Name 'Value' | Should -BeTrue
        }
    }

    It 'returns false when PSObject lacks the property' {
        InModuleScope DomainSecurityAuditor {
            $obj = [pscustomobject]@{ Name = 'test' }
            Test-DSAProperty -InputObject $obj -Name 'Missing' | Should -BeFalse
        }
    }

    It 'returns true when hashtable contains the key' {
        InModuleScope DomainSecurityAuditor {
            $hash = @{ Name = 'test'; Count = 5 }
            Test-DSAProperty -InputObject $hash -Name 'Name' | Should -BeTrue
            Test-DSAProperty -InputObject $hash -Name 'Count' | Should -BeTrue
        }
    }

    It 'returns false when hashtable lacks the key' {
        InModuleScope DomainSecurityAuditor {
            $hash = @{ Name = 'test' }
            Test-DSAProperty -InputObject $hash -Name 'Missing' | Should -BeFalse
        }
    }

    It 'returns false for null input' {
        InModuleScope DomainSecurityAuditor {
            Test-DSAProperty -InputObject $null -Name 'Any' | Should -BeFalse
        }
    }
}

Describe 'Get-DSAStatusMetadata' {
    It 'returns correct metadata for Pass status' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status 'Pass'
            $meta.Class | Should -Be 'passed'
            $meta.Filter | Should -Be 'pass'
            $meta.Icon | Should -Be '✔'
        }
    }

    It 'returns correct metadata for Fail status' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status 'Fail'
            $meta.Class | Should -Be 'failed'
            $meta.Filter | Should -Be 'fail'
            $meta.Icon | Should -Be '✖'
        }
    }

    It 'returns correct metadata for Warning status' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status 'Warning'
            $meta.Class | Should -Be 'warning'
            $meta.Filter | Should -Be 'warning'
            $meta.Icon | Should -Be '!'
        }
    }

    It 'returns info metadata for unknown status' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status 'Unknown'
            $meta.Class | Should -Be 'info'
            $meta.Filter | Should -Be 'info'
            $meta.Icon | Should -Be 'ℹ'
        }
    }

    It 'returns info metadata for null or empty status' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status ''
            $meta.Class | Should -Be 'info'
            $meta.Filter | Should -Be 'info'

            $meta = Get-DSAStatusMetadata -Status $null
            $meta.Class | Should -Be 'info'
        }
    }

    It 'handles case-insensitive status values' {
        InModuleScope DomainSecurityAuditor {
            $meta = Get-DSAStatusMetadata -Status 'PASS'
            $meta.Class | Should -Be 'passed'

            $meta = Get-DSAStatusMetadata -Status 'fail'
            $meta.Class | Should -Be 'failed'

            $meta = Get-DSAStatusMetadata -Status 'WARNING'
            $meta.Class | Should -Be 'warning'
        }
    }
}

Describe 'Dependency helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'returns missing modules when they are not available' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith {
                param($Name, $ListAvailable)
                if ($ListAvailable -and ($Name -contains 'Present')) {
                    return [pscustomobject]@{ Name = 'Present' }
                }
            } -ParameterFilter { $ListAvailable -eq $true }

            $result = Test-DSADependency -Name @('Present', 'MissingOne')
            $result.IsCompliant | Should -BeFalse
            $result.MissingModules | Should -Contain 'MissingOne'
        }
    }

    It 'installs missing modules when Install-Module succeeds' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }

            $available = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            Mock -CommandName Get-Module -MockWith {
                param($Name, $ListAvailable)
                if ($ListAvailable -and $Name -and ($Name -is [System.Collections.IEnumerable])) {
                    $foundModules = @()
                    foreach ($entry in $Name) {
                        if ($available.Contains($entry)) {
                            $foundModules += [pscustomobject]@{ Name = $entry }
                        }
                    }
                    return $foundModules
                }
                if ($ListAvailable -and $Name -and $available.Contains($Name)) {
                    return [pscustomobject]@{ Name = $Name }
                }
            } -ParameterFilter { $ListAvailable -eq $true }

            function Install-Module { param($Name) }
            Mock -CommandName Install-Module -MockWith {
                param($Name)
                $null = $available.Add($Name)
            }

            $result = Test-DSADependency -Name @('DomainDetective') -AttemptInstallation
            $result.IsCompliant | Should -BeTrue
            $result.MissingModules.Count | Should -Be 0
            Assert-MockCalled -CommandName Install-Module -Times 1 -Scope It -Exactly -ParameterFilter { $Name -eq 'DomainDetective' }
        }
    }

    It 'throws and logs when dependencies remain missing' {
        InModuleScope DomainSecurityAuditor {
            $logged = [System.Collections.Generic.List[string]]::new()
            Mock -CommandName Write-DSALog -MockWith {
                param($Message)
                $logged.Add($Message) | Out-Null
            }

            Mock -CommandName Test-DSADependency -MockWith {
                [pscustomobject]@{
                    MissingModules = @('Pester')
                    IsCompliant    = $false
                }
            }

            { Confirm-DSADependencies -Name @('Pester') -LogFile 'log.txt' } | Should -Throw -ExpectedMessage '*Missing dependencies*'
            ($logged -join ' ') | Should -Match 'Missing dependencies: Pester'
        }
    }

    It 'imports DomainDetective only once per session' {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
            $script:DSADomainDetectiveLoaded = $true
            $importCount = 0
            Mock -CommandName Get-Module -MockWith { throw 'should not query modules' }
            Mock -CommandName Import-Module -MockWith { $importCount++ }

            Import-DSADomainDetectiveModule

            $importCount | Should -Be 0
            $script:DSADomainDetectiveLoaded | Should -BeTrue
        }
    }
}

Describe 'Path and run context helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'rejects invalid paths and overly long paths' {
        InModuleScope DomainSecurityAuditor {
            $invalidChar = [System.IO.Path]::GetInvalidPathChars() | Select-Object -First 1
            $invalidPath = "Invalid${invalidChar}Path"
            { Resolve-DSAPath -Path $invalidPath } | Should -Throw -ExpectedMessage '*invalid characters*'

            $longName = 'a' * 221
            $longPath = Join-Path -Path $TestDrive -ChildPath "$longName.txt"
            { Resolve-DSAPath -Path $longPath -PathType 'File' -EnsureExists } | Should -Throw -ExpectedMessage '*exceeds*'
        }
    }

    It 'creates directories and files when EnsureExists is specified' {
        InModuleScope DomainSecurityAuditor {
            $dirPath = Join-Path -Path $TestDrive -ChildPath 'nested/dir'
            $resolvedDir = Resolve-DSAPath -Path $dirPath -EnsureExists
            Test-Path -Path $resolvedDir | Should -BeTrue

            $filePath = Join-Path -Path $TestDrive -ChildPath 'files/example.txt'
            $resolvedFile = Resolve-DSAPath -Path $filePath -PathType 'File' -EnsureExists
            Test-Path -Path $resolvedFile | Should -BeTrue
        }
    }

    It 'initializes run context and prunes logs' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Start-Transcript -MockWith { }
            Mock -CommandName Invoke-DSALogRetention -MockWith { }
            Mock -CommandName Write-DSALog -MockWith { }

            $context = New-DSARunContext -OutputRoot $TestDrive -LogRoot $TestDrive -RetentionCount 2
            $context.LogFile | Should -Not -BeNullOrEmpty
            $context.OutputRoot | Should -Not -BeNullOrEmpty
            $context.TranscriptStarted | Should -BeTrue

            Assert-MockCalled -CommandName Invoke-DSALogRetention -Times 1 -Scope It
            Assert-MockCalled -CommandName Start-Transcript -Times 1 -Scope It
        }
    }

    It 'logs a warning when transcript start fails' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Invoke-DSALogRetention -MockWith { }
            Mock -CommandName Start-Transcript -MockWith { throw 'transcript failure' }
            $logged = [System.Collections.Generic.List[string]]::new()
            Mock -CommandName Write-DSALog -MockWith {
                param($Message)
                $logged.Add($Message) | Out-Null
            }

            $context = New-DSARunContext -OutputRoot $TestDrive -LogRoot $TestDrive
            $context.TranscriptStarted | Should -BeFalse
            ($logged -join ' ') | Should -Match 'Failed to start transcript'
        }
    }
}

Describe 'Baseline validation helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'flags duplicate check identifiers' {
        InModuleScope DomainSecurityAuditor {
            $path = Join-Path -Path $TestDrive -ChildPath 'Baseline.Duplicate.psd1'
            @"
@{
    Profiles = @{
        Default = @{
            Checks = @(
                @{ Id = 'Dup'; Condition = 'MustExist'; Target = 'Records.MX'; Area = 'MX'; Severity = 'High' },
                @{ Id = 'Dup'; Condition = 'MustExist'; Target = 'Records.SPFRecord'; Area = 'SPF'; Severity = 'High' }
            )
        }
    }
}
"@ | Set-Content -Path $path -Encoding UTF8

            $result = Test-DSABaselineProfile -Path $path
            $result.IsValid | Should -BeFalse
            ($result.Errors -join ' ') | Should -Match 'duplicate check Id'
        }
    }

    It 'detects missing required properties and invalid ExpectedValue' {
        InModuleScope DomainSecurityAuditor {
            $path = Join-Path -Path $TestDrive -ChildPath 'Baseline.Invalid.psd1'
            @'
@{
    Profiles = @{
        Default = @{
            Checks = @(
                @{ Id = 'MissingTarget'; Condition = 'MustContain'; Area = 'SPF'; Severity = 'High' },
                @{ Id = 'BadExpected'; Condition = 'MustContain'; Target = 'Records.SPFRecord'; Area = 'SPF'; Severity = 'High'; ExpectedValue = $null }
            )
        }
    }
}
'@ | Set-Content -Path $path -Encoding UTF8

            $result = Test-DSABaselineProfile -Path $path
            $result.IsValid | Should -BeFalse
            ($result.Errors -join ' ') | Should -Match 'missing required property'
            ($result.Errors -join ' ') | Should -Match 'define an ExpectedValue'
        }
    }

    It 'rejects unsupported baseline file extensions' {
        InModuleScope DomainSecurityAuditor {
            $path = Join-Path -Path $TestDrive -ChildPath 'Baseline.txt'
            Set-Content -Path $path -Value 'content' -Encoding UTF8
            { Import-DSABaselineConfig -Path $path } | Should -Throw -ExpectedMessage '*Unsupported baseline profile extension*'
        }
    }

    It 'throws when named baseline profile is missing' {
        InModuleScope DomainSecurityAuditor {
            { Get-DSABaseline -ProfileName 'DoesNotExist' } | Should -Throw -ExpectedMessage '*not found*'
        }
    }
}

Describe 'Condition and value helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'validates ExpectedValue payloads' {
        InModuleScope DomainSecurityAuditor {
            $validation = Test-DSAConditionExpectedValue -Condition 'MustContain' -ExpectedValue $null
            $validation.IsValid | Should -BeFalse
            $validation.Message | Should -Match 'ExpectedValue'

            $rangeValidation = Test-DSAConditionExpectedValue -Condition 'BetweenInclusive' -ExpectedValue @{ Min = $null; Max = $null }
            $rangeValidation.IsValid | Should -BeFalse
        }
    }

    It 'evaluates baseline conditions correctly' -TestCases @(
        @{ Condition = 'MustContain'; Value = 'spf include'; ExpectedValue = 'include'; ExpectedResult = $true }
        @{ Condition = 'MustNotContain'; Value = @('ptr', 'mx'); ExpectedValue = @('ptr'); ExpectedResult = $false }
        @{ Condition = 'MustBeOneOf'; Value = 'Reject'; ExpectedValue = @('Reject', 'Quarantine'); ExpectedResult = $true }
        @{ Condition = 'LessThanOrEqual'; Value = 5; ExpectedValue = 10; ExpectedResult = $true }
        @{ Condition = 'LessThanOrEqual'; Value = '5'; ExpectedValue = 10; ExpectedResult = $true }
        @{ Condition = 'BetweenInclusive'; Value = 400; ExpectedValue = @{ Min = 300; Max = 600 }; ExpectedResult = $true }
        @{ Condition = 'BetweenInclusive'; Value = 'non-numeric'; ExpectedValue = @{ Min = 300; Max = 600 }; ExpectedResult = $false }
        @{ Condition = 'MustBeEmpty'; Value = @(); ExpectedValue = $null; ExpectedResult = $true }
        @{ Condition = 'UnsupportedCondition'; Value = 'value'; ExpectedValue = $null; ExpectedResult = $false }
    ) {
        param($Condition, $Value, $ExpectedValue, $ExpectedResult)

        InModuleScope DomainSecurityAuditor -Parameters $_ {
            $result = Test-DSABaselineCondition -Condition $Condition -Value $Value -ExpectedValue $ExpectedValue
            $result | Should -Be $ExpectedResult
        }
    }

    It 'normalizes and formats values' {
        InModuleScope DomainSecurityAuditor {
            (ConvertTo-DSABaselineArray -Value $null).Count | Should -Be 0
            (@(ConvertTo-DSABaselineArray -Value 'solo')).Count | Should -Be 1
            Format-DSAActualValue -Value $null | Should -Be 'None'
            Format-DSAActualValue -Value @($null) | Should -Be 'None'
            Format-DSAActualValue -Value @('a', 'b') | Should -Be 'a, b'
        }
    }
}

Describe 'DKIM and status helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'evaluates DKIM selector status using default minimum key length' {
        InModuleScope DomainSecurityAuditor {
            $check = [pscustomobject]@{
                Id      = 'DKIMKeyStrength'
                Area    = 'DKIM'
                Status  = 'Pass'
                Severity = 'High'
            }
            $selector = [pscustomobject]@{
                Selector         = 'sel1'
                DkimRecordExists = $true
                KeyLength        = 512
                ValidPublicKey   = $true
                ValidRsaKeyLength = $true
                WeakKey          = $false
            }

            $status = Get-DSADkimSelectorStatus -Selector $selector -Check $check
            $status | Should -Be 'Fail'
        }
    }

    It 'fails selectors when required DKIM properties are missing' {
        InModuleScope DomainSecurityAuditor {
            $check = [pscustomobject]@{
                Id       = 'DKIMKeyStrength'
                Area     = 'DKIM'
                Status   = 'Pass'
                Severity = 'High'
            }
            $selector = [pscustomobject]@{
                Selector         = 'missing-fields'
                DkimRecordExists = $true
                WeakKey          = $false
            }

            Get-DSADkimSelectorStatus -Selector $selector -Check $check | Should -Be 'Fail'

            $ttlCheck = [pscustomobject]@{
                Id            = 'DKIMTtl'
                Area          = 'DKIM'
                Status        = 'Pass'
                ExpectedValue = @{ Min = 300; Max = 600 }
            }

            Get-DSADkimSelectorStatus -Selector $selector -Check $ttlCheck | Should -Be 'Fail'
        }
    }

    It 'applies TTL bounds and propagates selector failures' {
        InModuleScope DomainSecurityAuditor {
            $check = [pscustomobject]@{
                Id           = 'DKIMTtl'
                Area         = 'DKIM'
                Status       = 'Pass'
                ExpectedValue = @{ Min = 300; Max = 600 }
            }
            $selector = [pscustomobject]@{
                Selector = 'sel2'
                DkimRecordExists = $true
                KeyLength = 2048
                ValidPublicKey = $true
                ValidRsaKeyLength = $true
                DnsRecordTtl = 120
            }
            $status = Get-DSADkimSelectorStatus -Selector $selector -Check $check
            $status | Should -Be 'Fail'

            $effective = Get-DSAEffectiveChecks -Checks @([pscustomobject]@{ Id = 'DKIMTtl'; Area = 'DKIM'; Status = 'Pass' }) -SelectorDetails @($selector)
            $effective[0].Status | Should -Be 'Fail'
        }
    }

    It 'counts statuses and handles DKIM-only overall status' {
        InModuleScope DomainSecurityAuditor {
            $checks = @(
                [pscustomobject]@{ Id = 'One'; Area = 'DKIM'; Status = 'Fail' },
                [pscustomobject]@{ Id = 'Two'; Area = 'DKIM'; Status = 'Pass' }
            )
            $counts = Get-DSAStatusCounts -Checks $checks
            $counts.Fail | Should -Be 1
            $counts.Pass | Should -Be 1
            $counts.Total | Should -Be 2

            $overall = Get-DSAOverallStatus -Checks $checks
            $overall | Should -Be 'Fail'
        }
    }
}

Describe 'Domain input and context helpers' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }

    It 'throws when no domains are supplied' {
        InModuleScope DomainSecurityAuditor {
            { Get-DSADomainInputState -CollectedDomains ([System.Collections.Generic.List[string]]::new()) -DomainMetadata @{} -DirectDomainSet ([System.Collections.Generic.HashSet[string]]::new()) } | Should -Throw -ExpectedMessage '*No domains were supplied*'
        }
    }

    It 'falls back to newline-delimited files when CSV import fails' {
        InModuleScope DomainSecurityAuditor {
            $inputPath = Join-Path -Path $TestDrive -ChildPath 'domains.txt'
            @'
alpha.example
beta.example
'@ | Set-Content -Path $inputPath -Encoding UTF8

            $logFile = Join-Path -Path $TestDrive -ChildPath 'log.txt'
            Mock -CommandName Write-DSALog -MockWith { }

            $state = Get-DSADomainInputState -CollectedDomains ([System.Collections.Generic.List[string]]::new()) -DomainMetadata @{} -DirectDomainSet ([System.Collections.Generic.HashSet[string]]::new()) -InputFile $inputPath -LogFile $logFile
            $state.TargetDomains | Should -Contain 'alpha.example'
            $state.TargetDomains | Should -Contain 'beta.example'
        }
    }

    It 'prefers metadata classification over parameter overrides and applies global selectors' {
        InModuleScope DomainSecurityAuditor {
            $metadata = @{
                'example.com' = [pscustomobject]@{
                    Classification       = 'SendingOnly'
                    ClassificationSource = 'CSV'
                }
            }
            $direct = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $direct.Add('example.com') | Out-Null

            $context = Resolve-DSADomainContext -DomainName 'example.com' -DomainMetadata $metadata -DirectDomainSet $direct -DefaultClassificationOverride 'ReceivingOnly' -GlobalDkimSelectors @('alpha') -ResolvedDnsEndpoint 'udp://1.1.1.1:53'
            $context.ClassificationOverride | Should -Be 'SendingOnly'
            $context.ClassificationSource | Should -Be 'CSV'
            $context.DkimSelectors | Should -Contain 'alpha'
            $context.ResolvedDnsEndpoint | Should -Be 'udp://1.1.1.1:53'
        }
    }

    It 'applies parameter classification overrides for direct domains when metadata is absent' {
        InModuleScope DomainSecurityAuditor {
            $metadata = @{}
            $direct = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $direct.Add('nocsv.example') | Out-Null

            $context = Resolve-DSADomainContext -DomainName 'nocsv.example' -DomainMetadata $metadata -DirectDomainSet $direct -DefaultClassificationOverride 'ReceivingOnly' -GlobalDkimSelectors @()
            $context.ClassificationOverride | Should -Be 'ReceivingOnly'
            $context.ClassificationSource | Should -Be 'Parameter'
        }
    }
}
