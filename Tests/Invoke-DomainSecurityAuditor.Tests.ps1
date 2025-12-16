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
            }

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
                        }
                    }
                }
            }

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
