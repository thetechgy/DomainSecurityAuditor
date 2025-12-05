BeforeAll {
    $stubModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Stubs'
    if (Test-Path -Path $stubModuleRoot) {
        $env:PSModulePath = "{0}{1}{2}" -f $stubModuleRoot, [System.IO.Path]::PathSeparator, $env:PSModulePath
    }

    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force

    # Define test helper in global scope for InModuleScope access
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
        DKIMSelectorDetails   = @([pscustomobject]@{ Name = 'selector1'; KeyLength = 2048; IsValid = $true; TTL = 3600 })
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
}

AfterAll {
    Remove-Item -Path Function:\New-TestEvidence -ErrorAction SilentlyContinue
}

Describe 'Invoke-DomainSecurityBaseline' {
    It 'is exported by the module' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor -ErrorAction Stop
        $command | Should -Not -BeNullOrEmpty
    }

    It 'includes required parameters' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor
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

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -SkipReportLaunch -PassThru
                $result | Should -Not -BeNullOrEmpty

                $profile = $result | Select-Object -First 1
                $profile.Domain | Should -Be 'example.com'
                $profile.Checks.Count | Should -BeGreaterThan 0
                $profile.OverallStatus | Should -Be 'Pass'
                $profile.ReportPath | Should -Be 'C:\Reports\domain_report.html'

                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'uses DomainDetective default DKIM selectors when none are provided' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence }

                Invoke-DomainSecurityBaseline -Domain 'example.com' -SkipReportLaunch -PassThru | Out-Null

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { -not $DkimSelector }
            }
        }

        It 'passes custom DKIM selectors from parameters' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                Invoke-DomainSecurityBaseline -Domain 'example.com' -DkimSelector 'sel1','sel2' -SkipReportLaunch -PassThru | Out-Null

                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 1 -ParameterFilter { $DkimSelector -and $DkimSelector -contains 'sel1' -and $DkimSelector -contains 'sel2' }
            }
        }

        It 'passes DNSEndpoint through to evidence collection' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence -Domain $Domain }

                Invoke-DomainSecurityBaseline -Domain 'example.com' -DNSEndpoint 'udp://1.1.1.1:53' -SkipReportLaunch -PassThru | Out-Null

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

                Invoke-DomainSecurityBaseline -InputFile $csvPath -SkipReportLaunch -PassThru | Out-Null

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

                Invoke-DomainSecurityBaseline -InputFile $csvPath -SkipReportLaunch -PassThru | Out-Null

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

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -PassThru
                $profile = $result | Select-Object -First 1
                $profile.OverallStatus | Should -Be 'Fail'

                $mxCheck = $profile.Checks | Where-Object { $_.Id -eq 'MXPresence' }
                $mxCheck.Status | Should -Be 'Fail'
                $profile.ReportPath | Should -Be 'C:\Reports\domain_report.html'

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

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -PassThru
                $profile = $result | Select-Object -First 1

                $spfLookup = $profile.Checks | Where-Object { $_.Id -eq 'SPFLookupLimit' }
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

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -PassThru
                $profile = $result | Select-Object -First 1
                $profile.Classification | Should -Match 'Parked'

                $nullMxCheck = $profile.Checks | Where-Object { $_.Id -eq 'MXNullForParked' }
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

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -BaselineProfilePath $profilePath -SkipReportLaunch -PassThru
                $profile = $result | Select-Object -First 1
                $spfLookup = $profile.Checks | Where-Object { $_.Id -eq 'SPFLookupLimit' }
                $spfLookup.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'skips report launch when requested' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { New-TestEvidence }

                Invoke-DomainSecurityBaseline -Domain 'example.com' -SkipReportLaunch -PassThru | Out-Null
                Assert-MockCalled -CommandName Open-DSAReport -Times 0 -Scope It
            }
        }

        It 'processes multiple domains' {
            InModuleScope DomainSecurityAuditor {
                $queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
                $queue.Enqueue((New-TestEvidence -Domain 'contoso.com'))
                $queue.Enqueue((New-TestEvidence -Domain 'example.com'))
                Mock -CommandName Get-DSADomainEvidence -MockWith { $queue.Dequeue() }

                $result = Invoke-DomainSecurityBaseline -Domain 'contoso.com','example.com' -SkipReportLaunch -PassThru
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

                $result = Invoke-DomainSecurityBaseline -InputFile $csvPath -SkipReportLaunch -PassThru
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

                $result = Invoke-DomainSecurityBaseline -InputFile $txtPath -SkipReportLaunch -PassThru
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

                $result = Invoke-DomainSecurityBaseline -InputFile $csvPath -SkipReportLaunch -PassThru
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

                $result = Invoke-DomainSecurityBaseline -Domain 'solo.example' -Classification SendingOnly -SkipReportLaunch -PassThru
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

                { Invoke-DomainSecurityBaseline -InputFile $csvPath -SkipReportLaunch } | Should -Throw -ExpectedMessage '*Allowed values*'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 0 -Scope It
            }
        }

        It 'errors when the command-line classification override is invalid' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith { throw 'Should not execute for invalid CLI override' }

                { Invoke-DomainSecurityBaseline -Domain 'solo.example' -Classification 'InvalidType' -SkipReportLaunch } | Should -Throw -ExpectedMessage '*Allowed values*'
                Assert-MockCalled -CommandName Get-DSADomainEvidence -Times 0 -Scope It
            }
        }

    }
}

Describe 'Get-DSADomainEvidence' {
    It 'forwards DNSEndpoint to DomainDetective health checks' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith { $null }
            Mock -CommandName Import-Module -MockWith { }
            Mock -CommandName Invoke-DSADomainDetectiveHealth -ModuleName DomainSecurityAuditor -MockWith {
                [pscustomobject]@{
                    Result = [pscustomobject]@{
                        Raw = [pscustomobject]@{
                            Summary       = [pscustomobject]@{ HasMxRecord = $true; HasSpfRecord = $true; HasDmarcRecord = $true }
                            MXAnalysis     = [pscustomobject]@{ MxRecords = @('mx1.example'); HasNullMx = $false }
                            SpfAnalysis    = [pscustomobject]@{
                                SpfRecord        = 'v=spf1 -all'
                                SpfRecords       = @('v=spf1 -all')
                                DnsLookupsCount  = 0
                                AllMechanism     = '-all'
                                HasPtrType       = $false
                                IncludeRecords   = @()
                                UnknownMechanisms = @()
                            }
                            DKIMAnalysis   = [pscustomobject]@{
                                AnalysisResults = @{
                                    'selector1' = [pscustomobject]@{ KeyLength = 2048; Ttl = 3600; IsValid = $true }
                                }
                            }
                            DmarcAnalysis  = [pscustomobject]@{
                                DmarcRecord = 'v=DMARC1; p=reject'
                                Policy      = 'reject'
                                MailtoRua   = @()
                                HttpRua     = @()
                                MailtoRuf   = @()
                                HttpRuf     = @()
                            }
                            MTASTSAnalysis = [pscustomobject]@{ DnsRecordPresent = $true; PolicyValid = $true; Mode = 'enforce'; MaxAge = 86400 }
                            TLSRPTAnalysis = [pscustomobject]@{
                                TlsRptRecordExists = $true
                                MailtoRua          = @()
                                HttpRua            = @()
                            }
                        }
                    }
                    Warnings = @()
                }
            } -ParameterFilter { $Parameters['DnsEndpoint'] -eq 'udp://9.9.9.9:53' }

            $evidence = Get-DSADomainEvidence -Domain 'example.com' -DNSEndpoint 'udp://9.9.9.9:53'
            $evidence | Should -Not -BeNullOrEmpty
            Assert-MockCalled -CommandName Invoke-DSADomainDetectiveHealth -Times 1 -ParameterFilter { $Parameters['DnsEndpoint'] -eq 'udp://9.9.9.9:53' -and $Parameters['HealthCheckType'] -contains 'SPF' }
        }
    }

    It 'captures all requested DKIM selectors without stopping at first match' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith { $null }
            Mock -CommandName Import-Module -MockWith { }
            Mock -CommandName Invoke-DSADomainDetectiveHealth -ModuleName DomainSecurityAuditor -MockWith {
                [pscustomobject]@{
                    Result = [pscustomobject]@{
                        Raw = [pscustomobject]@{
                            Summary       = [pscustomobject]@{
                                HasMxRecord    = $true
                                HasSpfRecord   = $true
                                HasDmarcRecord = $true
                            }
                            MXAnalysis     = [pscustomobject]@{ MxRecords = @('mx1.example'); HasNullMx = $false }
                            SpfAnalysis    = [pscustomobject]@{
                                SpfRecord        = 'v=spf1 -all'
                                SpfRecords       = @('v=spf1 -all')
                                DnsLookupsCount  = 1
                                AllMechanism     = '-all'
                                HasPtrType       = $false
                                IncludeRecords   = @()
                                UnknownMechanisms = @()
                            }
                            DKIMAnalysis   = [pscustomobject]@{
                                AnalysisResults = @{
                                    'selector1' = [pscustomobject]@{ KeyLength = 2048; Ttl = 3600; IsValid = $true }
                                    'selector2' = [pscustomobject]@{ KeyLength = 768; Ttl = 7200; IsValid = $false }
                                }
                            }
                            DmarcAnalysis  = [pscustomobject]@{
                                DmarcRecord = 'v=DMARC1; p=reject'
                                Policy      = 'reject'
                                MailtoRua   = @('mailto:rua@example.com')
                                HttpRua     = @()
                                MailtoRuf   = @()
                                HttpRuf     = @()
                            }
                            MTASTSAnalysis = [pscustomobject]@{ DnsRecordPresent = $true; PolicyValid = $true; Mode = 'enforce'; MaxAge = 86400 }
                            TLSRPTAnalysis = [pscustomobject]@{
                                TlsRptRecordExists = $true
                                MailtoRua          = @('mailto:tls@example.com')
                                HttpRua            = @()
                            }
                        }
                    }
                    Warnings = @()
                }
            }

            $evidence = Get-DSADomainEvidence -Domain 'example.com' -DkimSelector @('selector1', 'missing-selector')
            $evidence.Records.DKIMSelectors | Should -Contain 'selector1'
            $evidence.Records.DKIMSelectors | Should -Contain 'selector2'
            $evidence.Records.DKIMSelectors | Should -Not -Contain 'missing-selector'

            $missing = $evidence.Records.DKIMSelectorDetails | Where-Object { $_.Name -eq 'missing-selector' }
            $missing | Should -Not -BeNullOrEmpty
            $missing.Found | Should -BeFalse
            $missing.IsValid | Should -BeFalse

            $weakCount = $evidence.Records.DKIMWeakSelectors
            $weakCount | Should -BeGreaterThan 0
        }
    }

    It 'does not report missing selectors when relying on DomainDetective defaults' {
        InModuleScope DomainSecurityAuditor {
            Mock -CommandName Write-DSALog -MockWith { }
            Mock -CommandName Get-Module -MockWith { $null }
            Mock -CommandName Import-Module -MockWith { }
            Mock -CommandName Invoke-DSADomainDetectiveHealth -ModuleName DomainSecurityAuditor -MockWith {
                [pscustomobject]@{
                    Result = [pscustomobject]@{
                        Raw = [pscustomobject]@{
                            Summary       = [pscustomobject]@{ HasMxRecord = $true; HasSpfRecord = $true; HasDmarcRecord = $true }
                            MXAnalysis     = [pscustomobject]@{ MxRecords = @('mx1.example'); HasNullMx = $false }
                            SpfAnalysis    = [pscustomobject]@{
                                SpfRecord        = 'v=spf1 -all'
                                SpfRecords       = @('v=spf1 -all')
                                DnsLookupsCount  = 1
                                AllMechanism     = '-all'
                                HasPtrType       = $false
                                IncludeRecords   = @()
                                UnknownMechanisms = @()
                            }
                            DKIMAnalysis   = [pscustomobject]@{
                                AnalysisResults = @{
                                    'selector1' = [pscustomobject]@{ KeyLength = 2048; Ttl = 3600; IsValid = $true }
                                }
                            }
                            DmarcAnalysis  = [pscustomobject]@{
                                DmarcRecord = 'v=DMARC1; p=reject'
                                Policy      = 'reject'
                                MailtoRua   = @('mailto:rua@example.com')
                                HttpRua     = @()
                                MailtoRuf   = @()
                                HttpRuf     = @()
                            }
                            MTASTSAnalysis = [pscustomobject]@{ DnsRecordPresent = $true; PolicyValid = $true; Mode = 'enforce'; MaxAge = 86400 }
                            TLSRPTAnalysis = [pscustomobject]@{
                                TlsRptRecordExists = $true
                                MailtoRua          = @('mailto:tls@example.com')
                                HttpRua            = @()
                            }
                        }
                    }
                    Warnings = @()
                }
            }

            $evidence = Get-DSADomainEvidence -Domain 'example.com'
            $evidence.Records.DKIMSelectors | Should -Contain 'selector1'
            $evidence.Records.DKIMSelectorDetails | Where-Object { $_.Found -eq $false } | Should -BeNullOrEmpty
        }
    }
}

Describe 'Baseline profile helpers' {
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
