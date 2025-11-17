BeforeAll {
    $stubModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Stubs'
    if (Test-Path -Path $stubModuleRoot) {
        $env:PSModulePath = "{0}{1}{2}" -f $stubModuleRoot, [System.IO.Path]::PathSeparator, $env:PSModulePath
    }

    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force

    InModuleScope DomainSecurityAuditor {
        function New-TestEvidence {
            param (
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
                Domain         = 'example.com'
                Classification = $Classification
                Records        = $records
            }

            if ($Adjust) {
                & $Adjust -ArgumentList $evidence
            }

            return $evidence
        }
    }
}

Describe 'Invoke-DomainSecurityBaseline' {
    It 'is exported by the module' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor -ErrorAction Stop
        $command | Should -Not -BeNullOrEmpty
    }

    It 'includes required parameters' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor
        $command.Parameters.Keys | Should -Contain 'DryRun'
        $command.Parameters.Keys | Should -Contain 'ShowProgress'
        $command.Parameters.Keys | Should -Contain 'SkipDependencies'
        $command.Parameters.Keys | Should -Contain 'DkimSelector'
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
            }
        }

        It 'returns structured compliance data for dry runs' {
            InModuleScope DomainSecurityAuditor {
                $result = Invoke-DomainSecurityBaseline -Domain 'example.com' -DryRun
                $result | Should -Not -BeNullOrEmpty

                $profile = $result | Select-Object -First 1
                $profile.Domain | Should -Be 'example.com'
                $profile.Checks.Count | Should -BeGreaterThan 0
                $profile.OverallStatus | Should -Be 'Pass'
                $profile.ReportPath | Should -BeNullOrEmpty

                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 0 -Scope It
            }
        }

        It 'flags missing MX records for active domains' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $records = Get-DSADryRunRecords
                    $records.MX = @()
                    $records.MXRecordCount = 0
                    New-DSADomainEvidenceObject -Domain 'example.com' -Classification 'SendingAndReceiving' -Records $records
                }

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com'
                $profile = $result | Select-Object -First 1
                $profile.OverallStatus | Should -Be 'Fail'

                $mxCheck = $profile.Checks | Where-Object { $_.Id -eq 'MXPresence' }
                $mxCheck.Status | Should -Be 'Fail'
                $profile.ReportPath | Should -Be 'C:\Reports\domain_report.html'

                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
            }
        }

        It 'enforces SPF lookup limits' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $records = Get-DSADryRunRecords
                    $records.SPFLookupCount = 15
                    New-DSADomainEvidenceObject -Domain 'example.com' -Classification 'SendingAndReceiving' -Records $records
                }

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com'
                $profile = $result | Select-Object -First 1

                $spfLookup = $profile.Checks | Where-Object { $_.Id -eq 'SPFLookupLimit' }
                $spfLookup.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
            }
        }

        It 'requires Null MX for parked domains' {
            InModuleScope DomainSecurityAuditor {
                Mock -CommandName Get-DSADomainEvidence -MockWith {
                    $records = Get-DSADryRunRecords
                    $records.MXHasNull = $false
                    New-DSADomainEvidenceObject -Domain 'example.com' -Classification 'Parked' -Records $records
                }

                $result = Invoke-DomainSecurityBaseline -Domain 'example.com'
                $profile = $result | Select-Object -First 1
                $profile.Classification | Should -Match 'Parked'

                $nullMxCheck = $profile.Checks | Where-Object { $_.Id -eq 'MXNullForParked' }
                $nullMxCheck.Status | Should -Be 'Fail'
                Assert-MockCalled -CommandName Publish-DSAHtmlReport -Times 1 -Scope It
            }
        }
    }
}
