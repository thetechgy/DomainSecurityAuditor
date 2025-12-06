BeforeAll {
    $stubModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Stubs'
    if (Test-Path -Path $stubModuleRoot) {
        $env:PSModulePath = "{0}{1}{2}" -f $stubModuleRoot, [System.IO.Path]::PathSeparator, $env:PSModulePath
    }

    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force
}

Describe 'Publish-DSAHtmlReport' {
    AfterEach {
        InModuleScope DomainSecurityAuditor {
            Reset-DSAModuleState
        }
    }
    It 'renders expected header and footer metadata' {
        InModuleScope DomainSecurityAuditor {
            $profile = [pscustomobject]@{
                Domain                 = 'example.com'
                Classification         = 'Default'
                OriginalClassification = 'SendingOnly'
                ClassificationOverride = $null
                OverallStatus          = 'Pass'
                Checks                 = @()
                Timestamp              = (Get-Date)
                Evidence               = [pscustomobject]@{}
            }

            $outputRoot = Join-Path -Path $TestDrive -ChildPath 'Output'
            $reportPath = Publish-DSAHtmlReport -Profiles $profile -OutputRoot $outputRoot -GeneratedOn (Get-Date)
            Test-Path -Path $reportPath | Should -BeTrue

            $content = Get-Content -Path $reportPath -Raw
            ($content -like '*Collected:*') | Should -BeTrue
            ($content -match 'Test Suite') | Should -BeTrue
            $content.Contains('DomainSecurityAuditor v') | Should -BeTrue
            $content.Contains('DomainSecurityAuditor on GitHub') | Should -BeTrue
        }
    }

    It 'renders DKIM selectors within the DKIM section' {
        InModuleScope DomainSecurityAuditor {
            $profile = [pscustomobject]@{
                Domain                 = 'example.com'
                Classification         = 'Default'
                OriginalClassification = 'SendingOnly'
                ClassificationOverride = $null
                OverallStatus          = 'Pass'
                Checks                 = @(
                    [pscustomobject]@{
                        Id          = 'DKIMKeyStrength'
                        Area        = 'DKIM'
                        Status      = 'Pass'
                        Severity    = 'High'
                        Enforcement = 'Required'
                        Expectation = 'Ensure DKIM selectors are strong.'
                        Actual      = 'selector1, selector2, missing'
                        Remediation = ''
                        References  = @()
                        ExpectedValue = 1024
                    }
                )
                Timestamp              = (Get-Date)
                Evidence               = [pscustomobject]@{
                    DKIMSelectorDetails = @(
                        [pscustomobject]@{ Name = 'selector1'; KeyLength = 2048; Ttl = 3600; IsValid = $true; Found = $true }
                        [pscustomobject]@{ Name = 'selector2'; KeyLength = 768; Ttl = 7200; IsValid = $false; Found = $true }
                        [pscustomobject]@{ Name = 'missing'; KeyLength = $null; Ttl = $null; IsValid = $false; Found = $false }
                    )
                }
            }

            $outputRoot = Join-Path -Path $TestDrive -ChildPath 'Output'
            $reportPath = Publish-DSAHtmlReport -Profiles $profile -OutputRoot $outputRoot -GeneratedOn (Get-Date)
            $content = Get-Content -Path $reportPath -Raw
            $content | Should -Match 'Selector details'
            $content | Should -Match 'selector1'
            $content | Should -Match 'selector2'
            $content | Should -Match 'missing'
            $content | Should -Match 'Key: 2048'
        }
    }

    It 'handles profiles with no checks' {
        InModuleScope DomainSecurityAuditor {
            $profile = [pscustomobject]@{
                Domain                 = 'example.com'
                Classification         = 'Default'
                OriginalClassification = 'SendingOnly'
                ClassificationOverride = $null
                OverallStatus          = 'Pass'
                Checks                 = @()
                Timestamp              = (Get-Date)
                Evidence               = [pscustomobject]@{}
            }

            $summary = Get-DSAReportSummary -Profiles $profile
            $summary.TotalChecks | Should -Be 0
            $summary.DomainCount | Should -Be 1
        }
    }
}

Describe 'Resolve-DSAClassificationOverride' {
    It 'rejects blank override values' {
        InModuleScope DomainSecurityAuditor {
            { Resolve-DSAClassificationOverride -Value '' -SourceDescription 'test parameter' } | Should -Throw -ExpectedMessage '*cannot be empty*Allowed values*'
        }
    }
}
