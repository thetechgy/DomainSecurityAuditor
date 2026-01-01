<#
.SYNOPSIS
    MX compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate MX record configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/MX' -Tag 'MX' {
    BeforeAll {
        # Evidence is injected into global scope before Pester runs
        # See Invoke-DSAComplianceTests.ps1 for evidence injection
        $script:Records = $global:ComplianceTestEvidence.Records
        $script:Classification = $global:ComplianceTestEvidence.Classification
    }

    Context 'MX Record Presence' {
        It 'MXPresence: At least one MX record should exist for active domains' -Tag 'MXPresence', 'Required', 'Critical' -Skip:($script:Classification -eq 'Parked' -or $script:Classification -eq 'SendingOnly') {
            $script:Records.MXRecordCount | Should -BeGreaterOrEqual 1
        }
    }

    Context 'MX TTL' {
        It 'MXTtl: TTL should be between 1 and 24 hours' -Tag 'MXTtl', 'Recommended', 'Low' {
            # Skip if no TTL available
            if ($null -eq $script:Records.MXMinimumTtl -or $script:Records.MXMinimumTtl -eq 0) {
                Set-ItResult -Skipped -Because 'No MX TTL available to evaluate'
            }
            $script:Records.MXMinimumTtl | Should -BeGreaterOrEqual 3600
            $script:Records.MXMinimumTtl | Should -BeLessOrEqual 86400
        }
    }

    Context 'Parked Domain MX' -Tag 'Parked' {
        It 'MXNullForParked: Parked domains should publish null MX' -Tag 'MXNullForParked', 'Required', 'High' -Skip:($script:Classification -ne 'Parked') {
            $script:Records.MXHasNull | Should -BeTrue
        }
    }
}
