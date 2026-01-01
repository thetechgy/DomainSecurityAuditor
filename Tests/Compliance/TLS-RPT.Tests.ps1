<#
.SYNOPSIS
    TLS-RPT compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate TLS-RPT configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/TLS-RPT' -Tag 'TLS-RPT' {
    BeforeAll {
        # Evidence is injected into script scope before Pester runs
        $script:Records = $global:ComplianceTestEvidence.Records
    }

    Context 'TLS-RPT Record Presence' {
        It 'TLSRPTPresence: TLS-RPT TXT record must exist' -Tag 'TLSRPTPresence', 'Required', 'Medium' {
            $script:Records.TLSRPTRecordPresent | Should -BeTrue
        }
    }

    Context 'TLS-RPT Reporting' {
        It 'TLSRPTAddresses: At least one reporting address must be defined' -Tag 'TLSRPTAddresses', 'Required', 'Medium' {
            $script:Records.TLSRPTAddresses | Should -Not -BeNullOrEmpty
        }
    }

    Context 'TLS-RPT TTL' {
        It 'TLSRPTTtl: TTL should be between 1 and 7 days' -Tag 'TLSRPTTtl', 'Recommended', 'Low' {
            # Skip if no TTL available
            if ($null -eq $script:Records.TLSRPTTtl -or $script:Records.TLSRPTTtl -eq 0) {
                Set-ItResult -Skipped -Because 'No TLS-RPT TTL available to evaluate'
            }
            $script:Records.TLSRPTTtl | Should -BeGreaterOrEqual 86400
            $script:Records.TLSRPTTtl | Should -BeLessOrEqual 604800
        }
    }
}
