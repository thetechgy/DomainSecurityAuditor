<#
.SYNOPSIS
    DMARC compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate DMARC record configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/DMARC' -Tag 'DMARC' {
    BeforeAll {
        # Evidence is injected into script scope before Pester runs
        $script:Records = $global:ComplianceTestEvidence.Records
        $script:Classification = $global:ComplianceTestEvidence.Classification
    }

    Context 'DMARC Record Presence' {
        It 'DMARCPresence: DMARC record must exist' -Tag 'DMARCPresence', 'Required', 'Critical' {
            $script:Records.DMARCRecord | Should -Not -BeNullOrEmpty
        }
    }

    Context 'DMARC Policy' {
        It 'DMARCPolicyStrength: Policy should be quarantine or reject' -Tag 'DMARCPolicyStrength', 'Required', 'High' {
            $script:Records.DMARCPolicy | Should -BeIn @('quarantine', 'reject')
        }
    }

    Context 'DMARC Reporting' {
        It 'DMARCRuaPresence: At least one RUA address must be defined' -Tag 'DMARCRuaPresence', 'Required', 'Medium' {
            $script:Records.DMARCRuaAddresses | Should -Not -BeNullOrEmpty
        }

        It 'DMARCRufOmission: Avoid RUF forensic feeds unless required' -Tag 'DMARCRufOmission', 'Recommended', 'Low' {
            $script:Records.DMARCRufAddresses | Should -BeNullOrEmpty
        }
    }

    Context 'DMARC TTL' {
        It 'DMARCTtl: TTL should be between 1 and 24 hours' -Tag 'DMARCTtl', 'Recommended', 'Low' {
            # Skip if no TTL available
            if ($null -eq $script:Records.DMARCTtl -or $script:Records.DMARCTtl -eq 0) {
                Set-ItResult -Skipped -Because 'No DMARC TTL available to evaluate'
            }
            $script:Records.DMARCTtl | Should -BeGreaterOrEqual 3600
            $script:Records.DMARCTtl | Should -BeLessOrEqual 86400
        }
    }

    Context 'Parked Domain DMARC' -Tag 'Parked' {
        It 'DMARCPolicyParked: Parked domains should use p=reject' -Tag 'DMARCPolicyParked', 'Required', 'High' -Skip:($script:Classification -ne 'Parked') {
            $script:Records.DMARCPolicy | Should -Be 'reject'
        }
    }
}
