<#
.SYNOPSIS
    MTA-STS compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate MTA-STS configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/MTA-STS' -Tag 'MTA-STS' {
    BeforeAll {
        # Evidence is injected into script scope before Pester runs
        $script:Records = $global:ComplianceTestEvidence.Records
    }

    Context 'MTA-STS Record Presence' {
        It 'MTASTSPresence: MTA-STS TXT record must exist' -Tag 'MTASTSPresence', 'Required', 'Medium' {
            $script:Records.MTASTSRecordPresent | Should -BeTrue
        }
    }

    Context 'MTA-STS Policy' {
        It 'MTASTSPolicyValid: Policy file must be reachable and valid' -Tag 'MTASTSPolicyValid', 'Required', 'Medium' {
            $script:Records.MTASTSPolicyValid | Should -BeTrue
        }

        It 'MTASTSMode: Mode should be enforce' -Tag 'MTASTSMode', 'Required', 'Medium' {
            $script:Records.MTASTSMode | Should -Be 'enforce'
        }
    }

    Context 'MTA-STS TTL' {
        It 'MTASTSTtl: TTL should be between 1 and 7 days' -Tag 'MTASTSTtl', 'Recommended', 'Low' {
            # Skip if no TTL available
            if ($null -eq $script:Records.MTASTSTtl -or $script:Records.MTASTSTtl -eq 0) {
                Set-ItResult -Skipped -Because 'No MTA-STS TTL available to evaluate'
            }
            $script:Records.MTASTSTtl | Should -BeGreaterOrEqual 86400
            $script:Records.MTASTSTtl | Should -BeLessOrEqual 604800
        }
    }
}
