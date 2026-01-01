<#
.SYNOPSIS
    DKIM compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate DKIM selector configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/DKIM' -Tag 'DKIM' {
    BeforeAll {
        # Evidence is injected into script scope before Pester runs
        $script:Records = $global:ComplianceTestEvidence.Records
        $script:Evidence = $global:ComplianceTestEvidence
    }

    Context 'DKIM Selector Presence' {
        It 'DKIMSelectorPresence: At least one DKIM selector should exist' -Tag 'DKIMSelectorPresence', 'Required', 'High' {
            $script:Records.DKIMSelectors | Should -Not -BeNullOrEmpty
        }
    }

    Context 'DKIM Key Strength' {
        It 'DKIMKeyStrength: Minimum key length should be >= 1024 bits' -Tag 'DKIMKeyStrength', 'Required', 'High' {
            # Skip if no selectors found
            if ($null -eq $script:Records.DKIMMinKeyLength -or $script:Records.DKIMMinKeyLength -eq 0) {
                Set-ItResult -Skipped -Because 'No DKIM selectors found to evaluate'
            }
            $script:Records.DKIMMinKeyLength | Should -BeGreaterOrEqual 1024
        }
    }

    Context 'DKIM Selector Health' {
        It 'DKIMSelectorHealth: No weak or invalid selectors should exist' -Tag 'DKIMSelectorHealth', 'Required', 'Medium' {
            $script:Records.DKIMWeakSelectors | Should -BeLessOrEqual 0
        }
    }

    Context 'DKIM TTL' {
        It 'DKIMTtl: TTL should be between 1 hour and 7 days' -Tag 'DKIMTtl', 'Recommended', 'Low' {
            # Skip if no TTL available
            if ($null -eq $script:Records.DKIMMinimumTtl -or $script:Records.DKIMMinimumTtl -eq 0) {
                Set-ItResult -Skipped -Because 'No DKIM TTL available to evaluate'
            }
            $script:Records.DKIMMinimumTtl | Should -BeGreaterOrEqual 3600
            $script:Records.DKIMMinimumTtl | Should -BeLessOrEqual 604800
        }
    }
}
