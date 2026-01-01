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
            $selectorDetails = $script:Records.DKIMSelectorDetails

            # Skip if no selectors
            if (-not $selectorDetails -or $selectorDetails.Count -eq 0) {
                Set-ItResult -Skipped -Because 'No DKIM selectors to evaluate'
                return
            }

            # Check each selector's TTL - collect failures for useful error message
            $failedSelectors = @()
            foreach ($selector in $selectorDetails) {
                # Use fallback chain for TTL property names (safe property access)
                $ttl = $null
                $ttlProps = @('AuthoritativeDnsRecordTtl', 'DnsRecordTtl', 'DkimRecordTtl', 'Ttl')
                foreach ($prop in $ttlProps) {
                    if ($selector.PSObject.Properties.Name -contains $prop) {
                        $val = $selector.PSObject.Properties[$prop].Value
                        if ($null -ne $val) {
                            $ttl = $val
                            break
                        }
                    }
                }

                if ($null -ne $ttl -and $ttl -gt 0) {
                    if ($ttl -lt 3600 -or $ttl -gt 604800) {
                        $failedSelectors += "$($selector.Selector): ${ttl}s"
                    }
                }
            }

            # Fail if any selector has bad TTL
            $failedSelectors | Should -BeNullOrEmpty -Because "All DKIM selector TTLs should be between 1h (3600s) and 7d (604800s). Failed: $($failedSelectors -join ', ')"
        }
    }
}
