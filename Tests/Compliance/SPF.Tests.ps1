<#
.SYNOPSIS
    SPF compliance tests for DomainSecurityAuditor.
.DESCRIPTION
    Pester tests that validate SPF record configuration against email security best practices.
    Tests run against pre-collected evidence from DomainDetective.
#>

Describe 'DomainSecurityAuditor/SPF' -Tag 'SPF' {
    BeforeAll {
        # Evidence is injected into script scope before Pester runs
        $script:Records = $global:ComplianceTestEvidence.Records
        $script:Classification = $global:ComplianceTestEvidence.Classification
    }

    Context 'SPF Record Presence' {
        It 'SPFPresence: SPF record must exist' -Tag 'SPFPresence', 'Required', 'Critical' {
            $script:Records.SPFRecord | Should -Not -BeNullOrEmpty
        }

        It 'SPFRecordMultiplicity: Only one SPF record should exist' -Tag 'SPFRecordMultiplicity', 'Required', 'High' {
            $script:Records.SPFRecordCount | Should -Be 1
        }
    }

    Context 'SPF Lookup Limits' {
        It 'SPFLookupLimit: DNS lookups must not exceed 10' -Tag 'SPFLookupLimit', 'Required', 'High' {
            $script:Records.SPFLookupCount | Should -BeLessOrEqual 10
        }
    }

    Context 'SPF Terminal Mechanism' {
        It 'SPFTerminalMechanism: Must end with -all or ~all' -Tag 'SPFTerminalMechanism', 'Required', 'Medium' {
            $script:Records.SPFTerminalMechanism | Should -BeIn @('-all', '~all')
        }
    }

    Context 'SPF Safety' {
        It 'SPFUnsafeMechanisms: Should not use ptr mechanism' -Tag 'SPFUnsafeMechanisms', 'Required', 'Medium' {
            $script:Records.SPFHasPtrMechanism | Should -BeFalse
        }

        It 'SPFRecordLength: Should be 255 characters or less' -Tag 'SPFRecordLength', 'Recommended', 'Medium' {
            $script:Records.SPFRecordLength | Should -BeLessOrEqual 255
        }
    }

    Context 'SPF TTL' {
        It 'SPFTtl: TTL should be between 1 and 24 hours' -Tag 'SPFTtl', 'Recommended', 'Low' {
            $script:Records.SPFTtl | Should -BeGreaterOrEqual 3600
            $script:Records.SPFTtl | Should -BeLessOrEqual 86400
        }
    }

    Context 'Parked Domain SPF' -Tag 'Parked' {
        It 'SPFTerminalParked: Parked domains should use -all' -Tag 'SPFTerminalParked', 'Required', 'High' -Skip:($script:Classification -ne 'Parked') {
            $script:Records.SPFTerminalMechanism | Should -Be '-all'
        }

        It 'SPFIncludesParked: Parked domains should not include providers' -Tag 'SPFIncludesParked', 'Required', 'Medium' -Skip:($script:Classification -ne 'Parked') {
            $script:Records.SPFIncludes | Should -BeNullOrEmpty
        }

        It 'SPFWildcardParked: Should configure wildcard SPF for subdomains' -Tag 'SPFWildcardParked', 'Recommended', 'Medium' -Skip:($script:Classification -ne 'Parked') {
            $script:Records.SPFWildcardConfigured | Should -BeTrue
        }
    }
}
