# Module-level constants for TTL property resolution.
# This is the single source of truth for TTL property candidates across DomainDetective responses.
$script:DSATtlCandidateNames = @(
    'AuthoritativeDnsRecordTtl'
    'AuthorityDnsRecordTtl'
    'DnsRecordAuthorityTtl'
    'AuthoritativeTtl'
    'SpfRecordTtl'
    'DmarcRecordTtl'
    'DkimRecordTtl'
    'TlsRptRecordTtl'
    'MtastsRecordTtl'
    'MxRecordTtl'
    'MinMxTtl'
    'DnsRecordTtl'
    'Ttl'
    'TimeToLive'
)

# Authoritative-only TTL property candidates (subset of DSATtlCandidateNames).
# Used to extract authoritative TTL from individual record objects without falling back to resolver TTL.
$script:DSAAuthoritativeTtlCandidateNames = @(
    'AuthoritativeDnsRecordTtl'
    'AuthorityDnsRecordTtl'
    'DnsRecordAuthorityTtl'
    'AuthoritativeTtl'
)

# Note: $script:DSAMinDkimKeyLength is defined in DomainSecurityAuditor.psm1

<#
.SYNOPSIS
    Clear script-scoped caches for the module.
.DESCRIPTION
    Resets condition definitions, DomainDetective import state, and reference link cache for test isolation or long-lived sessions.
#>
function Reset-DSAModuleState {
    # Utility for tests/long-running sessions to clear script-scoped caches.
    $script:DSAConditionDefinitions = $null
    $script:DSADomainDetectiveLoaded = $false
    $script:DSAKnownReferenceLinks = @{}
}
