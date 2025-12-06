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

