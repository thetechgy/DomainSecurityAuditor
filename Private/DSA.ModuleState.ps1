function Reset-DSAModuleState {
    # Utility for tests/long-running sessions to clear script-scoped caches.
    $script:DSAConditionDefinitions = $null
    $script:DSADomainDetectiveLoaded = $false
    $script:DSAKnownReferenceLinks = @{}
}
