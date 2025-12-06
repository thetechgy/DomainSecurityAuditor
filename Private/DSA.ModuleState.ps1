function Reset-DSAModuleState {
    $script:DSAConditionDefinitions = $null
    $script:DSADomainDetectiveLoaded = $false
    $script:DSAKnownReferenceLinks = @{}
}
