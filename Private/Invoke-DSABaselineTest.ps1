function Invoke-DSABaselineTest {
    <#
.SYNOPSIS
    Evaluates domain evidence against baseline check definitions.
.DESCRIPTION
    Runs each check in the baseline profile against the provided domain evidence,
    evaluating conditions and returning pass/fail/warning results for each check.
.PARAMETER DomainEvidence
    The domain evidence object from Get-DSADomainEvidence containing Records property.
.PARAMETER BaselineDefinition
    Hashtable of baseline profiles keyed by classification name. If omitted, loads default baseline.
.PARAMETER ClassificationOverride
    Optional classification to use instead of the evidence-derived classification.
.OUTPUTS
    PSCustomObject with Domain, Classification, OverallStatus, and Checks array.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscustomobject]$DomainEvidence,

        [Parameter()]
        [hashtable]$BaselineDefinition,

        [string]$ClassificationOverride
    )

    if (-not $BaselineDefinition) {
        $baseline = Get-DSABaseline
        $BaselineDefinition = $baseline.Profiles
    }

    $effectiveClassification = if (-not [string]::IsNullOrWhiteSpace($ClassificationOverride)) {
        $ClassificationOverride
    }
    else {
        $DomainEvidence.Classification
    }

    $classificationKey = Get-DSAClassificationKey -Classification $effectiveClassification
    if (-not $classificationKey -or -not $BaselineDefinition.ContainsKey($classificationKey)) {
        $classificationKey = 'Default'
    }

    $profileDefinition = $BaselineDefinition[$classificationKey]
    if (-not $profileDefinition -or -not $profileDefinition.Checks) {
        throw "Baseline profile '$classificationKey' is missing or has no checks defined."
    }

    $checkResults = [System.Collections.Generic.List[object]]::new()

    foreach ($check in $profileDefinition.Checks) {
        $expectedValue = $null
        if ($check -is [hashtable]) {
            if ($check.ContainsKey('ExpectedValue')) {
                $expectedValue = $check.ExpectedValue
            }
        }
        elseif ($check.PSObject -and $check.PSObject.Properties.Name -contains 'ExpectedValue') {
            $expectedValue = $check.ExpectedValue
        }

        $value = Get-DSAEvidenceValue -DomainEvidence $DomainEvidence -Path $check.Target
        $conditionMet = Test-DSABaselineCondition -Condition $check.Condition -Value $value -ExpectedValue $expectedValue
        $status = if ($conditionMet) {
            'Pass'
        }
        elseif (($check.Enforcement ?? 'Required') -ieq 'Required') {
            'Fail'
        }
        else {
            'Warning'
        }

        $actualValue = Format-DSAActualValue -Value $value
        $result = [pscustomobject]@{
            Id            = $check.Id
            Area          = $check.Area
            Status        = $status
            Severity      = $check.Severity
            Enforcement   = $check.Enforcement
            Expectation   = $check.Expectation
            ExpectedValue = $expectedValue
            Actual        = $actualValue
            Remediation   = $check.Remediation
            References    = $check.References
        }

        $null = $checkResults.Add($result)
    }

    $selectorDetails = $null
    if ($DomainEvidence.PSObject.Properties.Name -contains 'Records' -and $DomainEvidence.Records -and $DomainEvidence.Records.PSObject.Properties.Name -contains 'DKIMSelectorDetails') {
        $selectorDetails = $DomainEvidence.Records.DKIMSelectorDetails
    }

    $effectiveChecks = Get-DSAEffectiveChecks -Checks $checkResults -SelectorDetails $selectorDetails
    $overallStatus = Get-DSAOverallStatus -Checks $effectiveChecks
    return [pscustomobject]@{
        Domain                 = $DomainEvidence.Domain
        Classification         = $profileDefinition.Name
        OriginalClassification = $DomainEvidence.Classification
        ClassificationOverride = $ClassificationOverride
        OverallStatus          = $overallStatus
        Checks                 = $effectiveChecks
    }
}

<#
.SYNOPSIS
    Resolve a nested property path from domain evidence.
.DESCRIPTION
    Traverses dot-delimited path segments on the evidence object, returning null when any segment is missing.
.PARAMETER DomainEvidence
    Domain evidence object produced by Get-DSADomainEvidence.
.PARAMETER Path
    Dot-delimited property path to extract.
#>
function Get-DSAEvidenceValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$DomainEvidence,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $segments = $Path -split '\.'
    $current = $DomainEvidence

    foreach ($segment in $segments) {
        if ($null -eq $current) {
            return $null
        }

        if ($current.PSObject.Properties.Name -contains $segment) {
            $current = $current.$segment
        }
        else {
            return $null
        }
    }

    return $current
}

<#
.SYNOPSIS
    Evaluate a baseline condition against an observed value.
.DESCRIPTION
    Fetches the condition definition and executes its evaluation scriptblock using the observed and expected values.
.PARAMETER Condition
    Baseline condition name.
.PARAMETER Value
    Observed value to test.
.PARAMETER ExpectedValue
    Expected value payload for the condition.
#>
function Test-DSABaselineCondition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Condition,

        [Parameter()]
        $Value,

        [Parameter()]
        [object]$ExpectedValue
    )

    $definition = Get-DSAConditionDefinition -Name $Condition
    if (-not $definition -or -not $definition.Evaluate) {
        return $false
    }

    return & $definition.Evaluate $Value $ExpectedValue
}

