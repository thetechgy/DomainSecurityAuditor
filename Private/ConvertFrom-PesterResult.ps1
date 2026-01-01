<#
.SYNOPSIS
    Converts Pester test results to DomainSecurityAuditor compliance profile format.
.DESCRIPTION
    Bridges Pester output to the existing HTML report generator by:
    1. Extracting test IDs from test names
    2. Joining with metadata (severity, remediation, references)
    3. Converting Pester pass/fail to DSA status (Pass/Warning/Fail)
    4. Building the compliance profile object structure
.PARAMETER PesterResult
    The Pester run result from Invoke-Pester -PassThru.
.PARAMETER Metadata
    Hashtable from Tests/Metadata.psd1 mapping test IDs to metadata.
.PARAMETER Evidence
    The domain evidence object used for the compliance tests.
.OUTPUTS
    PSCustomObject matching the compliance profile schema expected by Publish-DSAHtmlReport.
.EXAMPLE
    $metadata = Import-PowerShellDataFile './Tests/Metadata.psd1'
    $profile = ConvertFrom-PesterResult -PesterResult $pesterResult -Metadata $metadata -Evidence $evidence
#>
function ConvertFrom-PesterResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $PesterResult,

        [Parameter(Mandatory)]
        [hashtable]$Metadata,

        [Parameter(Mandatory)]
        [pscustomobject]$Evidence
    )

    $checks = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($test in $PesterResult.Tests) {
        # Extract test ID from the first tag (convention: first tag is the test ID)
        $testId = $null
        foreach ($tag in $test.Tag) {
            if ($Metadata.ContainsKey($tag)) {
                $testId = $tag
                break
            }
        }

        # Fall back to extracting from test name if no matching tag found
        if (-not $testId) {
            # Try pattern "TestId: Description"
            if ($test.Name -match '^([^:]+):') {
                $testId = $Matches[1].Trim()
            }
        }

        # Skip if we couldn't identify the test
        if (-not $testId -or -not $Metadata.ContainsKey($testId)) {
            Write-Warning "Could not find metadata for test: $($test.Name)"
            continue
        }

        $meta = $Metadata[$testId]

        # Determine status based on Pester result and enforcement level
        $status = switch ($test.Result) {
            'Passed' { 'Pass' }
            'Skipped' { 'Pass' }  # Skipped tests (e.g., parked-only checks) count as pass
            'Failed' {
                if ($meta.Enforcement -eq 'Required') {
                    'Fail'
                }
                else {
                    'Warning'
                }
            }
            default { 'Warning' }
        }

        # Extract actual value from error record if available
        $actualValue = if ($test.Result -eq 'Passed') {
            'Passed'
        }
        elseif ($test.Result -eq 'Skipped') {
            'Skipped'
        }
        elseif ($test.ErrorRecord -and $test.ErrorRecord.TargetObject) {
            $test.ErrorRecord.TargetObject
        }
        elseif ($test.ErrorRecord) {
            $test.ErrorRecord.Exception.Message
        }
        else {
            'Unknown'
        }

        $check = [pscustomobject]@{
            Id          = $testId
            Area        = $meta.Area
            Status      = $status
            Severity    = $meta.Severity
            Enforcement = $meta.Enforcement
            Expectation = $meta.Expectation
            Actual      = $actualValue
            Remediation = $meta.Remediation
            References  = $meta.References
        }

        $checks.Add($check)
    }

    # Determine overall status
    $overallStatus = if ($checks.Status -contains 'Fail') {
        'Fail'
    }
    elseif ($checks.Status -contains 'Warning') {
        'Warning'
    }
    else {
        'Pass'
    }

    # Build compliance profile object matching existing schema
    $complianceResult = [pscustomobject]@{
        Domain                 = $Evidence.Domain
        Classification         = $Evidence.Classification
        OriginalClassification = $Evidence.Classification
        ClassificationOverride = $null
        OverallStatus          = $overallStatus
        Checks                 = $checks.ToArray()
        Evidence               = $Evidence
    }

    return $complianceResult
}
