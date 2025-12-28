<#
.SYNOPSIS
    Publishes Pester test results to GitHub Job Summary.

.DESCRIPTION
    Parses JUnit XML test results from Pester and generates a markdown summary
    that is written to the GitHub Actions Job Summary.

.PARAMETER ResultsPath
    Path to the JUnit XML test results file (e.g., PesterResults.xml).

.PARAMETER Title
    Title to display in the summary header.

.EXAMPLE
    ./Publish-TestResults.ps1 -ResultsPath 'Output/TestResults/PesterResults.xml' -Title 'Pester Tests'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResultsPath,

    [string]$Title = 'Pester Test Results'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ResultsPath)) {
    Write-Warning "Test results file not found: $ResultsPath"
    exit 0
}

Write-Host "Parsing test results from: $ResultsPath"

try {
    [xml]$junit = Get-Content -Path $ResultsPath -Raw
}
catch {
    Write-Error "Failed to parse JUnit XML: $_"
    exit 1
}

# Handle both single testsuite and testsuites wrapper
$testSuites = if ($junit.testsuites) {
    $junit.testsuites.testsuite
}
elseif ($junit.testsuite) {
    @($junit.testsuite)
}
else {
    Write-Warning "No test suites found in results file"
    exit 0
}

# Aggregate counts
$totalTests = 0
$totalFailures = 0
$totalErrors = 0
$totalSkipped = 0
$totalTime = 0.0

$failedTests = [System.Collections.ArrayList]::new()

foreach ($suite in $testSuites) {
    $totalTests += [int]$suite.tests
    $totalFailures += [int]$suite.failures
    $totalErrors += [int]$suite.errors
    $totalSkipped += [int]$suite.skipped
    $totalTime += [double]$suite.time

    # Collect failed test details
    foreach ($testCase in $suite.testcase) {
        if ($testCase.failure) {
            [void]$failedTests.Add(@{
                Suite   = $suite.name
                Name    = $testCase.name
                Time    = $testCase.time
                Message = $testCase.failure.message
                Details = $testCase.failure.'#text'
            })
        }
        if ($testCase.error) {
            [void]$failedTests.Add(@{
                Suite   = $suite.name
                Name    = $testCase.name
                Time    = $testCase.time
                Message = $testCase.error.message
                Details = $testCase.error.'#text'
            })
        }
    }
}

$totalPassed = $totalTests - $totalFailures - $totalErrors - $totalSkipped

# Determine status icon
$statusIcon = if ($totalFailures -gt 0 -or $totalErrors -gt 0) { ':x:' }
              elseif ($totalSkipped -gt 0) { ':warning:' }
              else { ':white_check_mark:' }

# Build markdown
$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine("## $statusIcon $Title")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| Metric | Count |")
[void]$sb.AppendLine("|--------|------:|")
[void]$sb.AppendLine("| Passed | $totalPassed |")
[void]$sb.AppendLine("| Failed | $totalFailures |")
[void]$sb.AppendLine("| Errors | $totalErrors |")
[void]$sb.AppendLine("| Skipped | $totalSkipped |")
[void]$sb.AppendLine("| **Total** | **$totalTests** |")
[void]$sb.AppendLine()
[void]$sb.AppendLine("*Duration: $([math]::Round($totalTime, 2))s*")
[void]$sb.AppendLine()

# Add failed tests section if any
if ($failedTests.Count -gt 0) {
    [void]$sb.AppendLine("<details>")
    [void]$sb.AppendLine("<summary>:x: Failed Tests ($($failedTests.Count))</summary>")
    [void]$sb.AppendLine()

    foreach ($test in $failedTests) {
        [void]$sb.AppendLine("### $($test.Suite)")
        [void]$sb.AppendLine("**$($test.Name)**")
        [void]$sb.AppendLine()
        if ($test.Message) {
            [void]$sb.AppendLine("``````")
            [void]$sb.AppendLine($test.Message)
            [void]$sb.AppendLine("``````")
        }
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine("</details>")
    [void]$sb.AppendLine()
}

# Write to GitHub Step Summary
$markdown = $sb.ToString()

if ($env:GITHUB_STEP_SUMMARY) {
    $markdown | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
    Write-Host "Test results written to GitHub Step Summary"
}
else {
    Write-Host "GITHUB_STEP_SUMMARY not set. Outputting to console:"
    Write-Host $markdown
}

# Output summary to console
Write-Host "=== Test Summary ==="
Write-Host "Passed: $totalPassed | Failed: $totalFailures | Errors: $totalErrors | Skipped: $totalSkipped | Total: $totalTests"
