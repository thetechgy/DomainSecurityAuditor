<#
.SYNOPSIS
    Publishes code coverage summary to GitHub Job Summary.

.DESCRIPTION
    Parses JaCoCo XML coverage reports from Pester and generates a markdown summary
    with optional badge and threshold checking.

.PARAMETER CoveragePath
    Path or glob pattern to JaCoCo XML coverage files.

.PARAMETER WarningThreshold
    Coverage percentage below which a warning is shown. Default: 60.

.PARAMETER FailThreshold
    Coverage percentage below which the build should fail. Default: 70.

.PARAMETER Badge
    Include a shields.io-style coverage badge in the output.

.EXAMPLE
    ./Publish-CoverageSummary.ps1 -CoveragePath 'coverage-reports/**/PesterCoverage.xml' -Badge
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CoveragePath,

    [int]$WarningThreshold = 60,

    [int]$FailThreshold = 70,

    [switch]$Badge
)

$ErrorActionPreference = 'Stop'

# Find coverage files
$coverageFiles = Get-ChildItem -Path $CoveragePath -ErrorAction SilentlyContinue

if (-not $coverageFiles -or $coverageFiles.Count -eq 0) {
    Write-Warning "No coverage files found matching: $CoveragePath"
    exit 0
}

Write-Host "Found $($coverageFiles.Count) coverage file(s)"

# Aggregate coverage data
$totalLineCovered = 0
$totalLineMissed = 0
$totalBranchCovered = 0
$totalBranchMissed = 0
$totalMethodCovered = 0
$totalMethodMissed = 0

foreach ($file in $coverageFiles) {
    Write-Host "Processing: $($file.FullName)"

    try {
        [xml]$coverage = Get-Content -Path $file.FullName -Raw
    }
    catch {
        Write-Warning "Failed to parse coverage file: $($file.Name) - $_"
        continue
    }

    # JaCoCo format has counters at the report level
    $counters = $coverage.report.counter

    foreach ($counter in $counters) {
        switch ($counter.type) {
            'LINE' {
                $totalLineCovered += [int]$counter.covered
                $totalLineMissed += [int]$counter.missed
            }
            'BRANCH' {
                $totalBranchCovered += [int]$counter.covered
                $totalBranchMissed += [int]$counter.missed
            }
            'METHOD' {
                $totalMethodCovered += [int]$counter.covered
                $totalMethodMissed += [int]$counter.missed
            }
        }
    }
}

# Calculate percentages
function Get-Percentage {
    param([int]$Covered, [int]$Missed)
    $total = $Covered + $Missed
    if ($total -eq 0) { return 0 }
    return [math]::Round(($Covered / $total) * 100, 2)
}

$lineTotal = $totalLineCovered + $totalLineMissed
$branchTotal = $totalBranchCovered + $totalBranchMissed
$methodTotal = $totalMethodCovered + $totalMethodMissed

$linePercent = Get-Percentage -Covered $totalLineCovered -Missed $totalLineMissed
$branchPercent = Get-Percentage -Covered $totalBranchCovered -Missed $totalBranchMissed
$methodPercent = Get-Percentage -Covered $totalMethodCovered -Missed $totalMethodMissed

# Determine status
$statusColor = if ($linePercent -ge $FailThreshold) { 'brightgreen' }
               elseif ($linePercent -ge $WarningThreshold) { 'yellow' }
               else { 'red' }

$statusIcon = if ($linePercent -ge $FailThreshold) { ':white_check_mark:' }
              elseif ($linePercent -ge $WarningThreshold) { ':warning:' }
              else { ':x:' }

# Build markdown
$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine("## $statusIcon Code Coverage Summary")
[void]$sb.AppendLine()

if ($Badge) {
    # Shields.io badge URL - encode the percent sign
    $badgeUrl = "https://img.shields.io/badge/coverage-$linePercent%25-$statusColor"
    [void]$sb.AppendLine("![Coverage]($badgeUrl)")
    [void]$sb.AppendLine()
}

[void]$sb.AppendLine("| Metric | Covered | Missed | Total | Percentage |")
[void]$sb.AppendLine("|--------|--------:|-------:|------:|-----------:|")
[void]$sb.AppendLine("| Lines | $totalLineCovered | $totalLineMissed | $lineTotal | $linePercent% |")

if ($branchTotal -gt 0) {
    [void]$sb.AppendLine("| Branches | $totalBranchCovered | $totalBranchMissed | $branchTotal | $branchPercent% |")
}

if ($methodTotal -gt 0) {
    [void]$sb.AppendLine("| Methods | $totalMethodCovered | $totalMethodMissed | $methodTotal | $methodPercent% |")
}

[void]$sb.AppendLine()
[void]$sb.AppendLine("**Thresholds:** Warning: $WarningThreshold% | Fail: $FailThreshold%")
[void]$sb.AppendLine()

# Write to GitHub Step Summary
$markdown = $sb.ToString()

if ($env:GITHUB_STEP_SUMMARY) {
    $markdown | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
    Write-Host "Coverage summary written to GitHub Step Summary"
}
else {
    Write-Host "GITHUB_STEP_SUMMARY not set. Outputting to console:"
    Write-Host $markdown
}

# Output summary to console
Write-Host "=== Coverage Summary ==="
Write-Host "Line Coverage: $linePercent% ($totalLineCovered/$lineTotal)"
if ($branchTotal -gt 0) {
    Write-Host "Branch Coverage: $branchPercent% ($totalBranchCovered/$branchTotal)"
}
if ($methodTotal -gt 0) {
    Write-Host "Method Coverage: $methodPercent% ($totalMethodCovered/$methodTotal)"
}

# Note: We don't fail the build here as the Pester step already enforces coverage thresholds
# This script is for reporting only
