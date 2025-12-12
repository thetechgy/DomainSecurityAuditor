<#
.SYNOPSIS
    Render compliance profiles into an HTML report.
.DESCRIPTION
    Builds an accessible HTML report with summary cards, per-domain sections, and DKIM selector breakdowns, then saves to the output directory.
.PARAMETER Profiles
    Compliance profiles to render.
.PARAMETER OutputRoot
    Root directory where the report will be written.
.PARAMETER GeneratedOn
    Timestamp used for metadata and filename.
.PARAMETER BaselineName
    Name of the baseline used during evaluation.
.PARAMETER BaselineVersion
    Version of the baseline used during evaluation.
.PARAMETER LogFile
    Optional log file path for write notifications.
#>
function Publish-DSAHtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject[]]$Profiles,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedOn,

        [string]$BaselineName,

        [string]$BaselineVersion,

        [string]$LogFile
    )

    $profilesList = @($Profiles)
    if (-not $profilesList -or $profilesList.Count -eq 0) {
        throw 'No compliance profiles were supplied to Publish-DSAHtmlReport.'
    }

    $reportsRoot = Resolve-DSAPath -Path (Join-Path -Path $OutputRoot -ChildPath 'Reports') -EnsureExists
    $reportFileName = 'domain_security_auditor_report_{0}.html' -f $GeneratedOn.ToString('yyyyMMdd_HHmmss')
    $reportPath = Join-Path -Path $reportsRoot -ChildPath $reportFileName

    $summary = Get-DSAReportSummary -Profiles $profilesList
    $module = Get-Module -Name DomainSecurityAuditor -ErrorAction SilentlyContinue | Select-Object -First 1
    $moduleVersion = if ($module) { $module.Version.ToString() } else { 'unknown' }
    $baselineNameText = if ($BaselineName) { $BaselineName } else { 'Baseline' }
    $baselineVersionText = if ($BaselineVersion) { " v$BaselineVersion" } else { '' }
    $testSuiteText = "Test Suite: $baselineNameText$baselineVersionText"

    $builder = [System.Text.StringBuilder]::new()
    $null = $builder.AppendLine('<!DOCTYPE html>')
    $null = $builder.AppendLine('<html lang="en">')
    $null = $builder.AppendLine('<head>')
    $null = $builder.AppendLine('    <meta charset="UTF-8">')
    $null = $builder.AppendLine('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
    $null = $builder.AppendLine('    <title>Domain Security Auditor Report</title>')
    $null = $builder.AppendLine('    <style>')
    $null = $builder.AppendLine((Get-DSAReportStyles))
    $null = $builder.AppendLine('    </style>')
    $null = $builder.AppendLine('</head>')
    $null = $builder.AppendLine('<body>')
    $null = $builder.AppendLine('  <a href="#main-content" class="skip-link">Skip to main content</a>')
    $null = $builder.AppendLine('  <main class="container" id="main-content" role="main">')
    $null = $builder.AppendLine('    <header class="header">')
    $null = $builder.AppendLine('      <h1>Domain Security Auditor Report</h1>')
    $localTimeZone = [System.TimeZoneInfo]::Local
    $timeZoneSuffix = if ($localTimeZone.IsDaylightSavingTime($GeneratedOn)) { $localTimeZone.DaylightName } else { $localTimeZone.StandardName }
    $collectedText = '{0} {1}' -f ($GeneratedOn.ToString('MMMM d, yyyy h:mm tt')), $timeZoneSuffix
    $null = $builder.AppendLine(('      <div class="meta">Collected: {0}</div>' -f (ConvertTo-DSAHtml $collectedText)))
    $null = $builder.AppendLine(('      <div class="meta">{0}</div>' -f (ConvertTo-DSAHtml $testSuiteText)))
    $null = $builder.AppendLine('    </header>')

    Add-DSASummaryCards -Builder $builder -Summary $summary
    Add-DSADomainSections -Builder $builder -Profiles $profilesList

    $null = $builder.AppendLine('    <footer class="footer">')
    $poweredByHtml = 'Powered by <a href="https://github.com/EvotecIT/DomainDetective" target="_blank" rel="noopener">DomainDetective</a> + <a href="https://github.com/pester/Pester" target="_blank" rel="noopener">Pester</a>'
    $null = $builder.AppendLine(("      <p><strong>DomainSecurityAuditor v{0}</strong> | {1}</p>" -f $moduleVersion, $poweredByHtml))
    $projectHtml = '<a href="https://github.com/thetechgy/DomainSecurityAuditor" target="_blank" rel="noopener">DomainSecurityAuditor on GitHub</a>'
    $null = $builder.AppendLine(("      <p class=""footer-secondary"">{0}</p>" -f $projectHtml))
    $null = $builder.AppendLine('    </footer>')
    $null = $builder.AppendLine('    <div class="back-to-top-wrapper">')
    $null = $builder.AppendLine('      <a class="back-to-top" href="#main-content" aria-label="Back to the top of the report">↑ Back to top</a>')
    $null = $builder.AppendLine('    </div>')

    $null = $builder.AppendLine('  </main>')
    $null = $builder.AppendLine('  <script>')
    $null = $builder.AppendLine((Get-DSAReportScript))
    $null = $builder.AppendLine('  </script>')
    $null = $builder.AppendLine('</body>')
    $null = $builder.AppendLine('</html>')

    Set-Content -Path $reportPath -Value $builder.ToString() -Encoding UTF8
    if ($LogFile) {
        Write-DSALog -Message "HTML report saved to '$reportPath'." -LogFile $LogFile
    }
    return $reportPath
}

<#
.SYNOPSIS
    Append summary cards to the report builder.
.DESCRIPTION
    Writes status-based summary cards and filter controls into the HTML builder using the supplied summary object.
.PARAMETER Builder
    StringBuilder that accumulates HTML output.
.PARAMETER Summary
    Summary object from Get-DSAReportSummary.
#>
function Add-DSASummaryCards {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject]$Summary
    )

    $null = $Builder.AppendLine('    <section class="summary">')
    $null = $Builder.AppendLine('      <div class="summary-cards">')
    foreach ($card in $Summary.Cards) {
        $styleClass = Get-DSAStatusClassName -Status $card.Style
        $icon = Get-DSAStatusIcon -Status $card.Style
        $isFilterable = -not [string]::IsNullOrWhiteSpace($card.Filter)
        $cardClasses = if ($isFilterable) { 'card filter-card' } else { 'card' }
        $filterAttr = if ($isFilterable) { " data-filter=""$($card.Filter)""" } else { '' }
        $ariaAttr = if ($isFilterable) { ' aria-pressed="false" role="button" tabindex="0"' } else { '' }
        $null = $Builder.AppendLine(("        <div class=""{0}""{1}{2}>" -f $cardClasses, $filterAttr, $ariaAttr))
        $null = $Builder.AppendLine('          <div class="card-header">')
        $null = $Builder.AppendLine(("            <div class='card-icon {0}'>{1}</div>" -f $styleClass, (ConvertTo-DSAHtml $icon)))
        $null = $Builder.AppendLine(("            <div class='card-title'>{0}</div>" -f (ConvertTo-DSAHtml $card.Label)))
        $null = $Builder.AppendLine('          </div>')
        $null = $Builder.AppendLine(("          <div class='card-value {0}'>{1}</div>" -f $styleClass, (ConvertTo-DSAHtml $card.Value)))
        if ($card.Description) {
            $null = $Builder.AppendLine(("          <div class='card-subtitle'>{0}</div>" -f (ConvertTo-DSAHtml $card.Description)))
        }
        $null = $Builder.AppendLine('        </div>')
    }
    $null = $Builder.AppendLine('      </div>')
    $null = $Builder.AppendLine('      <div class="filter-summary" id="filter-summary" aria-live="polite">Showing: All checks</div>')
    $null = $Builder.AppendLine('    </section>')
}

<#
.SYNOPSIS
    Append per-domain result sections to the report.
.DESCRIPTION
    Iterates profiles, grouping checks by protocol area and adding interactive sections with status metadata.
.PARAMETER Builder
    StringBuilder that accumulates HTML output.
.PARAMETER Profiles
    Compliance profiles to render.
#>
function Add-DSADomainSections {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject[]]$Profiles
    )

    $null = $Builder.AppendLine('    <div class="section-controls" role="group" aria-label="Protocol section controls">')
    $null = $Builder.AppendLine('      <button type="button" class="section-toggle" id="toggle-all-sections" aria-pressed="false">Expand all sections</button>')
    $null = $Builder.AppendLine('    </div>')

    foreach ($profile in $Profiles) {
        $statusClass = Get-DSAStatusClassName -Status $profile.OverallStatus
        $statusAttr = switch ($statusClass) {
            'passed' { 'pass' }
            'failed' { 'fail' }
            'warning' { 'warning' }
            default { 'info' }
        }
        $checks = if ($profile.Checks) { @($profile.Checks | Where-Object { $_ }) } else { @() }
        $checkCount = ($checks | Measure-Object).Count
        $metaSegments = [System.Collections.Generic.List[string]]::new()
        $hasOverride = $false
        if ($profile.PSObject.Properties.Name -contains 'ClassificationOverride' -and -not [string]::IsNullOrWhiteSpace($profile.ClassificationOverride)) {
            $null = $metaSegments.Add(("Override: {0}" -f $profile.ClassificationOverride))
            $hasOverride = $true
        }
        if ($profile.OriginalClassification) {
            $label = if ($hasOverride) { 'Detected' } else { 'Detected' }
            $null = $metaSegments.Add(("{0}: {1}" -f $label, $profile.OriginalClassification))
        }
        if ($checkCount -gt 0) {
            $null = $metaSegments.Add(("{0} checks executed" -f $checkCount))
        }
        $statusText = if ($profile.OverallStatus) { $profile.OverallStatus.ToUpperInvariant() } else { '' }

        $null = $Builder.AppendLine(("    <section class=""domain-results status-{0}"" data-status=""{0}"">" -f $statusAttr))
        $null = $Builder.AppendLine('      <div class="domain-header">')
        $null = $Builder.AppendLine('        <div class="domain-title">')
        $null = $Builder.AppendLine(("          <div class='domain-name'>{0}</div>" -f (ConvertTo-DSAHtml $profile.Domain)))
        $null = $Builder.AppendLine(("          <span class='domain-status {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $statusText)))
        $null = $Builder.AppendLine('        </div>')
        if ($metaSegments.Count -gt 0) {
            $metaText = [string]::Join(' • ', $metaSegments)
            $null = $Builder.AppendLine(("        <div class='domain-meta'>{0}</div>" -f (ConvertTo-DSAHtml $metaText)))
        }
        $null = $Builder.AppendLine('      </div>')

        if ($checkCount -eq 0) {
            $null = $Builder.AppendLine('      <div class="domain-empty">No checks were evaluated for this domain.</div>')
            $null = $Builder.AppendLine('    </section>')
            continue
        }

        $groupedChecks = $checks | Group-Object -Property Area
        $domainSlug = ($profile.Domain -replace '[^a-zA-Z0-9]', '-').ToLowerInvariant()
        foreach ($group in $groupedChecks) {
            Add-DSAProtocolSection -Builder $Builder -Group $group -DomainSlug $domainSlug -Profile $profile
        }

        $null = $Builder.AppendLine('    </section>')
    }
}

<#
.SYNOPSIS
    Render a protocol-specific section for a domain.
.DESCRIPTION
    Builds the expandable section for a protocol area, including aggregated status and individual test results.
.PARAMETER Builder
    StringBuilder for HTML output.
.PARAMETER Group
    Grouped set of checks for the protocol area.
.PARAMETER DomainSlug
    Sanitized domain identifier used in element ids.
.PARAMETER Profile
    Compliance profile for the domain.
#>
function Add-DSAProtocolSection {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSObject]$Group,
        [string]$DomainSlug,
        [pscustomobject]$Profile
    )

    if (-not $Group -or -not $Group.Group) {
        return
    }

    $groupChecks = @($Group.Group | Where-Object { $_ })
    if ($groupChecks.Count -eq 0) {
        return
    }

    $checkCount = ($groupChecks | Measure-Object).Count
    $sectionClass = 'protocol-section'
    $detailsClass = 'protocol-details'
    $checkLabel = if ($checkCount -eq 1) { '1 check' } else { ('{0} checks' -f $checkCount) }
    $areaSlug = ($Group.Name -replace '[^a-zA-Z0-9]', '-').ToLowerInvariant()
    $detailsId = "protocol-{0}-{1}" -f $DomainSlug, $areaSlug

    $selectorDetails = $null
    if (($Group.Name -eq 'DKIM') -and $Profile -and $Profile.PSObject.Properties.Name -contains 'Evidence') {
        $selectorDetails = $Profile.Evidence.DKIMSelectorDetails
    }

    $effectiveChecks = Get-DSAEffectiveChecks -Checks $groupChecks -SelectorDetails $selectorDetails
    $areaStatus = Get-DSAOverallStatus -Checks $effectiveChecks
    $statusClass = Get-DSAStatusClassName -Status $areaStatus

    $null = $Builder.AppendLine(("      <div class=""{0}"">" -f $sectionClass))
    $null = $Builder.AppendLine(("        <div class=""protocol-header"" role=""button"" tabindex=""0"" aria-expanded=""false"" aria-controls=""{0}"">" -f $detailsId))
    $null = $Builder.AppendLine(("          <div class='protocol-name'>{0}</div>" -f (ConvertTo-DSAHtml $Group.Name)))
    $null = $Builder.AppendLine('          <div class="protocol-status">')
    $null = $Builder.AppendLine(("            <span class='status-badge {0}'><span class='sr-only'>Status: </span>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $areaStatus)))
    $null = $Builder.AppendLine(("            <span class='protocol-count'>{0}</span>" -f $checkLabel))
    $null = $Builder.AppendLine('            <span class="chevron" aria-hidden="true">▶</span>')
    $null = $Builder.AppendLine('          </div>')
    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine(("        <div class=""{0}"" id=""{1}"" aria-hidden=""true"">" -f $detailsClass, $detailsId))

    foreach ($check in $effectiveChecks) {
        Add-DSATestResult -Builder $Builder -Check $check -Selectors $selectorDetails
    }

    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine('      </div>')
}

<#
.SYNOPSIS
    Render a single test result card.
.DESCRIPTION
    Writes the test header, expectation, observed values, remediation, references, and DKIM selector breakdowns when applicable.
.PARAMETER Builder
    StringBuilder for HTML output.
.PARAMETER Check
    Baseline check result to render.
.PARAMETER Selectors
    Optional DKIM selector details for DKIM check enrichment.
#>
function Add-DSATestResult {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject]$Check,
        [pscustomobject[]]$Selectors
    )

    if (-not $Check) {
        return
    }

    $effectiveStatus = $Check.Status
    $statusClass = Get-DSAStatusClassName -Status $effectiveStatus
    $statusIcon = Get-DSAStatusIcon -Status $effectiveStatus
    $filterStatus = Get-DSAFilterStatus -Status $effectiveStatus
    $detailItems = [System.Collections.Generic.List[object]]::new()
    $suppressActual = ($Check.Area -eq 'DKIM' -and $Check.Id -in @('DKIMKeyStrength', 'DKIMTtl'))
    if (-not $suppressActual -and $Check.PSObject.Properties.Name -contains 'Actual' -and ($Check.Actual -ne $null)) {
        $valueHtml = ConvertTo-DSAValueHtml -Value $Check.Actual
        $null = $detailItems.Add([pscustomobject]@{
                Label  = 'Observed Value'
                Value  = $valueHtml
                IsHtml = $true
            })
    }
    elseif ($suppressActual) {
        $null = $detailItems.Add([pscustomobject]@{
                Label  = 'Observed Value'
                Value  = 'See selector details below'
                IsHtml = $false
            })
    }
    if ($Check.Severity) {
        $null = $detailItems.Add([pscustomobject]@{
                Label  = 'Severity'
                Value  = $Check.Severity
                IsHtml = $false
            })
    }
    if ($Check.PSObject.Properties.Name -contains 'Enforcement' -and $Check.Enforcement) {
        $null = $detailItems.Add([pscustomobject]@{
                Label  = 'Enforcement'
                Value  = $Check.Enforcement
                IsHtml = $false
            })
    }

    $null = $Builder.AppendLine(("          <div class=""test-result"" data-status=""{0}"">" -f (ConvertTo-DSAHtml $filterStatus)))
    $null = $Builder.AppendLine('            <div class="test-header">')
    $null = $Builder.AppendLine(("              <div class='test-icon {0}' aria-label='{1} status'>{2}</div>" -f $statusClass, (ConvertTo-DSAHtml $effectiveStatus), (ConvertTo-DSAHtml $statusIcon)))
    $null = $Builder.AppendLine('              <div class="test-content">')
    $null = $Builder.AppendLine('                <div class="test-title-row">')
    $null = $Builder.AppendLine(("                  <div class='test-name'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Id)))
    $null = $Builder.AppendLine(("                  <span class='status-pill {0}'><span class='sr-only'>Status: </span>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $Check.Status)))
    $null = $Builder.AppendLine('                </div>')
    if ($Check.Expectation) {
        $null = $Builder.AppendLine(("                <div class='test-message'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Expectation)))
    }

    if ($detailItems.Count -gt 0) {
        $null = $Builder.AppendLine('                <div class="details-grid">')
        foreach ($detail in $detailItems) {
            $valueText = if ($detail.IsHtml) { $detail.Value } else { ConvertTo-DSAHtml -Value $detail.Value }
            $null = $Builder.AppendLine('                  <div class="detail-item">')
            $null = $Builder.AppendLine(("                    <div class='detail-label'>{0}</div>" -f (ConvertTo-DSAHtml $detail.Label)))
            $null = $Builder.AppendLine(("                    <div class='detail-value'>{0}</div>" -f $valueText))
            $null = $Builder.AppendLine('                  </div>')
        }
        $null = $Builder.AppendLine('                </div>')
    }

    if ($Check.Remediation -and ($Check.Status -ne 'Pass')) {
        $null = $Builder.AppendLine('                <div class="test-recommendation">')
        $null = $Builder.AppendLine('                  <div class="label">Remediation</div>')
        $null = $Builder.AppendLine(("                  <div class='text'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Remediation)))
        $null = $Builder.AppendLine('                </div>')
    }

    if ($Check.References -and @($Check.References).Count -gt 0) {
        $references = @($Check.References) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($references) {
            $null = $Builder.AppendLine('                <div class="test-references">')
            foreach ($ref in $references) {
                $referenceHtml = ConvertTo-DSAReferenceHtml -Reference $ref
                if ($referenceHtml) {
                    $null = $Builder.AppendLine(("                  {0}" -f $referenceHtml))
                }
            }
            $null = $Builder.AppendLine('                </div>')
        }
    }

    $breakdownEligibleIds = @('DKIMKeyStrength', 'DKIMTtl')
    if ($Selectors -and $Check.Area -eq 'DKIM' -and ($Check.Id -in $breakdownEligibleIds)) {
        Add-DSADkimSelectorBreakdown -Builder $Builder -Selectors $Selectors -Check $Check
    }

    $null = $Builder.AppendLine('              </div>')
    $null = $Builder.AppendLine('            </div>')
    $null = $Builder.AppendLine('          </div>')
}

<#
.SYNOPSIS
    Compute aggregate report statistics.
.DESCRIPTION
    Summarizes pass/fail/warning counts across domains and checks, producing card metadata for the report header.
.PARAMETER Profiles
    Compliance profiles to summarize.
#>
function Get-DSAReportSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$Profiles
    )

    $profileList = @($Profiles)
    $domainCount = ($profileList | Measure-Object).Count
    $passed = ($profileList | Where-Object { $_.OverallStatus -eq 'Pass' } | Measure-Object).Count
    $failed = ($profileList | Where-Object { $_.OverallStatus -eq 'Fail' } | Measure-Object).Count
    $warningDomains = ($profileList | Where-Object { $_.OverallStatus -eq 'Warning' } | Measure-Object).Count

    $checkStatusCounts = @{
        Pass    = 0
        Fail    = 0
        Warning = 0
    }
    $totalChecks = 0
    foreach ($profile in $profileList) {
        $selectorDetails = $null
        if ($profile -and $profile.PSObject.Properties['Evidence'] -and $profile.Evidence -and $profile.Evidence.PSObject.Properties['DKIMSelectorDetails']) {
            $selectorDetails = $profile.Evidence.DKIMSelectorDetails
        }

        $checksInput = if ($profile.Checks) { $profile.Checks } else { @() }
        $checks = Get-DSAEffectiveChecks -Checks $checksInput -SelectorDetails $selectorDetails
        if (-not $checks) {
            $checks = @()
        }

        $counts = Get-DSAStatusCounts -Checks $checks
        $totalChecks += $counts.Total
        $checkStatusCounts['Pass'] += $counts.Pass
        $checkStatusCounts['Fail'] += $counts.Fail
        $checkStatusCounts['Warning'] += $counts.Warning
    }

    $cards = @(
        [pscustomobject]@{ Label = 'Passing Checks'; Value = $checkStatusCounts['Pass']; Description = 'Checks meeting expectations.'; Style = 'Pass'; Filter = 'pass' }
        [pscustomobject]@{ Label = 'Failing Checks'; Value = $checkStatusCounts['Fail']; Description = 'Immediate attention required.'; Style = 'Fail'; Filter = 'fail' }
        [pscustomobject]@{ Label = 'Warning Checks'; Value = $checkStatusCounts['Warning']; Description = 'Recommendations available.'; Style = 'Warning'; Filter = 'warning' }
        [pscustomobject]@{ Label = 'Total Checks'; Value = $totalChecks; Description = ("Across {0} domains" -f $domainCount); Style = 'Info'; Filter = 'all' }
    )

    return [pscustomobject]@{
        DomainCount   = $domainCount
        Passed        = $passed
        Failed        = $failed
        Warning       = $warningDomains
        TotalChecks   = $totalChecks
        TotalWarnings = $checkStatusCounts.Warning
        Cards         = $cards
    }
}


<#
.SYNOPSIS
    Render DKIM selector breakdown cards for a DKIM check.
.DESCRIPTION
    Emits per-selector status, key length/TTL metadata, and not-found markers to provide detail within the DKIM section.
.PARAMETER Builder
    StringBuilder for HTML output.
.PARAMETER Selectors
    DKIM selector objects returned from evidence collection.
.PARAMETER Check
    DKIM check driving status evaluation.
#>
function Add-DSADkimSelectorBreakdown {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [pscustomobject[]]$Selectors,
        [pscustomobject]$Check
    )

    $selectorList = @($Selectors | Where-Object { $_ })
    if (-not $selectorList) {
        return
    }

    $null = $Builder.AppendLine('                <div class="dkim-selectors">')
    $null = $Builder.AppendLine('                  <div class="dkim-selectors-title">Selector details</div>')
    $null = $Builder.AppendLine('                  <div class="dkim-selector-grid">')

    foreach ($selector in $selectorList) {
        $found = if ($selector.PSObject.Properties.Name -contains 'Found') {
            [bool]$selector.Found
        }
        elseif ($selector.PSObject.Properties.Name -contains 'DkimRecordExists') {
            [bool]$selector.DkimRecordExists
        }
        else {
            $true
        }
        $keyLengthValue = if ($selector.KeyLength) { $selector.KeyLength } else { 'Unknown' }
        $ttl = Get-DSATtlValue -InputObject $selector
        $ttlValue = if ($null -ne $ttl) { $ttl } else { 'Unknown' }
        $selectorName = if ($selector.PSObject.Properties.Name -contains 'Name') { $selector.Name } else { $selector.Selector }

        $status = Get-DSADkimSelectorStatus -Selector $selector -Check $Check
        $statusClass = Get-DSAStatusClassName -Status $status

        $null = $Builder.AppendLine(("                    <div class=""selector-card {0}"">" -f $statusClass))
        $null = $Builder.AppendLine(("                      <div class=""selector-name"">{0}</div>" -f (ConvertTo-DSAHtml $selectorName)))
        $null = $Builder.AppendLine(("                      <div class=""selector-status {0}"">{1}</div>" -f $statusClass, (ConvertTo-DSAHtml $status)))
        $null = $Builder.AppendLine('                      <div class="selector-meta">')
        if ($Check.Id -eq 'DKIMKeyStrength') {
            $null = $Builder.AppendLine(("                        <span>Key: {0}</span>" -f (ConvertTo-DSAHtml $keyLengthValue)))
        }
        if ($Check.Id -eq 'DKIMTtl') {
            $null = $Builder.AppendLine(("                        <span>TTL: {0}</span>" -f (ConvertTo-DSAHtml $ttlValue)))
        }
        if (-not $found) {
            $null = $Builder.AppendLine('                        <span class="selector-warning">Not found</span>')
        }
        $null = $Builder.AppendLine('                      </div>')
        $null = $Builder.AppendLine('                    </div>')
    }

    $null = $Builder.AppendLine('                  </div>')
    $null = $Builder.AppendLine('                </div>')
}
