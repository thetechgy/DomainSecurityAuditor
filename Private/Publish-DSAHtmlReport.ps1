$script:DSAKnownReferenceLinks = @{
    'dmarc.org Deployment Guide'             = 'https://dmarc.org/resources/deployment/'
    'M3AAWG Email Authentication Best Practices' = 'https://www.m3aawg.org/published-documents/m3aawg-email-authentication-best-practices'
    'M3AAWG DKIM Deployment Guide'           = 'https://www.m3aawg.org/published-documents/m3aawg-dkim-deployment-document'
    'M3AAWG DMARC Deployment'                = 'https://www.m3aawg.org/published-documents/m3aawg-dmarc-deployment'
    'M3AAWG TLS Guidance'                    = 'https://www.m3aawg.org/published-documents/m3aawg-tls-best-practices'
    'M3AAWG Operational Guidance'            = 'https://www.m3aawg.org/published-documents'
}

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
    $reportFileName = '{0}_domain_security_report.html' -f $GeneratedOn.ToString('yyyyMMdd_HHmmss')
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
    $null = $builder.AppendLine('    <title>Domain Security Compliance Report</title>')
    $null = $builder.AppendLine('    <style>')
    $null = $builder.AppendLine((Get-DSAReportStyles))
    $null = $builder.AppendLine('    </style>')
    $null = $builder.AppendLine('</head>')
    $null = $builder.AppendLine('<body>')
    $null = $builder.AppendLine('  <a href="#main-content" class="skip-link">Skip to main content</a>')
    $null = $builder.AppendLine('  <main class="container" id="main-content" role="main">')
    $null = $builder.AppendLine('    <header class="header">')
    $null = $builder.AppendLine('      <h1>Domain Security Compliance Report</h1>')
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

    $null = $builder.AppendLine('  </div>')
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

function Add-DSADomainSections {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject[]]$Profiles
    )

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

    $areaStatus = Get-DSAAreaStatus -Checks $Group.Group
    $statusClass = Get-DSAStatusClassName -Status $areaStatus
    $checkCount = ($groupChecks | Measure-Object).Count
    $sectionClass = 'protocol-section'
    $detailsClass = 'protocol-details'
    $checkLabel = if ($checkCount -eq 1) { '1 check' } else { ('{0} checks' -f $checkCount) }
    $areaSlug = ($Group.Name -replace '[^a-zA-Z0-9]', '-').ToLowerInvariant()
    $detailsId = "protocol-{0}-{1}" -f $DomainSlug, $areaSlug

    $null = $Builder.AppendLine(("      <div class=""{0}"">" -f $sectionClass))
    $null = $Builder.AppendLine(("        <div class=""protocol-header"" role=""button"" tabindex=""0"" aria-expanded=""false"" aria-controls=""{0}"">" -f $detailsId))
    $null = $Builder.AppendLine(("          <div class='protocol-name'>{0}</div>" -f (ConvertTo-DSAHtml $Group.Name)))
    $null = $Builder.AppendLine('          <div class="protocol-status">')
    $null = $Builder.AppendLine(("            <span class='status-badge {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $areaStatus)))
    $null = $Builder.AppendLine(("            <span class='protocol-count'>{0}</span>" -f $checkLabel))
    $null = $Builder.AppendLine('            <span class="chevron" aria-hidden="true">▶</span>')
    $null = $Builder.AppendLine('          </div>')
    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine(("        <div class=""{0}"" id=""{1}"" aria-hidden=""true"">" -f $detailsClass, $detailsId))

    $selectorDetails = $null
    if (($Group.Name -eq 'DKIM') -and $Profile -and $Profile.PSObject.Properties.Name -contains 'Evidence') {
        $selectorDetails = $Profile.Evidence.DKIMSelectorDetails
    }

    foreach ($check in $groupChecks) {
        Add-DSATestResult -Builder $Builder -Check $check -Selectors $selectorDetails
    }

    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine('      </div>')
}

function Add-DSATestResult {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject]$Check,
        [pscustomobject[]]$Selectors
    )

    if (-not $Check) {
        return
    }

    $statusClass = Get-DSAStatusClassName -Status $Check.Status
    $statusIcon = Get-DSAStatusIcon -Status $Check.Status
    $filterStatus = Get-DSAFilterStatus -Status $Check.Status
    $detailItems = [System.Collections.Generic.List[object]]::new()
    if ($Check.PSObject.Properties.Name -contains 'Actual' -and ($Check.Actual -ne $null)) {
        $valueHtml = ConvertTo-DSAValueHtml -Value $Check.Actual
        $null = $detailItems.Add([pscustomobject]@{
                Label = 'Observed Value'
                Value = $valueHtml
                IsHtml = $true
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
    $null = $Builder.AppendLine(("              <div class='test-icon {0}'>{1}</div>" -f $statusClass, (ConvertTo-DSAHtml $statusIcon)))
    $null = $Builder.AppendLine('              <div class="test-content">')
    $null = $Builder.AppendLine('                <div class="test-title-row">')
    $null = $Builder.AppendLine(("                  <div class='test-name'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Id)))
    $null = $Builder.AppendLine(("                  <span class='status-pill {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $Check.Status)))
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

    if ($Selectors -and $Check.Area -eq 'DKIM') {
        Add-DSADkimSelectorBreakdown -Builder $Builder -Selectors $Selectors -Check $Check
    }

    $null = $Builder.AppendLine('              </div>')
    $null = $Builder.AppendLine('            </div>')
    $null = $Builder.AppendLine('          </div>')
}

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
        $checks = if ($profile.Checks) { @($profile.Checks | Where-Object { $_ }) } else { @() }
        foreach ($check in $checks) {
            if (-not $check) {
                continue
            }
            $totalChecks++
            switch ($check.Status) {
                'Pass' { $checkStatusCounts['Pass'] += 1 }
                'Fail' { $checkStatusCounts['Fail'] += 1 }
                'Warning' { $checkStatusCounts['Warning'] += 1 }
            }
        }
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

function Get-DSAReportStyles {
@"
:root {
    --color-bg: #f5f7fa;
    --color-surface: #ffffff;
    --color-surface-alt: #f8fafc;
    --color-surface-subtle: #f9fafb;
    --color-text: #1f2937;
    --color-text-strong: #111827;
    --color-muted: #4b5563;
    --color-muted-light: #6b7280;
    --color-muted-lightest: #9ca3af;
    --color-border: #e5e7eb;
    --color-border-light: #f3f4f6;
    --color-pass: #0f766e;
    --color-pass-bg: #ecfdf3;
    --color-fail: #b91c1c;
    --color-fail-bg: #fef2f2;
    --color-warn: #92400e;
    --color-warn-bg: #fffbeb;
    --color-info: #1d4ed8;
    --color-info-bg: #e0e7ff;
    --color-info-text: #1e3a8a;
    --color-focus: #2563eb;
    --color-focus-light: #ffffff;
    --color-header-start: #363671;
    --color-header-end: #1f2a44;
    --color-recommendation-bg: #eef2ff;
    --color-recommendation-border: #4338ca;
    --color-recommendation-label: #312e81;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.7;
    color: var(--color-text);
    background-color: var(--color-bg);
    font-size: 16px;
}
.skip-link {
    position: absolute;
    top: -100px;
    left: 50%;
    transform: translateX(-50%);
    background: var(--color-text-strong);
    color: var(--color-surface);
    padding: 12px 24px;
    border-radius: 0 0 8px 8px;
    text-decoration: none;
    font-weight: 700;
    z-index: 1000;
    transition: top 0.2s ease;
}
.skip-link:focus {
    top: 0;
    outline: 3px solid var(--color-focus);
    outline-offset: 2px;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}
.header {
    background: linear-gradient(135deg, var(--color-header-start) 0%, var(--color-header-end) 100%);
    color: white;
    padding: 32px;
    border-radius: 12px;
    margin-bottom: 30px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.12);
}
.header h1 {
    font-size: clamp(2rem, 2vw + 1rem, 2.6rem);
    margin-bottom: 12px;
}
.header .meta {
    opacity: 0.95;
    font-size: 1.05rem;
}
.summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.filter-summary {
    margin-top: 8px;
    color: var(--color-muted);
    font-size: 0.95rem;
    font-weight: 600;
}
.card {
    background: var(--color-surface);
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.card:hover { transform: translateY(-2px); }
.card:focus-visible, .protocol-header:focus-visible {
    outline: 3px solid var(--color-focus);
    outline-offset: 4px;
}
.header .card:focus-visible {
    outline-color: var(--color-focus-light);
}
.card-header { display: flex; align-items: center; margin-bottom: 12px; }
.card-icon {
    width: 42px;
    height: 42px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 14px;
    font-weight: bold;
    color: white;
    font-size: 1.1rem;
}
.card-title { font-size: 1.1rem; font-weight: 600; color: var(--color-text-strong); }
.card-value {
    font-size: 2.1rem;
    font-weight: 700;
    margin-bottom: 6px;
}
.card-subtitle { color: var(--color-muted-light); font-size: 1rem; }
.card-icon.passed { background-color: var(--color-pass); }
.card-value.passed { color: var(--color-pass); }
.card-icon.failed { background-color: var(--color-fail); }
.card-value.failed { color: var(--color-fail); }
.card-icon.warning { background-color: var(--color-warn); }
.card-value.warning { color: var(--color-warn); }
.card-icon.info { background-color: var(--color-info); }
.card-value.info { color: var(--color-info); }
.card.filter-card {
    cursor: pointer;
    transition: box-shadow 0.2s ease, transform 0.2s ease;
}
.card.filter-card.active { box-shadow: 0 0 0 3px rgba(37,99,235,0.5); transform: translateY(-2px); }
.domain-results {
    background: var(--color-surface);
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    margin-bottom: 30px;
    overflow: hidden;
}
.domain-empty {
    padding: 24px;
    color: var(--color-muted-light);
    font-style: italic;
    border-top: 1px solid var(--color-border-light);
}
.domain-header {
    background: var(--color-surface-alt);
    padding: 22px;
    border-bottom: 1px solid var(--color-border);
}
.domain-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.domain-name { font-size: 1.5rem; font-weight: 700; color: var(--color-text-strong); }
.domain-meta { margin-top: 12px; color: var(--color-muted-light); font-size: 0.98rem; }
.domain-status {
    padding: 8px 18px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.domain-status.passed { background-color: var(--color-pass-bg); color: var(--color-pass); border: 2px solid var(--color-pass); }
.domain-status.failed { background-color: var(--color-fail-bg); color: var(--color-fail); border: 2px solid var(--color-fail); }
.domain-status.warning { background-color: var(--color-warn-bg); color: var(--color-warn); border: 2px solid var(--color-warn); }
.protocol-section { border-bottom: 1px solid var(--color-border); }
.protocol-header {
    background: var(--color-surface-subtle);
    padding: 18px 24px;
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.protocol-header:hover { background: var(--color-border-light); }
.protocol-name { font-weight: 700; font-size: 1.05rem; color: var(--color-text-strong); }
.protocol-status { display: flex; align-items: center; gap: 12px; font-size: 0.95rem; color: var(--color-muted); }
.protocol-count { font-weight: 600; color: var(--color-text-strong); }
.chevron {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--color-border);
    color: var(--color-text-strong);
    font-size: 0.75rem;
    transition: transform 0.2s ease, background-color 0.2s ease, color 0.2s ease;
}
.protocol-section.expanded .chevron {
    transform: rotate(90deg);
    background: var(--color-info-bg);
    color: var(--color-info-text);
}
.status-badge {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.9rem;
    font-weight: 700;
    text-transform: uppercase;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}
.status-badge.passed { background-color: var(--color-pass-bg); color: var(--color-pass); border-bottom: 2px solid var(--color-pass); }
.status-badge.failed { background-color: var(--color-fail-bg); color: var(--color-fail); border-bottom: 2px solid var(--color-fail); }
.status-badge.warning { background-color: var(--color-warn-bg); color: var(--color-warn); border-bottom: 2px solid var(--color-warn); }
.status-badge.info { background-color: var(--color-info-bg); color: var(--color-info-text); border-bottom: 2px solid var(--color-info); }
.protocol-details { display: none; padding: 0; }
.protocol-details.expanded { display: block; }
.test-result {
    padding: 18px 24px;
    border-top: 1px solid var(--color-border-light);
}
.test-result:last-child { border-bottom: none; }
.test-header { display: flex; align-items: flex-start; gap: 16px; }
.test-icon {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.95rem;
    font-weight: 700;
    color: white;
    flex-shrink: 0;
    box-shadow: 0 2px 6px rgba(0,0,0,0.12);
}
.test-icon.passed { background-color: var(--color-pass); }
.test-icon.failed { background-color: var(--color-fail); }
.test-icon.warning { background-color: var(--color-warn); }
.test-icon.info { background-color: var(--color-info); }
.test-content { flex: 1; display: flex; flex-direction: column; gap: 10px; }
.test-title-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.test-name { font-weight: 700; color: var(--color-text-strong); font-size: 1rem; }
.test-message { color: var(--color-muted-light); font-size: 0.97rem; }
.status-pill {
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.85rem;
    text-transform: uppercase;
    font-weight: 700;
}
.status-pill.passed { background-color: var(--color-pass-bg); color: var(--color-pass); border-bottom: 2px solid var(--color-pass); }
.status-pill.failed { background-color: var(--color-fail-bg); color: var(--color-fail); border-bottom: 2px solid var(--color-fail); }
.status-pill.warning { background-color: var(--color-warn-bg); color: var(--color-warn); border-bottom: 2px solid var(--color-warn); }
.status-pill.info { background-color: var(--color-info-bg); color: var(--color-info-text); border-bottom: 2px solid var(--color-info); }
.details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
}
.detail-item {
    background: var(--color-surface-subtle);
    padding: 10px;
    border-radius: 8px;
}
.detail-label {
    font-size: 0.78rem;
    color: var(--color-muted-light);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}
.detail-value {
    font-weight: 700;
    color: var(--color-text-strong);
    word-break: break-word;
    overflow-wrap: anywhere;
}
.test-recommendation {
    background: var(--color-recommendation-bg);
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid var(--color-recommendation-border);
}
.test-recommendation .label {
    font-weight: 700;
    color: var(--color-recommendation-label);
    margin-bottom: 4px;
}
.test-recommendation .text { color: var(--color-text); }
.test-references {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.dkim-selectors {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--color-surface-subtle);
    border: 1px solid var(--color-border);
}
.dkim-selectors-title {
    font-weight: 700;
    color: var(--color-text-strong);
    margin-bottom: 8px;
    font-size: 0.95rem;
}
.dkim-selector-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
}
.selector-card {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
.selector-card.passed { border-color: var(--color-pass); }
.selector-card.failed { border-color: var(--color-fail); }
.selector-name { font-weight: 700; color: var(--color-text-strong); }
.selector-status { font-weight: 700; margin-top: 2px; text-transform: uppercase; font-size: 0.8rem; }
.selector-status.passed { color: var(--color-pass); }
.selector-status.failed { color: var(--color-fail); }
.selector-meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; color: var(--color-muted); font-size: 0.9rem; }
.selector-warning { color: var(--color-warn); font-weight: 700; }
.reference-link {
    display: inline-block;
    padding: 6px 12px;
    border-radius: 999px;
    background: var(--color-border);
    color: var(--color-text-strong);
    text-decoration: none;
    font-size: 0.9rem;
    font-weight: 700;
    transition: background-color 0.2s ease, color 0.2s ease;
}
.reference-link:hover {
    background: #d1d5db;
    color: var(--color-text-strong);
}
.reference-link.reference-link--static {
    cursor: default;
    background: var(--color-border-light);
    color: var(--color-muted-light);
}
.footer {
    background: var(--color-surface);
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    text-align: center;
    color: var(--color-muted-light);
    margin: 40px auto 0;
    max-width: 960px;
}
.footer p {
    margin-bottom: 8px;
}
.footer-secondary {
    margin-top: 10px;
    font-size: 0.95rem;
}
.value-none { color: var(--color-muted-lightest); font-style: italic; }
.value-positive { color: var(--color-pass); font-weight: 700; }
.value-negative { color: var(--color-fail); font-weight: 700; }
@media (max-width: 640px) {
    .domain-title { flex-direction: column; align-items: flex-start; gap: 10px; }
    .summary-cards { grid-template-columns: 1fr; }
    .test-title-row { flex-direction: column; align-items: flex-start; gap: 6px; }
    .protocol-header { padding: 16px; }
}
@media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation-duration: 0.01ms !important; }
    .card:hover { transform: none; }
    .chevron { transform: none !important; }
}
"@
}


function Get-DSAReportScript {
@"
const protocolSections = document.querySelectorAll('.protocol-section');

const setSectionExpanded = (section, header, details, expanded) => {
    section.classList.toggle('expanded', expanded);
    if (details) {
        details.classList.toggle('expanded', expanded);
        details.setAttribute('aria-hidden', expanded ? 'false' : 'true');
    }
    if (header) {
        header.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    }
};

protocolSections.forEach((section) => {
    const header = section.querySelector('.protocol-header');
    const details = section.querySelector('.protocol-details');
    if (!header || !details) {
        return;
    }
    setSectionExpanded(section, header, details, false);

    const toggleSection = () => {
        const expanded = !section.classList.contains('expanded');
        setSectionExpanded(section, header, details, expanded);
    };

    header.addEventListener('click', toggleSection);
    header.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleSection();
        }
    });
});

const filterCards = document.querySelectorAll('.summary-cards .card[data-filter]');
const domainSections = document.querySelectorAll('.domain-results');
const filterSummary = document.getElementById('filter-summary');
let activeFilters = ['all'];

const setCardState = (card, isActive) => {
    card.classList.toggle('active', isActive);
    card.setAttribute('aria-pressed', isActive ? 'true' : 'false');
};

const renderFilterSummary = () => {
    if (!filterSummary) {
        return;
    }
    if (activeFilters.includes('all')) {
        filterSummary.textContent = 'Showing: All checks';
    } else {
        const pretty = activeFilters.map(f => {
            switch (f) {
                case 'pass': return 'Passing';
                case 'fail': return 'Failing';
                case 'warning': return 'Warning';
                default: return f;
            }
        });
        filterSummary.textContent = 'Showing: ' + pretty.join(', ');
    }
};

const applyDomainFilter = (filters) => {
    const normalizedFilters = (filters || ['all']).map(f => (f || 'all').toLowerCase());
    const matchAll = normalizedFilters.includes('all');

    domainSections.forEach(domain => {
        let domainHasMatch = false;
        const protocols = domain.querySelectorAll('.protocol-section');

        protocols.forEach(section => {
            const details = section.querySelector('.protocol-details');
            const tests = section.querySelectorAll('.test-result');
            let sectionHasMatch = false;

            tests.forEach(test => {
                const status = (test.getAttribute('data-status') || '').toLowerCase();
                const matches = matchAll || normalizedFilters.includes(status);
                test.style.display = matches ? '' : 'none';
                if (matches) {
                    sectionHasMatch = true;
                }
            });

            if (matchAll) {
                section.style.display = '';
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, section.classList.contains('expanded'));
                delete section.dataset.filterExpanded;
            } else if (sectionHasMatch) {
                section.style.display = '';
                domainHasMatch = true;
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, true);
                section.dataset.filterExpanded = 'true';
            } else {
                section.style.display = 'none';
                setSectionExpanded(section, section.querySelector('.protocol-header'), details, false);
                delete section.dataset.filterExpanded;
            }
        });

        domain.style.display = (matchAll || domainHasMatch) ? '' : 'none';
    });
};

filterCards.forEach(card => {
    card.addEventListener('click', () => {
        const filter = card.getAttribute('data-filter') || 'all';
        if (filter === 'all') {
            activeFilters = ['all'];
            filterCards.forEach(c => setCardState(c, c.getAttribute('data-filter') === 'all'));
        } else {
            const isActive = card.classList.contains('active');
            if (isActive) {
                activeFilters = activeFilters.filter(f => f !== filter);
            } else {
                activeFilters = activeFilters.filter(f => f !== 'all');
                activeFilters.push(filter);
            }
            if (activeFilters.length === 0) {
                activeFilters = ['all'];
            }
            filterCards.forEach(c => {
                const f = c.getAttribute('data-filter');
                setCardState(c, activeFilters.includes(f));
            });
        }
        renderFilterSummary();
        applyDomainFilter(activeFilters);
    });

    card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            card.click();
        }
    });
});

const defaultFilter = document.querySelector('.summary-cards .card[data-filter=\"all\"]');
if (defaultFilter) {
    activeFilters = ['all'];
    setCardState(defaultFilter, true);
    filterCards.forEach(c => {
        if (c !== defaultFilter) {
            setCardState(c, false);
        }
    });
    renderFilterSummary();
    applyDomainFilter(activeFilters);
} else {
    activeFilters = ['all'];
    renderFilterSummary();
    applyDomainFilter(activeFilters);
}
"@
}

function ConvertTo-DSAHtml {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    return [System.Net.WebUtility]::HtmlEncode($text)
}

function ConvertTo-DSAValueHtml {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return '<span class="value-none">None</span>'
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return '<span class="value-positive">Yes</span>'
        }
        return '<span class="value-negative">No</span>'
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @($Value | Where-Object { $_ })
        if ($items.Count -eq 0) {
            return '<span class="value-none">None</span>'
        }
        return ($items | ForEach-Object { ConvertTo-DSAHtml $_ }) -join ', '
    }

    return ConvertTo-DSAHtml -Value $Value
}

function ConvertTo-DSAReferenceHtml {
    param (
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return ''
    }

    $normalized = $Reference.Trim()
    $link = Get-DSAKnownReferenceLink -Reference $normalized
    if (-not $link -and $normalized -match '^(https?://\S+)$') {
        $link = $matches[1]
    }

    if ($link) {
        $display = ConvertTo-DSAHtml -Value $normalized
        return ("<a class=""reference-link"" href=""{0}"" target=""_blank"" rel=""noopener"">{1}</a>" -f $link, $display)
    }

    $displayText = ConvertTo-DSAHtml -Value $normalized
    return ("<span class=""reference-link reference-link--static"">{0}</span>" -f $displayText)
}

function Get-DSAKnownReferenceLink {
    param (
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $null
    }

    $trimmed = $Reference.Trim()

    if ($trimmed -match '^RFC\s+(\d+)(?:\s+§\s*([\d\.]+))?$') {
        $rfcNumber = $matches[1]
        $section = $matches[2]
        $url = "https://www.rfc-editor.org/rfc/rfc$rfcNumber"
        if ($section) {
            $sectionFragment = $section -replace '\s+', ''
            $url = "$url#section-$sectionFragment"
        }
        return $url
    }

    if ($script:DSAKnownReferenceLinks.ContainsKey($trimmed)) {
        return $script:DSAKnownReferenceLinks[$trimmed]
    }

    return $null
}

function Get-DSAStatusClassName {
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return 'info'
    }

    switch ($Status.ToLowerInvariant()) {
        'pass' { return 'passed' }
        'fail' { return 'failed' }
        'warning' { return 'warning' }
        default { return 'info' }
    }
}

function Get-DSAStatusIcon {
    param (
        [string]$Status
    )

    switch ($Status.ToLowerInvariant()) {
        'pass' { return '✔' }
        'fail' { return '✖' }
        'warning' { return '!' }
        default { return 'ℹ' }
    }
}

function Get-DSAFilterStatus {
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return 'info'
    }

    switch ($Status.ToLowerInvariant()) {
        'pass' { return 'pass' }
        'fail' { return 'fail' }
        'warning' { return 'warning' }
        default { return 'info' }
    }
}

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
        $found = if ($selector.PSObject.Properties.Name -contains 'Found') { [bool]$selector.Found } else { $true }
        $keyLengthValue = if ($selector.KeyLength) { $selector.KeyLength } else { 'Unknown' }
        $ttlValue = if ($selector.Ttl) { $selector.Ttl } else { 'Unknown' }

        $status = Get-DSADkimSelectorStatus -Selector $selector -Check $Check
        $statusClass = Get-DSAStatusClassName -Status $status

        $null = $Builder.AppendLine(("                    <div class=""selector-card {0}"">" -f $statusClass))
        $null = $Builder.AppendLine(("                      <div class=""selector-name"">{0}</div>" -f (ConvertTo-DSAHtml $selector.Name)))
        $null = $Builder.AppendLine(("                      <div class=""selector-status {0}"">{1}</div>" -f $statusClass, (ConvertTo-DSAHtml $status)))
        $null = $Builder.AppendLine('                      <div class="selector-meta">')
        $null = $Builder.AppendLine(("                        <span>Key: {0}</span>" -f (ConvertTo-DSAHtml $keyLengthValue)))
        $null = $Builder.AppendLine(("                        <span>TTL: {0}</span>" -f (ConvertTo-DSAHtml $ttlValue)))
        if (-not $found) {
            $null = $Builder.AppendLine('                        <span class="selector-warning">Not found</span>')
        }
        $null = $Builder.AppendLine('                      </div>')
        $null = $Builder.AppendLine('                    </div>')
    }

    $null = $Builder.AppendLine('                  </div>')
    $null = $Builder.AppendLine('                </div>')
}

function Get-DSADkimSelectorStatus {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$Selector,
        [Parameter(Mandatory = $true)][pscustomobject]$Check
    )

    $found = if ($Selector.PSObject.Properties.Name -contains 'Found') { [bool]$Selector.Found } else { $true }
    $keyLength = $Selector.KeyLength
    $ttl = $Selector.Ttl
    $isValid = if ($Selector.PSObject.Properties.Name -contains 'IsValid') { [bool]$Selector.IsValid } else { $true }

    switch ($Check.Id) {
        'DKIMSelectorPresence' {
            return $(if ($found) { 'Pass' } else { 'Fail' })
        }
        'DKIMKeyStrength' {
            $min = if ($Check.PSObject.Properties.Name -contains 'ExpectedValue') { $Check.ExpectedValue } else { 1024 }
            $passesKey = $keyLength -as [int] -ge $min
            return $(if ($found -and $passesKey -and $isValid) { 'Pass' } else { 'Fail' })
        }
        'DKIMSelectorHealth' {
            $min = 1024
            $passesKey = $keyLength -as [int] -ge $min
            return $(if ($found -and $isValid -and $passesKey) { 'Pass' } else { 'Fail' })
        }
        'DKIMTtl' {
            $min = $null
            $max = $null
            if ($Check.PSObject.Properties.Name -contains 'ExpectedValue') {
                $min = $Check.ExpectedValue.Min
                $max = $Check.ExpectedValue.Max
            }
            $ttlNumber = $ttl -as [int]
            $passTtl = $false
            if ($ttlNumber -and $min -and $max) {
                $passTtl = ($ttlNumber -ge $min -and $ttlNumber -le $max)
            }
            return $(if ($passTtl) { 'Pass' } else { 'Fail' })
        }
        default {
            return $(if ($found -and $isValid) { 'Pass' } else { 'Fail' })
        }
    }
}

function Get-DSAAreaStatus {
    param (
        [Parameter(Mandatory = $true)][System.Collections.IEnumerable]$Checks
    )

    $checkArray = @($Checks)
    if ($checkArray | Where-Object { $_.Status -eq 'Fail' }) {
        return 'Fail'
    }
    if ($checkArray | Where-Object { $_.Status -eq 'Warning' }) {
        return 'Warning'
    }
    return 'Pass'

}
