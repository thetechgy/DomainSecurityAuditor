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
    $moduleVersion = if ($module) { $module.Version.ToString() } else { $null }
    $frameworkText = if ($moduleVersion) { "Framework Version: DomainSecurityAuditor $moduleVersion" } else { 'Framework Version: DomainSecurityAuditor' }
    $domainSummaryText = "Domains Evaluated: $($summary.DomainCount) | Checks Evaluated: $($summary.TotalChecks)"

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
    $null = $builder.AppendLine('  <div class="container">')
    $null = $builder.AppendLine('    <header class="header">')
    $null = $builder.AppendLine('      <h1>Domain Security Compliance Report</h1>')
    $null = $builder.AppendLine(('      <div class="meta">Generated on {0}</div>' -f (ConvertTo-DSAHtml ($GeneratedOn.ToString('dddd, MMMM d, yyyy h:mm tt')))))
    $null = $builder.AppendLine(('      <div class="meta">{0}</div>' -f (ConvertTo-DSAHtml $domainSummaryText)))
    $null = $builder.AppendLine(('      <div class="meta">{0}</div>' -f (ConvertTo-DSAHtml $frameworkText)))
    $null = $builder.AppendLine('    </header>')

    Add-DSASummaryCards -Builder $builder -Summary $summary
    Add-DSADomainSections -Builder $builder -Profiles $profilesList

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
        $null = $Builder.AppendLine(("        <div class=""{0}""{1}>" -f $cardClasses, $filterAttr))
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
        if ($profile.Classification) {
            $null = $metaSegments.Add($profile.Classification)
        }
        if ($profile.OriginalClassification) {
            $null = $metaSegments.Add(("Detected: {0}" -f $profile.OriginalClassification))
        }
        if ($checkCount -gt 0) {
            $null = $metaSegments.Add(("{0} checks executed" -f $checkCount))
        }
        if ($profile.PSObject.Properties.Name -contains 'Timestamp' -and $profile.Timestamp) {
            $formatted = $profile.Timestamp.ToString('MMMM d, yyyy h:mm tt')
            $null = $metaSegments.Add(("Evaluated on {0}" -f $formatted))
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
        foreach ($group in $groupedChecks) {
            Add-DSAProtocolSection -Builder $Builder -Group $group
        }

        $null = $Builder.AppendLine('    </section>')
    }
}

function Add-DSAProtocolSection {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSObject]$Group
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

    $null = $Builder.AppendLine(("      <div class=""{0}"">" -f $sectionClass))
    $null = $Builder.AppendLine('        <div class="protocol-header">')
    $null = $Builder.AppendLine(("          <div class='protocol-name'>{0}</div>" -f (ConvertTo-DSAHtml $Group.Name)))
    $null = $Builder.AppendLine('          <div class="protocol-status">')
    $null = $Builder.AppendLine(("            <span class='status-badge {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $areaStatus)))
    $null = $Builder.AppendLine(("            <span class='protocol-count'>{0}</span>" -f $checkLabel))
    $null = $Builder.AppendLine('            <span class="chevron" aria-hidden="true">▶</span>')
    $null = $Builder.AppendLine('          </div>')
    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine(("        <div class=""{0}"">" -f $detailsClass))

    foreach ($check in $groupChecks) {
        Add-DSATestResult -Builder $Builder -Check $check
    }

    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine('      </div>')
}

function Add-DSATestResult {
    param (
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][pscustomobject]$Check
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

    if ($Check.Remediation) {
        $null = $Builder.AppendLine('                <div class="test-recommendation">')
        $null = $Builder.AppendLine('                  <div class="label">Remediation</div>')
        $null = $Builder.AppendLine(("                  <div class='text'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Remediation)))
        $null = $Builder.AppendLine('                </div>')
    }

    if ($Check.References -and $Check.References.Count -gt 0) {
        $references = $Check.References | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
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
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f7fa;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}
.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 30px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}
.header h1 {
    font-size: 2.5rem;
    margin-bottom: 10px;
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
.card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.card:hover { transform: translateY(-2px); }
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
.card-title { font-size: 1.1rem; font-weight: 600; color: #374151; }
.card-value {
    font-size: 2.1rem;
    font-weight: 700;
    margin-bottom: 6px;
}
.card-subtitle { color: #6b7280; font-size: 0.95rem; }
.card-icon.passed { background-color: #10b981; }
.card-value.passed { color: #10b981; }
.card-icon.failed { background-color: #ef4444; }
.card-value.failed { color: #ef4444; }
.card-icon.warning { background-color: #f59e0b; }
.card-value.warning { color: #f59e0b; }
.card-icon.info { background-color: #3b82f6; }
.card-value.info { color: #3b82f6; }
.card.filter-card { cursor: pointer; transition: box-shadow 0.2s ease, transform 0.2s ease; }
.card.filter-card.active { box-shadow: 0 0 0 3px rgba(59,130,246,0.35); transform: translateY(-2px); }
.domain-results {
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    margin-bottom: 30px;
    overflow: hidden;
}
.domain-empty {
    padding: 24px;
    color: #6b7280;
    font-style: italic;
    border-top: 1px solid #f3f4f6;
}
.domain-header {
    background: #f8fafc;
    padding: 22px;
    border-bottom: 1px solid #e5e7eb;
}
.domain-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.domain-name { font-size: 1.5rem; font-weight: 600; color: #374151; }
.domain-meta { margin-top: 12px; color: #6b7280; font-size: 0.95rem; }
.domain-status {
    padding: 8px 18px;
    border-radius: 999px;
    font-weight: 600;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.domain-status.passed { background-color: #d1fae5; color: #065f46; }
.domain-status.failed { background-color: #fee2e2; color: #991b1b; }
.domain-status.warning { background-color: #fef3c7; color: #92400e; }
.protocol-section { border-bottom: 1px solid #e5e7eb; }
.protocol-header {
    background: #f9fafb;
    padding: 18px 24px;
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.protocol-header:hover { background: #f3f4f6; }
.protocol-name { font-weight: 600; font-size: 1.05rem; color: #374151; }
.protocol-status { display: flex; align-items: center; gap: 12px; font-size: 0.9rem; color: #6b7280; }
.protocol-count { font-weight: 500; color: #4b5563; }
.chevron {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #e5e7eb;
    color: #4b5563;
    font-size: 0.75rem;
    transition: transform 0.2s ease, background-color 0.2s ease, color 0.2s ease;
}
.protocol-section.expanded .chevron {
    transform: rotate(90deg);
    background: #c7d2fe;
    color: #312e81;
}
.status-badge {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
}
.status-badge.passed { background-color: #d1fae5; color: #065f46; }
.status-badge.failed { background-color: #fee2e2; color: #991b1b; }
.status-badge.warning { background-color: #fef3c7; color: #92400e; }
.status-badge.info { background-color: #e0e7ff; color: #312e81; }
.protocol-details { display: none; padding: 0; }
.protocol-details.expanded { display: block; }
.test-result {
    padding: 18px 24px;
    border-top: 1px solid #f3f4f6;
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
.test-icon.passed { background-color: #10b981; }
.test-icon.failed { background-color: #ef4444; }
.test-icon.warning { background-color: #f59e0b; }
.test-icon.info { background-color: #3b82f6; }
.test-content { flex: 1; display: flex; flex-direction: column; gap: 10px; }
.test-title-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.test-name { font-weight: 600; color: #111827; font-size: 1rem; }
.test-message { color: #6b7280; font-size: 0.95rem; }
.status-pill {
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    text-transform: uppercase;
    font-weight: 600;
}
.status-pill.passed { background-color: #d1fae5; color: #065f46; }
.status-pill.failed { background-color: #fee2e2; color: #991b1b; }
.status-pill.warning { background-color: #fef3c7; color: #92400e; }
.status-pill.info { background-color: #e0e7ff; color: #312e81; }
.details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
}
.detail-item {
    background: #f9fafb;
    padding: 10px;
    border-radius: 8px;
}
.detail-label {
    font-size: 0.75rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}
.detail-value {
    font-weight: 600;
    color: #374151;
}
.test-recommendation {
    background: #eef2ff;
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid #4338ca;
}
.test-recommendation .label {
    font-weight: 600;
    color: #312e81;
    margin-bottom: 4px;
}
.test-recommendation .text { color: #1f2937; }
.test-references {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.reference-link {
    display: inline-block;
    padding: 6px 12px;
    border-radius: 999px;
    background: #e5e7eb;
    color: #374151;
    text-decoration: none;
    font-size: 0.85rem;
    font-weight: 600;
    transition: background-color 0.2s ease, color 0.2s ease;
}
.reference-link:hover {
    background: #d1d5db;
    color: #111827;
}
.reference-link.reference-link--static {
    cursor: default;
    background: #f3f4f6;
    color: #6b7280;
}
.value-none { color: #9ca3af; font-style: italic; }
.value-positive { color: #065f46; font-weight: 600; }
.value-negative { color: #991b1b; font-weight: 600; }
@media (max-width: 640px) {
    .domain-title { flex-direction: column; align-items: flex-start; gap: 10px; }
    .summary-cards { grid-template-columns: 1fr; }
    .test-title-row { flex-direction: column; align-items: flex-start; gap: 6px; }
}
"@
}


function Get-DSAReportScript {
@"
const protocolSections = document.querySelectorAll('.protocol-section');
protocolSections.forEach((section) => {
    const header = section.querySelector('.protocol-header');
    const details = section.querySelector('.protocol-details');
    if (!header || !details) {
        return;
    }
    header.addEventListener('click', () => {
        section.classList.toggle('expanded');
        details.classList.toggle('expanded');
    });
});

const filterCards = document.querySelectorAll('.summary-cards .card[data-filter]');
const domainSections = document.querySelectorAll('.domain-results');

const applyDomainFilter = (filter) => {
    const normalizedFilter = (filter || 'all').toLowerCase();
    const matchAll = normalizedFilter === 'all';

    domainSections.forEach(domain => {
        let domainHasMatch = false;
        const protocols = domain.querySelectorAll('.protocol-section');

        protocols.forEach(section => {
            const details = section.querySelector('.protocol-details');
            const tests = section.querySelectorAll('.test-result');
            let sectionHasMatch = false;

            tests.forEach(test => {
                const status = (test.getAttribute('data-status') || '').toLowerCase();
                const matches = matchAll || status === normalizedFilter;
                test.style.display = matches ? '' : 'none';
                if (matches) {
                    sectionHasMatch = true;
                }
            });

            if (matchAll) {
                section.style.display = '';
                if (section.dataset.filterExpanded === 'true') {
                    section.classList.remove('expanded');
                    if (details) {
                        details.classList.remove('expanded');
                    }
                    delete section.dataset.filterExpanded;
                }
            } else if (sectionHasMatch) {
                section.style.display = '';
                domainHasMatch = true;
                if (!section.classList.contains('expanded')) {
                    section.classList.add('expanded');
                    if (details) {
                        details.classList.add('expanded');
                    }
                    section.dataset.filterExpanded = 'true';
                }
            } else {
                section.style.display = 'none';
                if (section.dataset.filterExpanded === 'true') {
                    section.classList.remove('expanded');
                    if (details) {
                        details.classList.remove('expanded');
                    }
                }
                delete section.dataset.filterExpanded;
            }
        });

        domain.style.display = (matchAll || domainHasMatch) ? '' : 'none';
    });
};

filterCards.forEach(card => {
    card.addEventListener('click', () => {
        const filter = card.getAttribute('data-filter') || 'all';
        filterCards.forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        applyDomainFilter(filter);
    });
});

const defaultFilter = document.querySelector('.summary-cards .card[data-filter=\"all\"]');
if (defaultFilter) {
    defaultFilter.classList.add('active');
    applyDomainFilter(defaultFilter.getAttribute('data-filter'));
} else {
    applyDomainFilter('all');
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
