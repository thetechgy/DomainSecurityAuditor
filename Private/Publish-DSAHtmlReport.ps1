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
    $null = $builder.AppendLine(('      <div class="meta">Domains evaluated: {0}</div>' -f $summary.DomainCount))
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
        $null = $Builder.AppendLine(("    <section class=""domain-results status-{0}"" data-status=""{0}"">" -f $statusAttr))
        $null = $Builder.AppendLine('      <div class="domain-header">')
        $null = $Builder.AppendLine('        <div class="domain-title">')
        $null = $Builder.AppendLine(("          <div class='domain-name'>{0}</div>" -f (ConvertTo-DSAHtml $profile.Domain)))
        $null = $Builder.AppendLine(("          <span class='domain-status {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $profile.OverallStatus)))
        $null = $Builder.AppendLine('        </div>')
        $null = $Builder.AppendLine(("        <div class='domain-meta'>Classification: {0} • Detected: {1}</div>" -f (ConvertTo-DSAHtml $profile.Classification), (ConvertTo-DSAHtml $profile.OriginalClassification)))
        $null = $Builder.AppendLine('      </div>')

        $groupedChecks = $profile.Checks | Group-Object -Property Area
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

    $areaStatus = Get-DSAAreaStatus -Checks $Group.Group
    $statusClass = Get-DSAStatusClassName -Status $areaStatus
    $checkCount = ($Group.Group | Measure-Object).Count
    $sectionClass = if ($areaStatus -eq 'Pass') { 'protocol-section' } else { 'protocol-section expanded' }
    $detailsClass = if ($areaStatus -eq 'Pass') { 'protocol-details' } else { 'protocol-details expanded' }
    $checkLabel = if ($checkCount -eq 1) { '1 check' } else { ('{0} checks' -f $checkCount) }

    $null = $Builder.AppendLine(("      <div class=""{0}"">" -f $sectionClass))
    $null = $Builder.AppendLine('        <div class="protocol-header">')
    $null = $Builder.AppendLine(("          <div class='protocol-name'>{0}</div>" -f (ConvertTo-DSAHtml $Group.Name)))
    $null = $Builder.AppendLine('          <div class="protocol-status">')
    $null = $Builder.AppendLine(("            <span class='status-badge {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $areaStatus)))
    $null = $Builder.AppendLine(("            <span class='protocol-count'>{0}</span>" -f $checkLabel))
    $null = $Builder.AppendLine('          </div>')
    $null = $Builder.AppendLine('        </div>')
    $null = $Builder.AppendLine(("        <div class=""{0}"">" -f $detailsClass))

    foreach ($check in $Group.Group) {
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

    $statusClass = Get-DSAStatusClassName -Status $Check.Status
    $null = $Builder.AppendLine('          <div class="test-result">')
    $null = $Builder.AppendLine('            <div class="test-header">')
    $null = $Builder.AppendLine(("              <div class='status-dot {0}'></div>" -f $statusClass))
    $null = $Builder.AppendLine('              <div>')
    $null = $Builder.AppendLine(("                <div class='test-name'>{0}</div>" -f (ConvertTo-DSAHtml $Check.Id)))
    $null = $Builder.AppendLine(("                <span class='status-pill {0}'>{1}</span>" -f $statusClass, (ConvertTo-DSAHtml $Check.Status)))
    $null = $Builder.AppendLine('              </div>')
    $null = $Builder.AppendLine('            </div>')

    $null = $Builder.AppendLine(('            <div class="test-line"><strong>Expectation:</strong> {0}</div>' -f (ConvertTo-DSAHtml $Check.Expectation)))
    $null = $Builder.AppendLine(('            <div class="test-line"><strong>Actual:</strong> {0}</div>' -f (ConvertTo-DSAValueHtml $Check.Actual)))
    if ($Check.Remediation) {
        $null = $Builder.AppendLine(('            <div class="test-line"><strong>Remediation:</strong> {0}</div>' -f (ConvertTo-DSAHtml $Check.Remediation)))
    }
    if ($Check.References -and $Check.References.Count -gt 0) {
        $references = $Check.References | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($references) {
            $null = $Builder.AppendLine('            <div class="test-line"><strong>References:</strong>')
            $null = $Builder.AppendLine('              <ul class="references-list">')
            foreach ($ref in $references) {
                $null = $Builder.AppendLine(("                <li>{0}</li>" -f (ConvertTo-DSAReferenceHtml $ref)))
            }
            $null = $Builder.AppendLine('              </ul>')
            $null = $Builder.AppendLine('            </div>')
        }
    }

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

    $totalChecks = 0
    $warningChecks = 0
    foreach ($profile in $profileList) {
        $checks = @($profile.Checks)
        $totalChecks += ($checks | Measure-Object).Count
        $warningChecks += ($checks | Where-Object { $_.Status -eq 'Warning' } | Measure-Object).Count
    }

    $cards = @(
        [pscustomobject]@{ Label = 'Domains Passed'; Value = $passed; Description = 'Full compliance achieved.'; Style = 'Pass'; Filter = 'pass' }
        [pscustomobject]@{ Label = 'Domains Failed'; Value = $failed; Description = 'Critical remediation required.'; Style = 'Fail'; Filter = 'fail' }
        [pscustomobject]@{ Label = 'Domains Warning'; Value = $warningDomains; Description = 'Action recommended.'; Style = 'Warning'; Filter = 'warning' }
        [pscustomobject]@{ Label = 'Total Checks'; Value = $totalChecks; Description = 'Checks executed across all domains.'; Style = 'Info'; Filter = 'all' }
        [pscustomobject]@{ Label = 'Total Warnings'; Value = $warningChecks; Description = 'Checks flagged with warnings.'; Style = 'Warning'; Filter = $null }
    )

    return [pscustomobject]@{
        DomainCount   = $domainCount
        Passed        = $passed
        Failed        = $failed
        Warning       = $warningDomains
        TotalChecks   = $totalChecks
        TotalWarnings = $warningChecks
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
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.card {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    transition: transform 0.2s ease;
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
.domain-header {
    background: #f8fafc;
    padding: 22px;
    border-bottom: 1px solid #e5e7eb;
}
.domain-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
}
.domain-name { font-size: 1.5rem; font-weight: 600; color: #374151; }
.domain-meta { color: #6b7280; font-size: 0.95rem; }
.domain-status {
    padding: 8px 18px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.95rem;
    text-transform: uppercase;
}
.domain-status.passed { background-color: #d1fae5; color: #065f46; }
.domain-status.failed { background-color: #fee2e2; color: #991b1b; }
.domain-status.warning { background-color: #fef3c7; color: #92400e; }
.protocol-section { border-bottom: 1px solid #e5e7eb; }
.protocol-header {
    background: #f9fafb;
    padding: 18px 24px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.protocol-header:hover { background: #f3f4f6; }
.protocol-name { font-weight: 600; font-size: 1.05rem; color: #374151; }
.protocol-status { display: flex; align-items: center; gap: 12px; font-size: 0.9rem; color: #6b7280; }
.protocol-count { font-weight: 500; color: #4b5563; }
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
.protocol-details { display: none; }
.protocol-details.expanded { display: block; }
.test-result {
    padding: 18px 24px;
    border-top: 1px solid #f3f4f6;
}
.test-header { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 10px; }
.status-dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    margin-top: 6px;
}
.status-dot.passed { background-color: #10b981; }
.status-dot.failed { background-color: #ef4444; }
.status-dot.warning { background-color: #f59e0b; }
.status-dot.info { background-color: #3b82f6; }
.test-name { font-weight: 600; color: #111827; font-size: 1rem; }
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
.test-line { margin-bottom: 6px; color: #374151; }
.test-line ul { margin: 6px 0 0 20px; }
.references-list a { color: #2563eb; text-decoration: none; }
.references-list a:hover { text-decoration: underline; }
.value-none { color: #9ca3af; font-style: italic; }
.value-positive { color: #065f46; font-weight: 600; }
.value-negative { color: #991b1b; font-weight: 600; }
.protocol-header::after {
    content: '▾';
    font-size: 1rem;
    color: #9ca3af;
    transition: transform 0.2s ease;
}
.protocol-section.expanded .protocol-header::after {
    transform: rotate(180deg);
}
@media (max-width: 640px) {
    .domain-title { flex-direction: column; align-items: flex-start; gap: 10px; }
    .summary-cards { grid-template-columns: 1fr; }
}
"@
}

function Get-DSAReportScript {
@"
const protocolSections = document.querySelectorAll('.protocol-section');
protocolSections.forEach((section) => {
    const header = section.querySelector('.protocol-header');
    const details = section.querySelector('.protocol-details');
    header.addEventListener('click', () => {
        section.classList.toggle('expanded');
        details.classList.toggle('expanded');
    });
});

const filterCards = document.querySelectorAll('.summary-cards .card[data-filter]');
const domainSections = document.querySelectorAll('.domain-results');

filterCards.forEach(card => {
    card.addEventListener('click', () => {
        const filter = card.getAttribute('data-filter');
        filterCards.forEach(c => c.classList.remove('active'));
        card.classList.add('active');

        domainSections.forEach(section => {
            const status = section.getAttribute('data-status');
            if (!filter || filter === 'all' || status === filter) {
                section.style.display = '';
            } else {
                section.style.display = 'none';
            }
        });
    });
});
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

    if ($Reference -match '^(https?://\S+)$') {
        $url = $matches[1]
        $display = ConvertTo-DSAHtml -Value $Reference
        return ("<a href=""{0}"" target=""_blank"" rel=""noopener"">{1}</a>" -f $url, $display)
    }

    return ConvertTo-DSAHtml -Value $Reference
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
