<#
.SYNOPSIS
    Calculate status distribution for a collection of baseline checks.
.DESCRIPTION
    Tallies pass, warning, and fail counts along with total checks and DKIM-specific totals.
.PARAMETER Checks
    Collection of check result objects.
#>
function Get-DSAStatusCounts {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [object[]]$Checks = @()
    )

    $statusCounts = @{
        Fail    = 0
        Warning = 0
        Pass    = 0
    }
    $totalCount = 0
    $dkimCount = 0

    foreach ($check in $Checks) {
        if (-not $check) {
            continue
        }

        $totalCount++
        if ($check.Area -eq 'DKIM') {
            $dkimCount++
        }

        switch ($check.Status) {
            'Fail' { $statusCounts.Fail++ }
            'Warning' { $statusCounts.Warning++ }
            'Pass' { $statusCounts.Pass++ }
        }
    }

    return [pscustomobject]@{
        Total     = $totalCount
        DKIMTotal = $dkimCount
        Fail      = $statusCounts.Fail
        Warning   = $statusCounts.Warning
        Pass      = $statusCounts.Pass
    }
}

<#
.SYNOPSIS
    Derive an overall status from individual check results.
.DESCRIPTION
    Returns Fail when any check fails, Warning when any warn remains, or Pass otherwise. Special handling keeps all-DKIM sets consistent.
.PARAMETER Checks
    Collection of check result objects.
#>
function Get-DSAOverallStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [object[]]$Checks = @()
    )

    $counts = Get-DSAStatusCounts -Checks $Checks

    if ($counts.Total -gt 0 -and $counts.DKIMTotal -eq $counts.Total) {
        if ($counts.Fail -eq $counts.Total) { return 'Fail' }
        if ($counts.Warning -eq $counts.Total) { return 'Warning' }
        if ($counts.Pass -eq $counts.Total) { return 'Pass' }
    }

    if ($counts.Fail -gt 0) { return 'Fail' }
    if ($counts.Warning -gt 0) { return 'Warning' }
    return 'Pass'
}

function Get-DSAColumnWidths {
    <#
    .SYNOPSIS
        Calculate maximum column widths for console output in a single pass.
    .DESCRIPTION
        Iterates through summary objects once, calculating the maximum string length
        for each specified property. Returns a hashtable of property names to widths.
    .PARAMETER Summaries
        Collection of summary objects to measure.
    .PARAMETER Properties
        Array of property names to calculate widths for.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [object[]]$Summaries = @(),

        [Parameter(Mandatory = $true)]
        [string[]]$Properties
    )

    $widths = @{}
    foreach ($prop in $Properties) {
        $widths[$prop] = 1
    }

    if (-not $Summaries -or $Summaries.Count -eq 0) {
        return $widths
    }

    foreach ($summary in $Summaries) {
        if (-not $summary) {
            continue
        }
        foreach ($prop in $Properties) {
            if ($summary.PSObject.Properties.Name -contains $prop) {
                $len = $summary.$prop.ToString().Length
                if ($len -gt $widths[$prop]) {
                    $widths[$prop] = $len
                }
            }
        }
    }

    return $widths
}

<#
.SYNOPSIS
    Get consolidated status metadata for a given status.
.DESCRIPTION
    Returns a hashtable containing CSS class name, filter token, and icon for the status.
    This is the single source of truth for status-related display properties.
.PARAMETER Status
    Status text to resolve (Pass, Fail, Warning, or other).
.OUTPUTS
    Hashtable with Class, Filter, and Icon keys.
#>
function Get-DSAStatusMetadata {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return @{ Class = 'info'; Filter = 'info'; Icon = 'ℹ' }
    }

    switch ($Status.ToLowerInvariant()) {
        'pass'    { return @{ Class = 'passed'; Filter = 'pass'; Icon = '✔' } }
        'fail'    { return @{ Class = 'failed'; Filter = 'fail'; Icon = '✖' } }
        'warning' { return @{ Class = 'warning'; Filter = 'warning'; Icon = '!' } }
        default   { return @{ Class = 'info'; Filter = 'info'; Icon = 'ℹ' } }
    }
}

<#
.SYNOPSIS
    Map a status to its CSS class name.
.DESCRIPTION
    Normalizes pass/fail/warning statuses to class tokens used in the HTML report.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAStatusClassName {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Class
}

<#
.SYNOPSIS
    Map a status to a simple icon.
.DESCRIPTION
    Returns Unicode characters representing pass, fail, warning, or info for report display.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAStatusIcon {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Icon
}

<#
.SYNOPSIS
    Normalize status values for filtering.
.DESCRIPTION
    Returns canonical filter tokens used to show/hide tests in the report.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAFilterStatus {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Filter
}
