function Get-DSAStatusCounts {
    [CmdletBinding()]
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

function Get-DSAOverallStatus {
    [CmdletBinding()]
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
