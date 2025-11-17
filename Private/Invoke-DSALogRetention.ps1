function Invoke-DSALogRetention {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$RetentionCount = 30
    )

    if (-not (Test-Path -Path $LogDirectory)) {
        return
    }

    $logFiles = @(Get-ChildItem -Path $LogDirectory -Filter '*.log' -File | Sort-Object -Property LastWriteTime -Descending)
    if ($logFiles.Count -le $RetentionCount -or $logFiles.Count -eq 0) {
        return
    }

    $logsToRemove = $logFiles[$RetentionCount..($logFiles.Count - 1)]
    foreach ($log in $logsToRemove) {
        try {
            Remove-Item -Path $log.FullName -Force -ErrorAction Stop
        } catch {
            Write-Warning -Message "Failed to remove log '$($log.Name)': $($_.Exception.Message)"
        }
    }
}
