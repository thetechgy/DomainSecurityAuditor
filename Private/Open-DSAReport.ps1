function Open-DSAReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$LogFile
    )

    $resolved = Resolve-DSAPath -Path $Path -PathType 'File'

    $opened = $false
    try {
        Start-Process -FilePath $resolved -ErrorAction Stop | Out-Null
        $opened = $true
    } catch {
        try {
            if ($IsWindows) {
                Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$resolved`"" -ErrorAction Stop | Out-Null
            } elseif ($IsMacOS) {
                Start-Process -FilePath 'open' -ArgumentList "`"$resolved`"" -ErrorAction Stop | Out-Null
            } else {
                Start-Process -FilePath 'xdg-open' -ArgumentList "`"$resolved`"" -ErrorAction Stop | Out-Null
            }
            $opened = $true
        } catch {
            if ($LogFile) {
                Write-DSALog -Message "Failed to launch report viewer: $($_.Exception.Message)" -LogFile $LogFile -Level 'WARN'
            }
        }
    }

    if ($opened -and $LogFile) {
        Write-DSALog -Message "Opened compliance report '$resolved'." -LogFile $LogFile -Level 'INFO'
    }
}
