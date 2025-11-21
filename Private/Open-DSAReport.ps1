function Open-DSAReport {
<#
.SYNOPSIS
    Opens a generated report file in the default viewer.
.DESCRIPTION
    Launches the specified report file using the system default application. Falls back to
    platform-specific commands (explorer/open/xdg-open) if the initial attempt fails.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$LogFile
    )

    $resolved = Resolve-DSAPath -Path $Path -PathType 'File'

    $opened = $false
    try {
        $null = Start-Process -FilePath $resolved -ErrorAction Stop
        $opened = $true
    } catch {
        try {
            if ($IsWindows) {
                $null = Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$resolved`"" -ErrorAction Stop
            } elseif ($IsMacOS) {
                $null = Start-Process -FilePath 'open' -ArgumentList "`"$resolved`"" -ErrorAction Stop
            } else {
                $null = Start-Process -FilePath 'xdg-open' -ArgumentList "`"$resolved`"" -ErrorAction Stop
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
