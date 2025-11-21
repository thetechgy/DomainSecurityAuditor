function Import-DSABaselineConfig {
<#
.SYNOPSIS
    Imports a baseline configuration from a .psd1 file.
.DESCRIPTION
    Reads the specified PowerShell data file and returns its contents as a hashtable.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $resolvedPath = Resolve-DSAPath -Path $Path -PathType 'File'
    $extension = [System.IO.Path]::GetExtension($resolvedPath)
    if ($extension.ToLowerInvariant() -ne '.psd1') {
        throw "Unsupported baseline profile extension '$extension'. Provide a .psd1 file."
    }

    return Import-PowerShellDataFile -Path $resolvedPath -ErrorAction Stop
}
