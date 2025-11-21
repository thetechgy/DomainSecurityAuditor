function Import-DSABaselineConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = Resolve-DSAPath -Path $Path -PathType 'File'
    $extension = [System.IO.Path]::GetExtension($resolvedPath)

    switch ($extension.ToLowerInvariant()) {
        '.json' {
            $content = Get-Content -Path $resolvedPath -Raw -ErrorAction Stop
            return $content | ConvertFrom-Json -Depth 32 -AsHashtable
        }
        '.psd1' {
            return Import-PowerShellDataFile -Path $resolvedPath -ErrorAction Stop
        }
        default {
            throw "Unsupported baseline config extension '$extension'. Provide a .json or .psd1 file."
        }
    }
}
