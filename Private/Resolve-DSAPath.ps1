function Resolve-DSAPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Directory', 'File')]
        [string]$PathType = 'Directory',

        [switch]$EnsureExists
    )

    $invalidChars = [System.IO.Path]::GetInvalidPathChars()
    if ($Path.IndexOfAny($invalidChars) -ge 0) {
        throw "Path '$Path' contains invalid characters."
    }

    # Normalize relative components before validation
    $expandedPath = [System.IO.Path]::GetFullPath((Resolve-Path -Path $Path -ErrorAction SilentlyContinue)?.Path ?? $Path)

    if ($EnsureExists -or $PathType -eq 'Directory') {
        $itemType = if ($PathType -eq 'Directory') { 'Directory' } else { 'File' }
        if (-not (Test-Path -Path $expandedPath)) {
            if ($itemType -eq 'Directory') {
                $null = New-Item -ItemType Directory -Path $expandedPath -Force
            } else {
                $directory = Split-Path -Path $expandedPath -Parent
                if (-not (Test-Path -Path $directory)) {
                    $null = New-Item -ItemType Directory -Path $directory -Force
                }
                $null = New-Item -ItemType File -Path $expandedPath -Force
            }
        }
    }

    if (-not (Test-Path -Path $expandedPath)) {
        throw "Unable to resolve path '$Path'."
    }

    # Limit path length to leave headroom for child items within the 260-character Windows maximum
    if ($expandedPath.Length -gt 180) {
        throw "Resolved path '$expandedPath' exceeds the 180-character limit."
    }

    return $expandedPath
}
