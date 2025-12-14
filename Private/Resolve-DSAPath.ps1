<#
.SYNOPSIS
    Resolve and optionally create module paths with validation.
.DESCRIPTION
    Normalizes paths, enforces type constraints, creates directories/files when requested, and guards against overly long paths.
.PARAMETER Path
    Path to resolve.
.PARAMETER PathType
    Expected item type: Directory or File.
.PARAMETER EnsureExists
    Create the path if it does not already exist.
#>
function Resolve-DSAPath {
    [CmdletBinding()]
    [OutputType([string])]
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
            }
            else {
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

    # Windows MAX_PATH is 260 characters; reserve headroom for child items (reports, transcripts) created under this path.
    $maxPathLength = 220
    if ($expandedPath.Length -gt $maxPathLength) {
        throw "Resolved path '$expandedPath' exceeds the $maxPathLength-character limit."
    }

    return $expandedPath
}
