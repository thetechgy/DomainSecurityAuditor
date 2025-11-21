function New-DSABaselineProfile {
<#
.SYNOPSIS
    Creates a new baseline profile file based on an existing built-in profile.
.DESCRIPTION
    Copies the specified source profile from the module's Configs directory to a new destination so that operators can
    adjust expectations without editing the module contents.
.PARAMETER Path
    Destination path for the new baseline file.
.PARAMETER SourceProfile
    Name of the built-in profile to copy. Defaults to 'Default'.
.PARAMETER Force
    Overwrite the destination file if it already exists.
.EXAMPLE
    New-DSABaselineProfile -Path '.\Baseline.MyOrg.psd1'
    Copies the default profile to Baseline.MyOrg.psd1 in the current directory.
#>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$SourceProfile = 'Default',

        [switch]$Force
    )

    $sourceInfo = Get-DSABaselineProfile -Name $SourceProfile
    if (-not $sourceInfo) {
        throw "Baseline profile '$SourceProfile' was not found."
    }

    $targetPath = [System.IO.Path]::GetFullPath($Path)
    $targetDirectory = Split-Path -Path $targetPath -Parent
    if (-not (Test-Path -Path $targetDirectory)) {
        $null = New-Item -Path $targetDirectory -ItemType Directory -Force
    }

    if ((Test-Path -Path $targetPath) -and -not $Force) {
        throw "The file '$targetPath' already exists. Use -Force to overwrite."
    }

    if ($PSCmdlet.ShouldProcess($targetPath, "Copy baseline profile '$SourceProfile'")) {
        Copy-Item -Path $sourceInfo.Path -Destination $targetPath -Force:$Force
    }

    return $targetPath
}
