function Invoke-ScriptAnalyzer {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$Path,

        [Parameter()]
        [string]$Settings
    )

    return @()
}
