function Invoke-ScriptAnalyzer {
    <#
    .SYNOPSIS
        Stubbed ScriptAnalyzer invocation for tests.
    .DESCRIPTION
        Returns an empty result set while exercising the same parameter surface as the real cmdlet.
    .PARAMETER Path
        Path passed through from Invoke-ScriptAnalyzer callers.
    .PARAMETER Settings
        Optional settings file forwarded from the caller.
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$Path,

        [Parameter()]
        [string]$Settings
    )

    process {
        return @()
    }
}
