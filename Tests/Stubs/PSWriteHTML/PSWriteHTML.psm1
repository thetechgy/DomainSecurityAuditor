function New-HTML {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $Content
    )

    return $Content
}

function Out-HTMLView {
    [CmdletBinding()]
    param (
        $InputObject
    )

    return $InputObject
}
