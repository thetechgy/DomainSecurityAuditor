function Get-DSADkimSelectorsFromRecord {
    <#
    .SYNOPSIS
        Extract DKIM selectors from a CSV or object record.
    .DESCRIPTION
        Normalizes selector values into a trimmed string array, handling collection and delimited string inputs.
        Supports both comma and semicolon delimiters for flexible CSV compatibility.
    .PARAMETER Record
        Input record containing DKIM selector metadata (expects DkimSelectors or DKIMSelectors property).
    .OUTPUTS
        System.String[] - Array of trimmed selector names.
    .EXAMPLE
        $selectors = Get-DSADkimSelectorsFromRecord -Record $csvRecord
        Returns an array of DKIM selector names extracted from the record.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        $Record
    )

    $dkimSelectorProperty = $Record.PSObject.Properties | Where-Object { $_.Name -in @('DkimSelectors', 'DKIMSelectors') } | Select-Object -First 1
    if (-not $dkimSelectorProperty) {
        return [string[]]@()
    }

    $rawSelectors = $dkimSelectorProperty.Value
    if ($rawSelectors -is [System.Collections.IEnumerable] -and -not ($rawSelectors -is [string])) {
        return [string[]]@($rawSelectors | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $selectorString = "$rawSelectors".Trim()
    if ([string]::IsNullOrWhiteSpace($selectorString)) {
        return [string[]]@()
    }

    return [string[]]@($selectorString -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
