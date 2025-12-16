<#
.SYNOPSIS
    Encode a value for safe HTML display.
.DESCRIPTION
    Converts values to strings and HTML-encodes them, returning an empty string when null.
.PARAMETER Value
    Value to encode.
#>
function ConvertTo-DSAHtml {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    return [System.Net.WebUtility]::HtmlEncode($text)
}

<#
.SYNOPSIS
    Format a value with semantic HTML wrappers.
.DESCRIPTION
    Returns stylized spans for boolean and empty values, joins enumerables, and HTML-encodes other inputs.
.PARAMETER Value
    Value to format.
#>
function ConvertTo-DSAValueHtml {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return '<span class="value-none">None</span>'
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return '<span class="value-positive">Yes</span>'
        }
        return '<span class="value-negative">No</span>'
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @($Value | Where-Object { $_ })
        if ($items.Count -eq 0) {
            return '<span class="value-none">None</span>'
        }
        return ($items | ForEach-Object { ConvertTo-DSAHtml $_ }) -join ', '
    }

    return ConvertTo-DSAHtml -Value $Value
}

<#
.SYNOPSIS
    Convert a reference string to an HTML link when possible.
.DESCRIPTION
    Resolves known references or RFCs to URLs, falling back to plain text when no mapping exists.
.PARAMETER Reference
    Reference text to render.
#>
function ConvertTo-DSAReferenceHtml {
    param (
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return ''
    }

    $normalized = $Reference.Trim()
    $link = Get-DSAKnownReferenceLink -Reference $normalized
    if (-not $link -and $normalized -match '^(https?://\S+)$') {
        $link = $matches[1]
    }

    if ($link) {
        $display = ConvertTo-DSAHtml -Value $normalized
        return ("<a class=""reference-link"" href=""{0}"" target=""_blank"" rel=""noopener"">{1}</a>" -f $link, $display)
    }

    $displayText = ConvertTo-DSAHtml -Value $normalized
    return ("<span class=""reference-link reference-link--static"">{0}</span>" -f $displayText)
}

<#
.SYNOPSIS
    Resolve a known reference label to a link.
.DESCRIPTION
    Loads cached reference mappings, handles RFC section linking, and returns the associated URL or null.
.PARAMETER Reference
    Reference label to resolve.
#>
function Get-DSAKnownReferenceLink {
    param (
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $null
    }

    $trimmed = $Reference.Trim()

    if (-not $script:DSAKnownReferenceLinks -or ($script:DSAKnownReferenceLinks -is [hashtable] -and $script:DSAKnownReferenceLinks.Count -eq 0)) {
        $referenceFile = Join-Path -Path $script:ConfigRoot -ChildPath 'ReferenceLinks.psd1'
        if (Test-Path -Path $referenceFile) {
            $script:DSAKnownReferenceLinks = Import-PowerShellDataFile -Path $referenceFile
        }
        else {
            $script:DSAKnownReferenceLinks = @{}
        }
    }

    if ($trimmed -match '^RFC\s+(\d+)(?:\s+§\s*([\d\.]+))?$') {
        $rfcNumber = $matches[1]
        $section = $matches[2]
        $url = "https://www.rfc-editor.org/rfc/rfc$rfcNumber"
        if ($section) {
            $sectionFragment = $section -replace '\s+', ''
            $url = "$url#section-$sectionFragment"
        }
        return $url
    }

    if ($script:DSAKnownReferenceLinks.ContainsKey($trimmed)) {
        return $script:DSAKnownReferenceLinks[$trimmed]
    }

    return $null
}

<#
.SYNOPSIS
    Get consolidated status metadata for a given status.
.DESCRIPTION
    Returns a hashtable containing CSS class name, filter token, and icon for the status.
    This is the single source of truth for status-related display properties.
.PARAMETER Status
    Status text to resolve (Pass, Fail, Warning, or other).
.OUTPUTS
    Hashtable with Class, Filter, and Icon keys.
#>
function Get-DSAStatusMetadata {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return @{ Class = 'info'; Filter = 'info'; Icon = 'ℹ' }
    }

    switch ($Status.ToLowerInvariant()) {
        'pass'    { return @{ Class = 'passed'; Filter = 'pass'; Icon = '✔' } }
        'fail'    { return @{ Class = 'failed'; Filter = 'fail'; Icon = '✖' } }
        'warning' { return @{ Class = 'warning'; Filter = 'warning'; Icon = '!' } }
        default   { return @{ Class = 'info'; Filter = 'info'; Icon = 'ℹ' } }
    }
}

<#
.SYNOPSIS
    Map a status to its CSS class name.
.DESCRIPTION
    Normalizes pass/fail/warning statuses to class tokens used in the HTML report.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAStatusClassName {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Class
}

<#
.SYNOPSIS
    Map a status to a simple icon.
.DESCRIPTION
    Returns Unicode characters representing pass, fail, warning, or info for report display.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAStatusIcon {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Icon
}

<#
.SYNOPSIS
    Normalize status values for filtering.
.DESCRIPTION
    Returns canonical filter tokens used to show/hide tests in the report.
.PARAMETER Status
    Status text to normalize.
#>
function Get-DSAFilterStatus {
    param (
        [string]$Status
    )

    return (Get-DSAStatusMetadata -Status $Status).Filter
}

