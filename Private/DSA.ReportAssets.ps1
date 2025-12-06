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

function Get-DSAKnownReferenceLink {
    param (
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $null
    }

    $trimmed = $Reference.Trim()

    if (-not $script:DSAKnownReferenceLinks -or ($script:DSAKnownReferenceLinks -is [hashtable] -and $script:DSAKnownReferenceLinks.Count -eq 0)) {
        $referenceFile = Join-Path -Path $script:ModuleRoot -ChildPath 'Configs/ReferenceLinks.psd1'
        if (Test-Path -Path $referenceFile) {
            $script:DSAKnownReferenceLinks = Import-PowerShellDataFile -Path $referenceFile
        } else {
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

function Get-DSAStatusClassName {
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return 'info'
    }

    switch ($Status.ToLowerInvariant()) {
        'pass' { return 'passed' }
        'fail' { return 'failed' }
        'warning' { return 'warning' }
        default { return 'info' }
    }
}

function Get-DSAStatusIcon {
    param (
        [string]$Status
    )

    switch ($Status.ToLowerInvariant()) {
        'pass' { return '✔' }
        'fail' { return '✖' }
        'warning' { return '!' }
        default { return 'ℹ' }
    }
}

function Get-DSAFilterStatus {
    param (
        [string]$Status
    )

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return 'info'
    }

    switch ($Status.ToLowerInvariant()) {
        'pass' { return 'pass' }
        'fail' { return 'fail' }
        'warning' { return 'warning' }
        default { return 'info' }
    }
}
