function Resolve-DSAClassificationOverride {
    <#
.SYNOPSIS
    Validates and normalizes user-supplied classification overrides.
.DESCRIPTION
    Ensures only supported baseline classification keys are accepted when overrides
    are supplied via CSV metadata or direct parameters, returning the canonical value.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Value,

        [Parameter()]
        [string]$SourceDescription = 'classification override'
    )

    $validValues = @('SendingOnly', 'ReceivingOnly', 'SendingAndReceiving', 'Parked')
    $allowed = [string]::Join(', ', $validValues)
    $sourceNote = if (-not [string]::IsNullOrWhiteSpace($SourceDescription)) {
        " ($SourceDescription)"
    }
    else {
        ''
    }

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Classification override cannot be empty$sourceNote. Allowed values: $allowed."
    }

    $normalized = $Value.Trim()
    foreach ($entry in $validValues) {
        if ([string]::Equals($normalized, $entry, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $entry
        }
    }

    throw "Classification override '$normalized'$sourceNote is invalid. Allowed values: $allowed."
}

<#
.SYNOPSIS
    Normalize a classification string to its canonical key.
.DESCRIPTION
    Strips non-letters and returns the standard baseline classification key when recognized.
.PARAMETER Classification
    Classification value to normalize.
#>
function Get-DSAClassificationKey {
    <#
.SYNOPSIS
    Normalizes a classification string to its canonical key form.
.DESCRIPTION
    Converts classification values like 'sending-only' or 'SendingOnly' to the
    standard key format used in baseline profiles.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [string]$Classification
    )

    if ([string]::IsNullOrWhiteSpace($Classification)) {
        return $null
    }

    $normalized = ($Classification -replace '[^a-zA-Z]', '').ToLowerInvariant()
    switch ($normalized) {
        'sendingonly' { return 'SendingOnly' }
        'receivingonly' { return 'ReceivingOnly' }
        'sendingandreceiving' { return 'SendingAndReceiving' }
        'parked' { return 'Parked' }
        default { return $Classification }
    }
}
