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
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [Parameter()]
        [string]$SourceDescription = 'classification override'
    )

    $validValues = @('SendingOnly', 'ReceivingOnly', 'SendingAndReceiving', 'Parked')
    $allowed = [string]::Join(', ', $validValues)
    $sourceNote = if (-not [string]::IsNullOrWhiteSpace($SourceDescription)) {
        " ($SourceDescription)"
    } else {
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
