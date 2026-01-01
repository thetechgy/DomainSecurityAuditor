<#
.SYNOPSIS
    Default profile configuration.
.DESCRIPTION
    Fallback profile when classification cannot be determined.
    Includes core email authentication checks.
#>
@{
    Name           = 'Default'
    Description    = 'Fallback profile when classification cannot be determined.'
    Classification = 'Default'

    # Tags to include (tests with these tags will run)
    IncludeTags    = @('SPF', 'DMARC', 'TLS-RPT')

    # Tags to exclude (tests with these tags will be skipped)
    ExcludeTags    = @('Parked')
}
