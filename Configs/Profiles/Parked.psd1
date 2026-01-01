<#
.SYNOPSIS
    Profile configuration for Parked domains.
.DESCRIPTION
    Domains not actively sending or receiving mail.
    Includes parked-specific checks (null MX, strict SPF, reject DMARC).
#>
@{
    Name           = 'Parked'
    Description    = 'Domains not actively sending or receiving mail.'
    Classification = 'Parked'

    # Tags to include (tests with these tags will run)
    # Note: Parked domains run all checks including parked-specific ones
    IncludeTags    = @('MX', 'SPF', 'DKIM', 'DMARC', 'MTA-STS', 'TLS-RPT', 'Parked')

    # Tags to exclude (tests with these tags will be skipped)
    ExcludeTags    = @()
}
