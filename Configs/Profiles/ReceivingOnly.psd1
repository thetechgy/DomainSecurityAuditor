<#
.SYNOPSIS
    Profile configuration for ReceivingOnly domains.
.DESCRIPTION
    Domains that accept inbound mail but are not expected to send.
    Includes MX checks and all standard email authentication checks.
#>
@{
    Name           = 'ReceivingOnly'
    Description    = 'Domains that accept inbound mail but are not expected to send.'
    Classification = 'ReceivingOnly'

    # Tags to include (tests with these tags will run)
    IncludeTags    = @('MX', 'SPF', 'DKIM', 'DMARC', 'MTA-STS', 'TLS-RPT')

    # Tags to exclude (tests with these tags will be skipped)
    ExcludeTags    = @('Parked')
}
