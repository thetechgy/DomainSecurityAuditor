<#
.SYNOPSIS
    Profile configuration for SendingAndReceiving domains.
.DESCRIPTION
    Domains that both send and receive messages.
    Includes all email authentication and MX checks.
#>
@{
    Name           = 'SendingAndReceiving'
    Description    = 'Domains that both send and receive messages.'
    Classification = 'SendingAndReceiving'

    # Tags to include (tests with these tags will run)
    IncludeTags    = @('MX', 'SPF', 'DKIM', 'DMARC', 'MTA-STS', 'TLS-RPT')

    # Tags to exclude (tests with these tags will be skipped)
    ExcludeTags    = @('Parked')
}
