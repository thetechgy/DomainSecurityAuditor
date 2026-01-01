<#
.SYNOPSIS
    Profile configuration for SendingOnly domains.
.DESCRIPTION
    Domains that originate mail but do not host inbound mailboxes.
    Excludes MX receiving checks, includes all sending-related checks.
#>
@{
    Name           = 'SendingOnly'
    Description    = 'Domains that originate mail but do not host inbound mailboxes.'
    Classification = 'SendingOnly'

    # Tags to include (tests with these tags will run)
    IncludeTags    = @('SPF', 'DKIM', 'DMARC', 'MTA-STS', 'TLS-RPT')

    # Tags to exclude (tests with these tags will be skipped)
    ExcludeTags    = @('Parked')
}
