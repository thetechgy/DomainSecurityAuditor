function Invoke-DomainDetective {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    return [pscustomobject]@{
        Domain               = $Domain
        Classification       = 'SendingAndReceiving'
        MXRecords            = @('mx1.stubbed.example')
        SPFRecord            = 'v=spf1 include:_spf.stubbed.example -all'
        DKIMSelectors        = @('selector1')
        DMARCRecord          = 'v=DMARC1; p=reject'
        MTASTSMode           = 'enforce'
        MTASTSTtl            = 86400
        TLSRPT               = 'v=TLSRPTv1; rua=mailto:tls@stubbed.example'
        SPFRecordTTL         = 3600
        DMARCRecordTTL       = 3600
        TLSRPTTtl            = 86400
    }
}
