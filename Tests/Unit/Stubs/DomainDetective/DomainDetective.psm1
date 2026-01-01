function Invoke-DomainDetective {
    <#
    .SYNOPSIS
        Test stub for the DomainDetective entry point.
    .DESCRIPTION
        Returns canned domain metadata so DomainSecurityAuditor tests can run without the real module.
    .PARAMETER Domain
        Target domain name to echo into the stubbed payload.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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
