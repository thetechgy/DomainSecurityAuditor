function New-DSADomainEvidenceObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Classification,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Records
    )

    return [pscustomobject]@{
        Domain         = $Domain
        Classification = $Classification
        Records        = $Records
    }
}

function Get-DSADryRunRecords {
    $selectorDetails = @(
        [pscustomobject]@{
            Name      = 'selector1'
            KeyLength = 2048
            IsValid   = $true
            TTL       = 3600
        },
        [pscustomobject]@{
            Name      = 'selector2'
            KeyLength = 2048
            IsValid   = $true
            TTL       = 3600
        }
    )

    return [pscustomobject]@{
        MX                    = @('mx1.contoso.example', 'mx2.contoso.example')
        MXRecordCount         = 2
        MXHasNull             = $false
        MXMinimumTtl          = 3600

        SPFRecord             = 'v=spf1 include:_spf.contoso.example -all'
        SPFRecords            = @('v=spf1 include:_spf.contoso.example -all')
        SPFRecordCount        = 1
        SPFLookupCount        = 2
        SPFTerminalMechanism  = '-all'
        SPFHasPtrMechanism    = $false
        SPFRecordLength       = 43
        SPFTtl                = 3600
        SPFIncludes           = @('_spf.contoso.example')
        SPFWildcardRecord     = 'v=spf1 -all'
        SPFWildcardConfigured = $true
        SPFUnsafeMechanisms   = @()

        DKIMSelectors         = @('selector1', 'selector2')
        DKIMSelectorDetails   = $selectorDetails
        DKIMMinKeyLength      = 2048
        DKIMWeakSelectors     = 0
        DKIMMinimumTtl        = 3600

        DMARCRecord           = 'v=DMARC1; p=reject; rua=mailto:dmarc@contoso.example'
        DMARCPolicy           = 'reject'
        DMARCRuaAddresses     = @('dmarc@contoso.example')
        DMARCRufAddresses     = @()
        DMARCTtl              = 3600

        MTASTSRecordPresent   = $true
        MTASTSPolicyValid     = $true
        MTASTSMode            = 'enforce'
        MTASTSTtl             = 86400

        TLSRPTRecordPresent   = $true
        TLSRPTAddresses       = @('tls-rpt@contoso.example')
        TLSRPTTtl             = 86400
    }
}
