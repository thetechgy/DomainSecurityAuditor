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

function Test-DDDomainOverallHealth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [string[]]$HealthCheckType,
        [string[]]$DkimSelectors,
        [string]$DnsEndpoint,
        [switch]$CollectAuthoritativeTtls
    )

    $dnsTtlAnalysis = $null
    if ($CollectAuthoritativeTtls) {
        $dnsTtlAnalysis = [pscustomobject]@{
            AuthoritativeMxTtls       = @(3600)
            AuthoritativeSpfTxtTtls   = @(3600)
            AuthoritativeDmarcTxtTtls = @(3600)
            AuthoritativeMtastsTxtTtls = @(86400)
            AuthoritativeTlsRptTxtTtls = @(86400)
            AuthoritativeDkimTxtTtls  = @{
                'selector1._domainkey.example.com' = @(3600)
            }
        }
    }

    return [pscustomobject]@{
        Raw = [pscustomobject]@{
            Summary        = [pscustomobject]@{
                HasMxRecord    = $true
                HasSpfRecord   = $true
                HasDmarcRecord = $true
            }
            MXAnalysis     = [pscustomobject]@{ MxRecords = @('mx1.stubbed.example'); HasNullMx = $false; MinMxTtl = 3600 }
            SpfAnalysis    = [pscustomobject]@{
                SpfRecord        = 'v=spf1 -all'
                SpfRecords       = @('v=spf1 -all')
                DnsLookupsCount  = 1
                AllMechanism     = '-all'
                HasPtrType       = $false
                DnsRecordTtl     = 3600
            }
            DKIMAnalysis   = [pscustomobject]@{
                AnalysisResults = @{
                    'selector1' = [pscustomobject]@{ KeyLength = 2048; Ttl = 3600; IsValid = $true }
                }
            }
            DmarcAnalysis  = [pscustomobject]@{
                DmarcRecord  = 'v=DMARC1; p=reject'
                Policy       = 'reject'
                MailtoRua    = @('mailto:rua@example.com')
                HttpRua      = @()
                MailtoRuf    = @()
                HttpRuf      = @()
                DnsRecordTtl = 3600
            }
            MTASTSAnalysis = [pscustomobject]@{ DnsRecordPresent = $true; PolicyValid = $true; Mode = 'enforce'; DnsRecordTtl = 86400 }
            TLSRPTAnalysis = [pscustomobject]@{
                TlsRptRecordExists = $true
                MailtoRua          = @('mailto:tls@example.com')
                HttpRua            = @()
                DnsRecordTtl       = 86400
            }
            DnsTtlAnalysis = $dnsTtlAnalysis
        }
    }
}
