function Get-DSADomainEvidence {
<#
.SYNOPSIS
    Collects domain security evidence using DomainDetective per-protocol cmdlets.
.DESCRIPTION
    Invokes DomainDetective SPF, DKIM, DMARC, MX, TLS-RPT, MTA-STS, and classification checks,
    returning a normalized object for baseline evaluation without custom parsing/flattening.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [string]$LogFile,

        [Alias('DkimSelectors')]
        [string[]]$DkimSelector,

        [string]$DNSEndpoint
    )

    Import-DSADomainDetectiveModule -LogFile $LogFile

    $dnsEndpointObject = $null
    if ($PSBoundParameters.ContainsKey('DNSEndpoint') -and -not [string]::IsNullOrWhiteSpace($DNSEndpoint)) {
        try {
            $dnsEndpointObject = [DnsClientX.DnsEndpoint]::$DNSEndpoint
        } catch {
            $dnsEndpointObject = $DNSEndpoint
            if ($LogFile) {
                Write-DSALog -Message ("Using DNS endpoint override '{0}' (fallback to string)." -f $DNSEndpoint) -LogFile $LogFile -Level 'WARN'
            }
        }
    }

    $commonParams = @{
        DomainName  = $Domain
        ErrorAction = 'Stop'
    }
    if ($dnsEndpointObject) {
        $commonParams['DnsEndpoint'] = $dnsEndpointObject
    }

    try {
        $spf = Test-DDEmailSpfRecord @commonParams
        $dkimParams = $commonParams.Clone()
        if ($PSBoundParameters.ContainsKey('DkimSelector')) {
            $dkimParams['Selectors'] = $DkimSelector
        }
        $dkim = Test-DDEmailDkimRecord @dkimParams
        $dmarc = Test-DDEmailDmarcRecord @commonParams
        $mx = Test-DDDnsMxRecord @commonParams
        $tlsRpt = Test-DDEmailTlsRptRecord @commonParams
        $classification = Test-DDMailDomainClassification @commonParams

        $mtastsParams = $commonParams.Clone()
        $mtastsParams['HealthCheckType'] = @('MTASTS')
        $mtastsHealth = Test-DDDomainOverallHealth @mtastsParams
    } catch {
        $message = "DomainDetective evidence collection failed for '$Domain': $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }

    $spfRaw = $spf.Raw
    $spfRecord = $spf.SpfRecord
    $spfRecords = $spfRaw.SpfRecords
    $spfCount = if ($spfRecords) { @($spfRecords).Count } elseif ($spfRecord) { 1 } else { 0 }
    $spfUnsafe = @($spf.UnknownMechanisms)
    if ($spfRaw.HasPtrType) { $spfUnsafe += 'ptr' }

    $dkimList = @($dkim | Where-Object { $_ })
    $dkimFound = @($dkimList | Where-Object { $_.DkimRecordExists })
    $dkimSelectors = @($dkimFound | ForEach-Object { $_.Selector })
    $dkimMinKey = $null
    if ($dkimFound) {
        $keyValues = @($dkimFound | ForEach-Object { $_.KeyLength } | Where-Object { $_ })
        if ($keyValues) {
            $dkimMinKey = ($keyValues | Measure-Object -Minimum).Minimum
        }
    }
    $dkimWeakCount = @(
        $dkimList | Where-Object {
            -not $_.DkimRecordExists -or
            -not $_.ValidPublicKey -or
            -not $_.ValidRsaKeyLength -or
            $_.WeakKey -or
            (($_.KeyLength -as [int]) -lt 1024)
        }
    ).Count
    $dkimTtls = @($dkimFound | ForEach-Object { $_.DnsRecordTtl } | Where-Object { $_ })
    $dkimMinTtl = if ($dkimTtls) { ($dkimTtls | Measure-Object -Minimum).Minimum } else { $null }

    $dmarcRaw = $dmarc.Raw
    $mtastsAnalysis = $mtastsHealth.Raw.MTASTSAnalysis

    $records = [pscustomobject]@{
        MX                    = $mx.MxRecords
        MXRecordCount         = @($mx.MxRecords).Count
        MXHasNull             = $mx.HasNullMx
        MXMinimumTtl          = $mx.MxRecordTtl

        SPFRecord             = $spfRecord
        SPFRecords            = $spfRecords
        SPFRecordCount        = $spfCount
        SPFLookupCount        = $spf.DnsLookupsCount
        SPFTerminalMechanism  = $spfRaw.AllMechanism
        SPFHasPtrMechanism    = [bool]$spfRaw.HasPtrType
        SPFRecordLength       = if ($spfRecord) { $spfRecord.Length } else { 0 }
        SPFTtl                = $spf.DnsRecordTtl
        SPFIncludes           = $spfRaw.IncludeRecords
        SPFWildcardRecord     = $null
        SPFWildcardConfigured = $false
        SPFUnsafeMechanisms   = $spfUnsafe

        DKIMSelectors         = $dkimSelectors
        DKIMSelectorDetails   = $dkimList
        DKIMMinKeyLength      = $dkimMinKey
        DKIMWeakSelectors     = $dkimWeakCount
        DKIMMinimumTtl        = $dkimMinTtl

        DMARCRecord           = $dmarc.DmarcRecord
        DMARCPolicy           = $dmarc.Policy
        DMARCRuaAddresses     = @($dmarc.MailtoRua + $dmarc.HttpRua)
        DMARCRufAddresses     = @($dmarc.MailtoRuf + $dmarc.HttpRuf)
        DMARCTtl              = $dmarc.DnsRecordTtl

        MTASTSRecordPresent   = [bool]$mtastsAnalysis.DnsRecordPresent
        MTASTSPolicyValid     = [bool]$mtastsAnalysis.PolicyValid
        MTASTSMode            = $mtastsAnalysis.Mode
        MTASTSTtl             = $mtastsAnalysis.DnsRecordTtl

        TLSRPTRecordPresent   = [bool]$tlsRpt.TlsRptRecordExists
        TLSRPTAddresses       = @($tlsRpt.MailtoRua + $tlsRpt.HttpRua)
        TLSRPTTtl             = $tlsRpt.DnsRecordTtl
    }

    Write-Verbose -Message "Collected DomainDetective evidence for '$Domain'."
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classification.Classification -Records $records
}
