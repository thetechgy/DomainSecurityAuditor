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
        }
        catch {
            $dnsEndpointObject = $DNSEndpoint
            if ($LogFile) {
                Write-DSALog -Message ("DNS endpoint '{0}' is not a known DnsClientX.DnsEndpoint value; passing as string." -f $DNSEndpoint) -LogFile $LogFile -Level 'WARN'
            }
        }
    }

    $commonParams = @{
        DomainName  = $Domain
        ErrorAction = 'Stop'
        WarningAction = 'SilentlyContinue'
    }
    if ($dnsEndpointObject) {
        $commonParams['DnsEndpoint'] = $dnsEndpointObject
    }

    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $spf = Test-DDEmailSpfRecord @commonParams
    }
    catch {
        $null = $errors.Add("SPF lookup failed for '$Domain': $($_.Exception.Message)")
    }

    $dkimParams = $commonParams.Clone()
    if ($PSBoundParameters.ContainsKey('DkimSelector')) {
        $dkimParams['Selectors'] = $DkimSelector
    }
    try {
        $dkim = Test-DDEmailDkimRecord @dkimParams
    }
    catch {
        $null = $errors.Add("DKIM lookup failed for '$Domain': $($_.Exception.Message)")
    }

    try {
        $dmarc = Test-DDEmailDmarcRecord @commonParams
    }
    catch {
        $null = $errors.Add("DMARC lookup failed for '$Domain': $($_.Exception.Message)")
    }

    try {
        $mx = Test-DDDnsMxRecord @commonParams
    }
    catch {
        $null = $errors.Add("MX lookup failed for '$Domain': $($_.Exception.Message)")
    }

    try {
        $tlsRpt = Test-DDEmailTlsRptRecord @commonParams
    }
    catch {
        $null = $errors.Add("TLS-RPT lookup failed for '$Domain': $($_.Exception.Message)")
    }

    try {
        $classification = Test-DDMailDomainClassification @commonParams
    }
    catch {
        $null = $errors.Add("Classification lookup failed for '$Domain': $($_.Exception.Message)")
    }

    $mtastsHealth = $null
    try {
        $mtastsParams = $commonParams.Clone()
        $mtastsParams['HealthCheckType'] = @('MTASTS')
        $mtastsHealth = Test-DDDomainOverallHealth @mtastsParams
    }
    catch {
        $null = $errors.Add("MTA-STS lookup failed for '$Domain': $($_.Exception.Message)")
    }

    if ($errors.Count -gt 0) {
        if ($LogFile) {
            foreach ($err in $errors) {
                Write-DSALog -Message $err -LogFile $LogFile -Level 'WARN'
            }
        }
        throw "DomainDetective evidence collection failed for '$Domain': $($errors -join '; ')"
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
            (($_.KeyLength -as [int]) -lt $script:DSAMinDkimKeyLength)
        }
    ).Count
    $dkimTtls = @($dkimFound | ForEach-Object { Get-DSATtlValue -InputObject $_ } | Where-Object { $_ })
    $dkimMinTtl = if ($dkimTtls) { ($dkimTtls | Measure-Object -Minimum).Minimum } else { $null }

    $mtastsAnalysis = $mtastsHealth.Raw.MTASTSAnalysis
    $mxMinimumTtl = Get-DSATtlValue -InputObject $mx -PropertyName 'MxRecordTtl'
    $spfTtl = Get-DSATtlValue -InputObject $spf
    $dmarcTtl = Get-DSATtlValue -InputObject $dmarc
    $mtastsTtl = Get-DSATtlValue -InputObject $mtastsAnalysis
    $tlsRptTtl = Get-DSATtlValue -InputObject $tlsRpt

    $records = [pscustomobject]@{
        MX                    = $mx.MxRecords
        MXRecordCount         = @($mx.MxRecords).Count
        MXHasNull             = $mx.HasNullMx
        MXMinimumTtl          = $mxMinimumTtl

        SPFRecord             = $spfRecord
        SPFRecords            = $spfRecords
        SPFRecordCount        = $spfCount
        SPFLookupCount        = $spf.DnsLookupsCount
        SPFTerminalMechanism  = $spfRaw.AllMechanism
        SPFHasPtrMechanism    = [bool]$spfRaw.HasPtrType
        SPFRecordLength       = if ($spfRecord) { $spfRecord.Length } else { 0 }
        SPFTtl                = $spfTtl
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
        DMARCTtl              = $dmarcTtl

        MTASTSRecordPresent   = [bool]$mtastsAnalysis.DnsRecordPresent
        MTASTSPolicyValid     = [bool]$mtastsAnalysis.PolicyValid
        MTASTSMode            = $mtastsAnalysis.Mode
        MTASTSTtl             = $mtastsTtl

        TLSRPTRecordPresent   = [bool]$tlsRpt.TlsRptRecordExists
        TLSRPTAddresses       = @($tlsRpt.MailtoRua + $tlsRpt.HttpRua)
        TLSRPTTtl             = $tlsRptTtl
    }

    Write-Verbose -Message "Collected DomainDetective evidence for '$Domain'."
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classification.Classification -Records $records
}
