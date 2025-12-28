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

        [string]$ClassificationOverride,

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

    $health = $null
    try {
        $healthParams = $commonParams.Clone()
        $healthParams['HealthCheckType'] = @('SPF', 'DKIM', 'DMARC', 'MX', 'MTASTS', 'TLSRPT', 'TTL')
        if ($PSBoundParameters.ContainsKey('DkimSelector')) {
            $healthParams['DkimSelectors'] = $DkimSelector
        }
        $health = Test-DDDomainOverallHealth @healthParams
    }
    catch {
        $null = $errors.Add("Overall health lookup failed for '$Domain': $($_.Exception.Message)")
    }

    $classificationValue = Get-DSAClassificationFromHealth -HealthData $health
    if (-not $classificationValue -and $health -and $health.Raw) {
        $classificationValue = Get-DSAClassificationFromHealth -HealthData $health.Raw
    }

    if (-not $classificationValue) {
        try {
            $classificationLookup = Test-DDMailDomainClassification @commonParams
            if ($classificationLookup -and (Test-DSAProperty -InputObject $classificationLookup -Name 'Classification')) {
                $classificationValue = "$($classificationLookup.Classification)".Trim()
            }
        }
        catch {
            $null = $errors.Add("Classification lookup failed for '$Domain': $($_.Exception.Message)")
        }
    }

    if ($errors.Count -gt 0 -or -not $health -or -not $health.Raw) {
        if ($LogFile) {
            foreach ($err in $errors) {
                Write-DSALog -Message $err -LogFile $LogFile -Level 'WARN'
            }
        }
        $failureMessage = if ($errors.Count -gt 0) { $errors -join '; ' } else { 'DomainDetective returned no data.' }
        throw "DomainDetective evidence collection failed for '$Domain': $failureMessage"
    }

    if ($PSBoundParameters.ContainsKey('ClassificationOverride') -and -not [string]::IsNullOrWhiteSpace($ClassificationOverride)) {
        $classificationValue = "$ClassificationOverride".Trim()
        if ($LogFile) {
            Write-DSALog -Message ("Using classification override '{0}' for '{1}'." -f $classificationValue, $Domain) -LogFile $LogFile -Level 'INFO'
        }
    }
    elseif (-not $classificationValue) {
        throw "Classification unavailable for '$Domain' after DomainDetective lookups."
    }

    $rawHealth = $health.Raw
    $spf = $rawHealth.SpfAnalysis
    $dkim = $rawHealth.DKIMAnalysis
    $dmarc = $rawHealth.DmarcAnalysis
    $mx = $rawHealth.MXAnalysis
    $mtastsAnalysis = $rawHealth.MTASTSAnalysis
    $tlsRpt = $rawHealth.TLSRPTAnalysis
    $ttlAnalysis = $rawHealth.DnsTtlAnalysis
    if (-not $ttlAnalysis) {
        $ttlAnalysis = [pscustomobject]@{}
    }

    $spfRecord = $spf.SpfRecord
    $spfRecords = $spf.SpfRecords
    $spfCount = if ($spfRecords) { @($spfRecords).Count } elseif ($spfRecord) { 1 } else { 0 }
    $spfUnsafe = @($spf.UnknownMechanisms)
    if ($spf.HasPtrType) { $spfUnsafe += 'ptr' }

    $dkimResult = Get-DSADkimAnalysisResult -DkimAnalysis $dkim
    $dkimList = $dkimResult.DkimList
    $dkimFound = $dkimResult.DkimFound
    $dkimSelectors = $dkimResult.DkimSelectors
    $dkimMinKey = $dkimResult.DkimMinKey
    $dkimWeakCount = $dkimResult.DkimWeakCount

    $spfAuthoritativeValues = Get-DSAAuthoritativeTtlValues -TtlAnalysis $ttlAnalysis -PropertyName 'ServerTtlTxtSpf'
    $spfResolverTtl = Get-DSATtlValue -InputObject $spf
    $spfTtl = Resolve-DSATtl -AuthoritativeValues $spfAuthoritativeValues -ResolverTtl $spfResolverTtl -RecordLabel 'SPF' -LogFile $LogFile

    $dmarcAuthoritativeValues = Get-DSAAuthoritativeTtlValues -TtlAnalysis $ttlAnalysis -PropertyName 'ServerTtlTxtDmarc'
    $dmarcResolverTtl = Get-DSATtlValue -InputObject $dmarc
    $dmarcTtl = Resolve-DSATtl -AuthoritativeValues $dmarcAuthoritativeValues -ResolverTtl $dmarcResolverTtl -RecordLabel 'DMARC' -LogFile $LogFile

    $dkimAuthoritativeValues = [System.Collections.Generic.List[object]]::new()
    if ($ttlAnalysis.ServerTtlTxtPerName) {
        foreach ($perNameMap in $ttlAnalysis.ServerTtlTxtPerName.Values) {
            if ($perNameMap) {
                foreach ($val in ($perNameMap.Values | Where-Object { $_ })) {
                    $null = $dkimAuthoritativeValues.Add($val)
                }
            }
        }
    }
    $dkimResolverTtls = @($dkimFound | ForEach-Object { Get-DSATtlValue -InputObject $_ } | Where-Object { $_ })
    $dkimResolverMin = if ($dkimResolverTtls) { ($dkimResolverTtls | Measure-Object -Minimum).Minimum } else { $null }
    $dkimMinTtl = Resolve-DSATtl -AuthoritativeValues $dkimAuthoritativeValues -ResolverTtl $dkimResolverMin -RecordLabel 'DKIM' -LogFile $LogFile

    $mtastsAuthoritativeValues = Get-DSAAuthoritativeTtlValues -TtlAnalysis $ttlAnalysis -PropertyName 'ServerTtlTxtMtasts'
    $mtastsResolverTtl = Get-DSATtlValue -InputObject $mtastsAnalysis
    $mtastsTtl = Resolve-DSATtl -AuthoritativeValues $mtastsAuthoritativeValues -ResolverTtl $mtastsResolverTtl -RecordLabel 'MTA-STS' -LogFile $LogFile

    $tlsRptAuthoritativeValues = Get-DSAAuthoritativeTtlValues -TtlAnalysis $ttlAnalysis -PropertyName 'ServerTtlTxtTlsRpt'
    $tlsRptResolverTtl = Get-DSATtlValue -InputObject $tlsRpt
    $tlsRptTtl = Resolve-DSATtl -AuthoritativeValues $tlsRptAuthoritativeValues -ResolverTtl $tlsRptResolverTtl -RecordLabel 'TLS-RPT' -LogFile $LogFile

    $mxMinimumTtl = if ($mx.MinMxTtl) { $mx.MinMxTtl } else { Get-DSATtlValue -InputObject $mx -PropertyName @('MxRecordTtl', 'MinMxTtl') }

    if ($LogFile) {
        $spfAuthCount = if ($spfAuthoritativeValues) { $spfAuthoritativeValues.Count } else { 0 }
        $dmarcAuthCount = if ($dmarcAuthoritativeValues) { $dmarcAuthoritativeValues.Count } else { 0 }
        $dkimAuthCount = $dkimAuthoritativeValues.Count
        $mtastsAuthCount = if ($mtastsAuthoritativeValues) { $mtastsAuthoritativeValues.Count } else { 0 }
        $tlsRptAuthCount = if ($tlsRptAuthoritativeValues) { $tlsRptAuthoritativeValues.Count } else { 0 }
        $ttlSourceMessage = "TTL source summary: SPF auth={0} resolver={1}; DMARC auth={2} resolver={3}; DKIM auth={4} resolverMin={5}; MX resolverMin={6}; MTASTS auth={7} resolver={8}; TLSRPT auth={9} resolver={10}" -f `
            $spfAuthCount, $spf.DnsRecordTtl, `
            $dmarcAuthCount, $dmarc.DnsRecordTtl, `
            $dkimAuthCount, $dkimResolverMin, `
            $mxMinimumTtl, $mtastsAuthCount, $mtastsTtl, `
            $tlsRptAuthCount, $tlsRptTtl
        Write-DSALog -Message $ttlSourceMessage -LogFile $LogFile -Level 'DEBUG'
    }

    $records = [pscustomobject]@{
        MX                    = $mx.MxRecords
        MXRecordCount         = @($mx.MxRecords).Count
        MXHasNull             = $mx.HasNullMx
        MXMinimumTtl          = $mxMinimumTtl

        SPFRecord             = $spfRecord
        SPFRecords            = $spfRecords
        SPFRecordCount        = $spfCount
        SPFLookupCount        = $spf.DnsLookupsCount
        SPFTerminalMechanism  = $spf.AllMechanism
        SPFHasPtrMechanism    = [bool]$spf.HasPtrType
        SPFRecordLength       = if ($spfRecord) { $spfRecord.Length } else { 0 }
        SPFTtl                = $spfTtl
        SPFIncludes           = $spf.IncludeRecords
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
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classificationValue -Records $records
}
