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

    try {
        $classification = Test-DDMailDomainClassification @commonParams
    }
    catch {
        $null = $errors.Add("Classification lookup failed for '$Domain': $($_.Exception.Message)")
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

    $getMinPositiveTtl = {
        param($values)
        $positives = @()
        foreach ($value in $values) {
            $converted = $value -as [int]
            if ($converted -and $converted -gt 0) {
                $positives += $converted
            }
        }
        if ($positives.Count -gt 0) {
            return ($positives | Measure-Object -Minimum).Minimum
        }
        return $null
    }

    $spfRecord = $spf.SpfRecord
    $spfRecords = $spf.SpfRecords
    $spfCount = if ($spfRecords) { @($spfRecords).Count } elseif ($spfRecord) { 1 } else { 0 }
    $spfUnsafe = @($spf.UnknownMechanisms)
    if ($spf.HasPtrType) { $spfUnsafe += 'ptr' }

    $dkimList = @()
    $dkimFound = @()
    if ($dkim -and $dkim.AnalysisResults) {
        foreach ($entry in $dkim.AnalysisResults.GetEnumerator()) {
            $selectorName = $entry.Key
            $analysisResult = $entry.Value
            if ($analysisResult -and -not ($analysisResult.PSObject.Properties.Name -contains 'Selector')) {
                $analysisResult | Add-Member -MemberType NoteProperty -Name 'Selector' -Value $selectorName -Force
            }
            if ($analysisResult) {
                $dkimList += $analysisResult
                if ($analysisResult.DkimRecordExists) {
                    $dkimFound += $analysisResult
                }
            }
        }
    }
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

    $authSpfTtl = $null
    if ($ttlAnalysis.ServerTtlTxtSpf) {
        $authSpfTtl = & $getMinPositiveTtl ($ttlAnalysis.ServerTtlTxtSpf.Values | Where-Object { $_ })
        if ($authSpfTtl -and $LogFile) {
            Write-DSALog -Message ("Using authoritative SPF TTL {0}" -f $authSpfTtl) -LogFile $LogFile -Level 'DEBUG'
        }
    }
    if (-not $authSpfTtl -and $LogFile) {
        Write-DSALog -Message 'Authoritative SPF TTL unavailable; falling back to resolver TTL.' -LogFile $LogFile -Level 'DEBUG'
    }

    $authDmarcTtl = $null
    if ($ttlAnalysis.ServerTtlTxtDmarc) {
        $authDmarcTtl = & $getMinPositiveTtl ($ttlAnalysis.ServerTtlTxtDmarc.Values | Where-Object { $_ })
        if ($authDmarcTtl -and $LogFile) {
            Write-DSALog -Message ("Using authoritative DMARC TTL {0}" -f $authDmarcTtl) -LogFile $LogFile -Level 'DEBUG'
        }
    }
    if (-not $authDmarcTtl -and $LogFile) {
        Write-DSALog -Message 'Authoritative DMARC TTL unavailable; falling back to resolver TTL.' -LogFile $LogFile -Level 'DEBUG'
    }

    $authDkimTtl = $null
    if ($ttlAnalysis.ServerTtlTxtPerName) {
        $dkimAuthoritativeValues = @()
        foreach ($perNameMap in $ttlAnalysis.ServerTtlTxtPerName.Values) {
            if ($perNameMap) {
                $dkimAuthoritativeValues += ($perNameMap.Values | Where-Object { $_ })
            }
        }
        if ($dkimAuthoritativeValues.Count -gt 0) {
            $authDkimTtl = & $getMinPositiveTtl $dkimAuthoritativeValues
        }
        if ($authDkimTtl -and $LogFile) {
            Write-DSALog -Message ("Using authoritative DKIM TTL {0}" -f $authDkimTtl) -LogFile $LogFile -Level 'DEBUG'
        }
    }
    if (-not $authDkimTtl -and $LogFile) {
        Write-DSALog -Message 'Authoritative DKIM TTL unavailable; falling back to resolver TTL.' -LogFile $LogFile -Level 'DEBUG'
    }

    $authMtastsTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject -and ($ttlAnalysis.PSObject.Properties.Name -contains 'ServerTtlTxtMtasts') -and $ttlAnalysis.ServerTtlTxtMtasts) {
        $authMtastsTtl = & $getMinPositiveTtl ($ttlAnalysis.ServerTtlTxtMtasts.Values | Where-Object { $_ })
        if ($authMtastsTtl -and $LogFile) {
            Write-DSALog -Message ("Using authoritative MTA-STS TTL {0}" -f $authMtastsTtl) -LogFile $LogFile -Level 'DEBUG'
        }
    }
    if (-not $authMtastsTtl -and $LogFile) {
        Write-DSALog -Message 'Authoritative MTA-STS TTL unavailable; falling back to resolver TTL.' -LogFile $LogFile -Level 'DEBUG'
    }

    $authTlsRptTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject -and ($ttlAnalysis.PSObject.Properties.Name -contains 'ServerTtlTxtTlsRpt') -and $ttlAnalysis.ServerTtlTxtTlsRpt) {
        $authTlsRptTtl = & $getMinPositiveTtl ($ttlAnalysis.ServerTtlTxtTlsRpt.Values | Where-Object { $_ })
        if ($authTlsRptTtl -and $LogFile) {
            Write-DSALog -Message ("Using authoritative TLS-RPT TTL {0}" -f $authTlsRptTtl) -LogFile $LogFile -Level 'DEBUG'
        }
    }
    if (-not $authTlsRptTtl -and $LogFile) {
        Write-DSALog -Message 'Authoritative TLS-RPT TTL unavailable; falling back to resolver TTL.' -LogFile $LogFile -Level 'DEBUG'
    }

    $mxMinimumTtl = if ($mx.MinMxTtl) { $mx.MinMxTtl } else { Get-DSATtlValue -InputObject $mx -PropertyName @('MxRecordTtl', 'MinMxTtl') }
    $spfTtl = if ($authSpfTtl) { $authSpfTtl } else { Get-DSATtlValue -InputObject $spf }
    $dmarcTtl = if ($authDmarcTtl) { $authDmarcTtl } else { Get-DSATtlValue -InputObject $dmarc }
    $dkimTtls = @($dkimFound | ForEach-Object { Get-DSATtlValue -InputObject $_ } | Where-Object { $_ })
    $dkimMinTtl = $authDkimTtl
    if (-not $dkimMinTtl) {
        $dkimMinTtl = if ($dkimTtls) { ($dkimTtls | Measure-Object -Minimum).Minimum } else { $null }
    }
    $mtastsTtl = if ($authMtastsTtl) { $authMtastsTtl } else { Get-DSATtlValue -InputObject $mtastsAnalysis }
    $tlsRptTtl = if ($authTlsRptTtl) { $authTlsRptTtl } else { Get-DSATtlValue -InputObject $tlsRpt }

    if ($LogFile) {
        $spfAuthCount = if ($ttlAnalysis.ServerTtlTxtSpf) { (@($ttlAnalysis.ServerTtlTxtSpf.Values | Where-Object { $_ })).Count } else { 0 }
        $dmarcAuthCount = if ($ttlAnalysis.ServerTtlTxtDmarc) { (@($ttlAnalysis.ServerTtlTxtDmarc.Values | Where-Object { $_ })).Count } else { 0 }
        $dkimAuthCount = 0
        if ($ttlAnalysis.ServerTtlTxtPerName) {
            foreach ($perNameMap in $ttlAnalysis.ServerTtlTxtPerName.Values) {
                if ($perNameMap) {
                    $dkimAuthCount += (@($perNameMap.Values | Where-Object { $_ })).Count
                }
            }
        }
        $mtastsAuthCount = if ($ttlAnalysis -and $ttlAnalysis.PSObject -and ($ttlAnalysis.PSObject.Properties.Name -contains 'ServerTtlTxtMtasts') -and $ttlAnalysis.ServerTtlTxtMtasts) { (@($ttlAnalysis.ServerTtlTxtMtasts.Values | Where-Object { $_ })).Count } else { 0 }
        $tlsRptAuthCount = if ($ttlAnalysis -and $ttlAnalysis.PSObject -and ($ttlAnalysis.PSObject.Properties.Name -contains 'ServerTtlTxtTlsRpt') -and $ttlAnalysis.ServerTtlTxtTlsRpt) { (@($ttlAnalysis.ServerTtlTxtTlsRpt.Values | Where-Object { $_ })).Count } else { 0 }
        $dkimResolverMin = if ($dkimTtls) { ($dkimTtls | Measure-Object -Minimum).Minimum } else { $null }
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
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classification.Classification -Records $records
}
