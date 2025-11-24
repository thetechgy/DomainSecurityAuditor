function Get-DSADomainEvidence {
<#
.SYNOPSIS
    Collects domain security evidence using DomainDetective.
.DESCRIPTION
    Invokes DomainDetective health checks to gather SPF, DMARC, DKIM, MX, MTA-STS, and TLS-RPT
    evidence for a domain. Returns a structured object containing all collected records for
    baseline evaluation.
.PARAMETER Domain
    The domain name to analyze.
.PARAMETER LogFile
    Optional path to a log file for recording errors and diagnostic messages.
.PARAMETER DkimSelector
    Optional DKIM selector names to verify. If omitted, DomainDetective's default selectors are used.
.PARAMETER DNSEndpoint
    Optional DNS endpoint (e.g., a resolver IP/port) forwarded to DomainDetective. Defaults to DomainDetective's system resolver when omitted.
.OUTPUTS
    PSCustomObject with Domain, Classification, and Records properties.
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

    try {
        if (-not (Get-Module -Name DomainDetective -ErrorAction SilentlyContinue)) {
            Import-Module -Name DomainDetective -ErrorAction Stop | Out-Null
        }
    } catch {
        $message = "DomainDetective module import failed: $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }

    $resolvedDkimSelectors = @()
    if ($PSBoundParameters.ContainsKey('DkimSelector')) {
        $resolvedDkimSelectors = @($DkimSelector | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $resolvedDnsEndpoint = $null
    if ($PSBoundParameters.ContainsKey('DNSEndpoint')) {
        $resolvedDnsEndpoint = "$DNSEndpoint".Trim()
        if (-not [string]::IsNullOrWhiteSpace($resolvedDnsEndpoint) -and $LogFile) {
            Write-DSALog -Message ("Using DNS endpoint override '{0}' for '{1}'." -f $resolvedDnsEndpoint, $Domain) -LogFile $LogFile -Level 'DEBUG'
        }
    }

    $healthCheckTypes = [System.Collections.Generic.List[string]]::new()
    foreach ($type in @('SPF', 'DMARC', 'DKIM', 'MX', 'MTASTS', 'TLSRPT')) {
        $null = $healthCheckTypes.Add($type)
    }

    try {
        $baseParams = @{
            DomainName              = $Domain
            HealthCheckType         = $healthCheckTypes.ToArray()
            CollectAuthoritativeTtls = $true
            ErrorAction             = 'Stop'
            WarningAction           = 'SilentlyContinue'
            InformationAction       = 'SilentlyContinue'
            WarningVariable         = 'ddWarnings'
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedDnsEndpoint)) {
            $baseParams['DnsEndpoint'] = $resolvedDnsEndpoint
        }

        $ddWarnings = $null
        $overall = Test-DDDomainOverallHealth @baseParams
        if ($LogFile -and $ddWarnings) {
            foreach ($warning in $ddWarnings) {
                if (-not [string]::IsNullOrWhiteSpace($warning)) {
                    Write-DSALog -Message ("DomainDetective warning: {0}" -f $warning) -LogFile $LogFile -Level 'WARN'
                }
            }
        }
    } catch {
        $message = "DomainDetective health check failed for '$Domain': $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }

    $raw = $overall.Raw
    $baseDkimMap = ConvertTo-DSADkimAnalysisMap -Analysis $raw.DKIMAnalysis
    $defaultSelectors = @($baseDkimMap.Keys | Where-Object { Test-DSADkimSelectorName -Value $_ })
    if ($LogFile) {
        $selectorSummary = if ($defaultSelectors) { $defaultSelectors -join ', ' } else { '(none)' }
        Write-DSALog -Message ("DKIM selectors from DomainDetective: {0}" -f $selectorSummary) -LogFile $LogFile -Level 'DEBUG'
    }

    # If custom selectors were provided, call DomainDetective again for missing ones and merge the results.
    $customMissing = @()
    if ($resolvedDkimSelectors -and $resolvedDkimSelectors.Count -gt 0) {
        $customSelectorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sel in $resolvedDkimSelectors) {
            if (-not [string]::IsNullOrWhiteSpace($sel) -and (Test-DSADkimSelectorName -Value $sel)) {
                $null = $customSelectorSet.Add($sel.Trim())
            }
        }

        $customMissing = @($customSelectorSet | Where-Object { $_ -notin $defaultSelectors })
        if ($customMissing -and $customMissing.Count -gt 0) {
            if ($LogFile) {
                Write-DSALog -Message ("Requesting additional DKIM selectors via DomainDetective: {0}" -f ($customMissing -join ', ')) -LogFile $LogFile -Level 'DEBUG'
            }
            try {
                $dkimOnlyParams = $baseParams.Clone()
                $dkimOnlyParams['HealthCheckType'] = @('DKIM')
                $dkimOnlyParams['DkimSelectors'] = $customMissing
                $dkimOnlyParams['CollectAuthoritativeTtls'] = $true
                $ddWarnings = $null
                $customOverall = Test-DDDomainOverallHealth @dkimOnlyParams
                if ($LogFile -and $ddWarnings) {
                    foreach ($warning in $ddWarnings) {
                        if (-not [string]::IsNullOrWhiteSpace($warning)) {
                            Write-DSALog -Message ("DomainDetective warning: {0}" -f $warning) -LogFile $LogFile -Level 'WARN'
                        }
                    }
                }

                $customMap = ConvertTo-DSADkimAnalysisMap -Analysis $customOverall.Raw.DKIMAnalysis
                if (-not $raw.DKIMAnalysis) {
                    $raw | Add-Member -NotePropertyName 'DKIMAnalysis' -NotePropertyValue ([pscustomobject]@{}) -Force
                }
                if (-not $raw.DKIMAnalysis.AnalysisResults) {
                    $raw.DKIMAnalysis | Add-Member -NotePropertyName 'AnalysisResults' -NotePropertyValue (@{}) -Force
                }

                foreach ($entry in $customMap.GetEnumerator()) {
                    $raw.DKIMAnalysis.AnalysisResults[$entry.Key] = $entry.Value
                }
            } catch {
                if ($LogFile) {
                    Write-DSALog -Message ("DomainDetective DKIM selector-specific check failed: $($_.Exception.Message)") -LogFile $LogFile -Level 'WARN'
                }
            }
        }
    }

    $summary = $raw.Summary
    $classification = Get-DSAClassificationFromSummary -Summary $summary

    $dkimSelectorsFound = @()
    $usingCustomSelectors = ($resolvedDkimSelectors.Count -gt 0)
    $missingSelectors = @()
    $dkimDetails = @()
    $dkimSelectorsPresent = @()
    $ttlAnalysis = $null

    try {
        $dkimSelectorsFound = @(Get-DSADkimSelectorNames -Analysis $raw.DKIMAnalysis)
        if ($LogFile) {
            $foundSummary = if ($dkimSelectorsFound) { $dkimSelectorsFound -join ', ' } else { '(none)' }
            Write-DSALog -Message ("DKIM selectors discovered after merge: {0}" -f $foundSummary) -LogFile $LogFile -Level 'DEBUG'
        }

        $customSelectorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sel in $resolvedDkimSelectors) {
            if (-not [string]::IsNullOrWhiteSpace($sel) -and (Test-DSADkimSelectorName -Value $sel)) {
                $null = $customSelectorSet.Add($sel.Trim())
            }
        }

        $dkimSelectorsToEvaluate = @($dkimSelectorsFound + $resolvedDkimSelectors) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-DSADkimSelectorName -Value $_) } | Sort-Object -Unique

        if ($usingCustomSelectors) {
            $missingSelectors = @($dkimSelectorsToEvaluate | Where-Object { ($_ -notin $dkimSelectorsFound) -and $customSelectorSet.Contains($_) })
            if ($missingSelectors -and $LogFile) {
                Write-DSALog -Message ("DKIM selector(s) not found in DNS: {0}" -f ($missingSelectors -join ', ')) -LogFile $LogFile -Level 'WARN'
            }
        }

        $ttlAnalysis = Get-DSAAuthoritativeTtlAnalysis -Domain $Domain -Raw $raw -DkimSelectors $dkimSelectorsToEvaluate -LogFile $LogFile
        $authoritativeDkimTtls = $null
        if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeDkimTxtTtls') {
            $authoritativeDkimTtls = $ttlAnalysis.AuthoritativeDkimTxtTtls
        }

        $dkimDetails = @(Get-DSADkimSelectorDetails -Analysis $raw.DKIMAnalysis -Selectors $dkimSelectorsToEvaluate -IncludeMissing:$usingCustomSelectors -MissingSelectors $missingSelectors -Domain $Domain -AuthoritativeDkimTtls $authoritativeDkimTtls)
        $dkimSelectorsPresent = @($dkimDetails | Where-Object { $_.Found } | ForEach-Object { $_.Name })
    } catch {
        if ($LogFile) {
            Write-DSALog -Message ("Failed to process DKIM selector details: $($_.Exception.Message)") -LogFile $LogFile -Level 'WARN'
        }
        $dkimSelectorsFound = @()
        $dkimDetails = @()
        $dkimSelectorsPresent = @()
        $missingSelectors = @()
    }

    $mxMinimumTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeMxTtls') {
        $mxMinimumTtl = Get-DSAMinimumIntFromValues -Values $ttlAnalysis.AuthoritativeMxTtls
    }
    if ($null -eq $mxMinimumTtl) {
        $mxMinimumTtl = ConvertTo-DSAInt -Value (Get-DSAAnalysisProperty -Analysis $raw.MXAnalysis -PropertyName 'MinMxTtl')
    }

    $spfTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeSpfTxtTtls') {
        $spfTtl = Get-DSAMinimumIntFromValues -Values $ttlAnalysis.AuthoritativeSpfTxtTtls
    }
    if ($null -eq $spfTtl) {
        $spfTtl = ConvertTo-DSAInt -Value (Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'DnsRecordTtl')
    }

    $dkimMinimumTtl = Get-DSADkimMinimumTtl -Analysis $dkimDetails
    $dmarcTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeDmarcTxtTtls') {
        $dmarcTtl = Get-DSAMinimumIntFromValues -Values $ttlAnalysis.AuthoritativeDmarcTxtTtls
    }
    if ($null -eq $dmarcTtl) {
        $dmarcTtl = ConvertTo-DSAInt -Value (Get-DSADmarcProperty -Analysis $raw.DmarcAnalysis -Property 'DnsRecordTtl')
    }

    $mtastsTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeMtastsTxtTtls') {
        $mtastsTtl = Get-DSAMinimumIntFromValues -Values $ttlAnalysis.AuthoritativeMtastsTxtTtls
    }
    if ($null -eq $mtastsTtl) {
        $mtastsTtl = ConvertTo-DSAInt -Value (Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'DnsRecordTtl')
    }

    $tlsRptTtl = $null
    if ($ttlAnalysis -and $ttlAnalysis.PSObject.Properties.Name -contains 'AuthoritativeTlsRptTxtTtls') {
        $tlsRptTtl = Get-DSAMinimumIntFromValues -Values $ttlAnalysis.AuthoritativeTlsRptTxtTtls
    }
    if ($null -eq $tlsRptTtl) {
        $tlsRptTtl = ConvertTo-DSAInt -Value (Get-DSAAnalysisProperty -Analysis $raw.TLSRPTAnalysis -PropertyName 'DnsRecordTtl')
    }

    $records = [pscustomobject]@{
        MX                    = @(Get-DSAMxHosts -Analysis $raw.MXAnalysis)
        MXRecordCount         = Get-DSAAnalysisProperty -Analysis $raw.MXAnalysis -PropertyName 'MxRecords' -AsCount
        MXHasNull             = Get-DSAAnalysisProperty -Analysis $raw.MXAnalysis -PropertyName 'HasNullMx'
        MXMinimumTtl          = $mxMinimumTtl

        SPFRecord             = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecord'
        SPFRecords            = @(Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecords')
        SPFRecordCount        = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecords' -AsCount
        SPFLookupCount        = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'DnsLookupsCount'
        SPFTerminalMechanism  = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'AllMechanism'
        SPFHasPtrMechanism    = [bool](Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'HasPtrType')
        SPFRecordLength       = Get-DSASpfRecordLength -Analysis $raw.SpfAnalysis
        SPFTtl                = $spfTtl
        SPFIncludes           = @(Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'IncludeRecords')
        SPFWildcardRecord     = $null
        SPFWildcardConfigured = $false
        SPFUnsafeMechanisms   = @(Get-DSASpfUnsafeMechanisms -Analysis $raw.SpfAnalysis)

        DKIMSelectors         = $dkimSelectorsPresent
        DKIMSelectorDetails   = $dkimDetails
        DKIMMinKeyLength      = Get-DSADkimMinimumKeyLength -Analysis $dkimDetails
        DKIMWeakSelectors     = Get-DSADkimWeakSelectorCount -Analysis $dkimDetails
        DKIMMinimumTtl        = $dkimMinimumTtl

        DMARCRecord           = Get-DSADmarcProperty -Analysis $raw.DmarcAnalysis -Property 'DmarcRecord'
        DMARCPolicy           = Get-DSADmarcProperty -Analysis $raw.DmarcAnalysis -Property 'Policy'
        DMARCRuaAddresses     = @(Get-DSADmarcAddresses -Analysis $raw.DmarcAnalysis -PropertyNames @('MailtoRua', 'HttpRua'))
        DMARCRufAddresses     = @(Get-DSADmarcAddresses -Analysis $raw.DmarcAnalysis -PropertyNames @('MailtoRuf', 'HttpRuf'))
        DMARCTtl              = $dmarcTtl

        MTASTSRecordPresent   = [bool](Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'DnsRecordPresent')
        MTASTSPolicyValid     = [bool](Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'PolicyValid')
        MTASTSMode            = Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'Mode'
        MTASTSTtl             = $mtastsTtl

        TLSRPTRecordPresent   = [bool](Get-DSAAnalysisProperty -Analysis $raw.TLSRPTAnalysis -PropertyName 'TlsRptRecordExists')
        TLSRPTAddresses       = @(Get-DSATlsRptAddresses -Analysis $raw.TLSRPTAnalysis)
        TLSRPTTtl             = $tlsRptTtl
    }

    Write-Verbose -Message "Collected DomainDetective evidence for '$Domain'."
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classification -Records $records
}

function Get-DSAAnalysisProperty {
    param (
        [Parameter()]
        $Analysis,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [switch]$AsCount
    )

    if (-not $Analysis) {
        if ($AsCount) { return 0 }
        return $null
    }

    if (-not $Analysis.PSObject.Properties[$PropertyName]) {
        if ($AsCount) { return 0 }
        return $null
    }

    $value = $Analysis.$PropertyName
    if ($AsCount) {
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            return @($value).Count
        }
        return 0
    }

    return $value
}

function Get-DSASpfProperty {
    param (
        $Analysis,
        [string]$Property,
        [switch]$AsCount
    )

    if (-not $Analysis) {
        if ($AsCount) { return 0 }
        return $null
    }

    if (-not $Analysis.PSObject.Properties[$Property]) {
        if ($AsCount) { return 0 }
        return $null
    }

    $value = $Analysis.$Property
    if ($AsCount) {
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            return @($value).Count
        }
        return 0
    }

    return $value
}

function Get-DSASpfRecordLength {
    param (
        $Analysis
    )

    $record = Get-DSASpfProperty -Analysis $Analysis -Property 'SpfRecord'
    if ($record) {
        return $record.Length
    }

    return 0
}

function Get-DSASpfUnsafeMechanisms {
    param (
        $Analysis
    )

    $unsafe = [System.Collections.Generic.List[string]]::new()
    if (-not $Analysis) {
        return $unsafe
    }

    if ($Analysis.PSObject.Properties['HasPtrType'] -and $Analysis.HasPtrType) {
        $null = $unsafe.Add('ptr')
    }
    if ($Analysis.PSObject.Properties['UnknownMechanisms'] -and $Analysis.UnknownMechanisms) {
        foreach ($entry in $Analysis.UnknownMechanisms) {
            if (-not [string]::IsNullOrWhiteSpace($entry)) {
                $null = $unsafe.Add($entry)
            }
        }
    }

    return $unsafe
}

function Get-DSADmarcProperty {
    param (
        $Analysis,
        [string]$Property
    )

    if (-not $Analysis) {
        return $null
    }

    if (-not $Analysis.PSObject.Properties[$Property]) {
        return $null
    }

    return $Analysis.$Property
}

function Get-DSADmarcAddresses {
    param (
        $Analysis,
        [string[]]$PropertyNames
    )

    if (-not $Analysis) {
        return @()
    }

    $addresses = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $PropertyNames) {
        $value = $Analysis.$name
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            foreach ($entry in $value) {
                if (-not [string]::IsNullOrWhiteSpace($entry)) {
                    $null = $addresses.Add($entry)
                }
            }
        }
    }

    return $addresses
}

function Get-DSAMxHosts {
    param (
        $Analysis
    )

    if (-not $Analysis -or -not $Analysis.MxRecords) {
        return @()
    }

    return $Analysis.MxRecords
}

function Get-DSATlsRptAddresses {
    param (
        $Analysis
    )

    if (-not $Analysis) {
        return @()
    }

    $addresses = [System.Collections.Generic.List[string]]::new()
    foreach ($property in @('MailtoRua', 'HttpRua')) {
        $value = $Analysis.$property
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            foreach ($entry in $value) {
                if (-not [string]::IsNullOrWhiteSpace($entry)) {
                    $null = $addresses.Add($entry)
                }
            }
        }
    }

    return $addresses
}

function Get-DSADkimSelectorNames {
    param (
        $Analysis
    )

    $map = ConvertTo-DSADkimAnalysisMap -Analysis $Analysis
    if (-not $map) {
        return @()
    }

    return $map.Keys | Where-Object { Test-DSADkimSelectorName -Value $_ }
}

function Get-DSADkimSelectorDetails {
    param (
        $Analysis,
        [string[]]$Selectors,
        [switch]$IncludeMissing,
        [string[]]$MissingSelectors,
        [string]$Domain,
        $AuthoritativeDkimTtls
    )

    $analysisMap = ConvertTo-DSADkimAnalysisMap -Analysis $Analysis

    $selectorSet = @()
    if ($Selectors) {
        $selectorSet = $Selectors
    } elseif ($analysisMap) {
        $selectorSet = $analysisMap.Keys
    }

    $normalizedSelectors = @($selectorSet | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Where-Object { Test-DSADkimSelectorName -Value $_ } | Sort-Object -Unique)
    if (-not $normalizedSelectors) {
        return @()
    }

    $details = [System.Collections.Generic.List[pscustomobject]]::new()
    $missingSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($missing in (@($MissingSelectors))) {
        if (-not [string]::IsNullOrWhiteSpace($missing)) {
            $null = $missingSet.Add($missing.Trim())
        }
    }

    foreach ($selector in $normalizedSelectors) {
        $data = $null
        if ($analysisMap -and $analysisMap.ContainsKey($selector)) {
            $data = $analysisMap[$selector]
        }

        if (-not $data) {
            if (-not $IncludeMissing -or -not $missingSet.Contains($selector)) {
                continue
            }
        }

        $keyLength = $null
        $ttl = $null
        $isValid = $false

        if ($data) {
            $keyLength = ConvertTo-DSAInt -Value ($data.PSObject.Properties['KeyLength']?.Value)
            $ttl = ConvertTo-DSAInt -Value ($data.PSObject.Properties['Ttl']?.Value ?? $data.PSObject.Properties['TTL']?.Value)
            if ($null -eq $ttl -and $null -ne $data.PSObject.Properties['Ttls']) {
                $ttl = Get-DSAMinimumIntFromValues -Values $data.Ttls
            }

            if ($AuthoritativeDkimTtls -and -not [string]::IsNullOrWhiteSpace($Domain)) {
                $fqdn = "{0}._domainkey.{1}" -f $selector, $Domain
                if ($AuthoritativeDkimTtls -is [System.Collections.IDictionary]) {
                    if ($AuthoritativeDkimTtls.ContainsKey($fqdn)) {
                        $authTtl = Get-DSAMinimumIntFromValues -Values $AuthoritativeDkimTtls[$fqdn]
                        if ($null -ne $authTtl) {
                            $ttl = $authTtl
                        }
                    }
                }
            }

            if ($null -ne $data.PSObject.Properties['IsValid']) {
                $isValid = [bool]$data.IsValid
            } else {
                $isValid = $true
                if ($null -ne $data.PSObject.Properties['ValidPublicKey']) {
                    $isValid = $isValid -and [bool]$data.ValidPublicKey
                }
                if ($null -ne $data.PSObject.Properties['ValidRsaKeyLength']) {
                    $isValid = $isValid -and [bool]$data.ValidRsaKeyLength
                }
                if ($null -ne $data.PSObject.Properties['DkimRecordExists']) {
                    $isValid = $isValid -and [bool]$data.DkimRecordExists
                }
                if ($null -ne $data.PSObject.Properties['StartsCorrectly']) {
                    $isValid = $isValid -and [bool]$data.StartsCorrectly
                }
            }
        }

        $record = [pscustomobject]@{
            Name      = $selector
            KeyLength = $keyLength
            Ttl       = $ttl
            IsValid   = $isValid
            Found     = ($null -ne $data)
        }
        $null = $details.Add($record)
    }

    return $details
}

function Get-DSADkimMinimumKeyLength {
    param (
        $Analysis
    )

    if ($Analysis -is [System.Collections.IEnumerable] -and -not ($Analysis -is [string]) -and -not ($Analysis.PSObject.Properties.Name -contains 'AnalysisResults')) {
        $details = @($Analysis | Where-Object { $_ })
    } else {
        $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    }

    if (@($details).Count -eq 0) {
        return $null
    }

    $lengths = @()
    foreach ($detail in $details) {
        if (-not $detail.Found) { continue }
        if ($null -eq $detail.KeyLength) { continue }
        $parsed = ConvertTo-DSAInt -Value $detail.KeyLength
        if ($null -ne $parsed) {
            $lengths += $parsed
        }
    }
    if (@($lengths).Count -eq 0) {
        return $null
    }

    return ($lengths | Measure-Object -Minimum).Minimum
}

function Get-DSADkimMinimumTtl {
    param (
        $Analysis
    )

    if ($Analysis -is [System.Collections.IEnumerable] -and -not ($Analysis -is [string]) -and -not ($Analysis.PSObject.Properties.Name -contains 'AnalysisResults')) {
        $details = @($Analysis | Where-Object { $_ })
    } else {
        $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    }

    if (@($details).Count -eq 0) {
        return $null
    }

    $ttls = @()
    foreach ($detail in $details) {
        if (-not $detail.Found) { continue }
        $parsed = ConvertTo-DSAInt -Value ($detail.PSObject.Properties['Ttl']?.Value ?? $detail.PSObject.Properties['TTL']?.Value ?? $detail.Ttl)
        if ($null -eq $parsed -and $null -ne $detail.PSObject.Properties['Ttls']) {
            $ttlCandidates = @()
            foreach ($value in $detail.Ttls) {
                $ttlParsed = ConvertTo-DSAInt -Value $value
                if ($null -ne $ttlParsed) {
                    $ttlCandidates += $ttlParsed
                }
            }
            if ($ttlCandidates) {
                $parsed = ($ttlCandidates | Measure-Object -Minimum).Minimum
            }
        }
        if ($null -ne $parsed) {
            $ttls += $parsed
        }
    }

    if (@($ttls).Count -eq 0) {
        return $null
    }

    return ($ttls | Measure-Object -Minimum).Minimum
}

function Get-DSADkimWeakSelectorCount {
    param (
        $Analysis
    )

    if ($Analysis -is [System.Collections.IEnumerable] -and -not ($Analysis -is [string]) -and -not ($Analysis.PSObject.Properties.Name -contains 'AnalysisResults')) {
        $details = @($Analysis | Where-Object { $_ })
    } else {
        $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    }

    if (@($details).Count -eq 0) {
        return 0
    }

    $count = 0
    foreach ($detail in $details) {
        $isWeak = $false
        if (-not $detail.Found) {
            $isWeak = $true
        } elseif ($null -ne $detail.KeyLength) {
            $parsed = ConvertTo-DSAInt -Value $detail.KeyLength
            if ($null -ne $parsed -and $parsed -lt 1024) {
                $isWeak = $true
            }
        }

        if ($detail.IsValid -eq $false) {
            $isWeak = $true
        }

        if ($isWeak) {
            $count++
        }
    }

    return $count
}

function ConvertTo-DSADkimAnalysisMap {
    param (
        $Analysis
    )

    if (-not $Analysis -or -not $Analysis.AnalysisResults) {
        return @{}
    }

    $map = @{}
    $results = $Analysis.AnalysisResults

    if ($results -is [System.Collections.IDictionary]) {
        foreach ($entry in $results.GetEnumerator()) {
            $keyText = "$($entry.Key)".Trim()
            $targetKey = $null
            if (Test-DSADkimSelectorName -Value $keyText) {
                $targetKey = $keyText
            } elseif ($entry.Value) {
                $candidate = $null
                if ($entry.Value.PSObject.Properties.Name -contains 'Name') {
                    $candidate = $entry.Value.Name
                } elseif ($entry.Value.PSObject.Properties.Name -contains 'Selector') {
                    $candidate = $entry.Value.Selector
                }
                if (Test-DSADkimSelectorName -Value $candidate) {
                    $targetKey = $candidate.Trim()
                }
            }

            if ($targetKey -and -not $map.ContainsKey($targetKey)) {
                $map[$targetKey] = $entry.Value
            }
        }
    } elseif ($results -is [System.Collections.IEnumerable] -and -not ($results -is [string])) {
        foreach ($item in $results) {
            if (-not $item) { continue }
            $candidate = $null
            if ($item.PSObject.Properties.Name -contains 'Name') {
                $candidate = $item.Name
            } elseif ($item.PSObject.Properties.Name -contains 'Selector') {
                $candidate = $item.Selector
            }

            if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                $keyText = "$candidate".Trim()
                if (-not $map.ContainsKey($keyText)) {
                    $map[$keyText] = $item
                }
            }
        }
    }

    return $map
}

function Test-DSAAuthoritativeTtlPresent {
    param (
        $Analysis
    )

    if (-not $Analysis) {
        return $false
    }

    $props = @(
        'AuthoritativeATtls'
        'AuthoritativeAaaaTtls'
        'AuthoritativeNsTtls'
        'AuthoritativeMxTtls'
        'AuthoritativeSpfTxtTtls'
        'AuthoritativeDmarcTxtTtls'
        'AuthoritativeMtastsTxtTtls'
        'AuthoritativeTlsRptTxtTtls'
    )

    foreach ($prop in $props) {
        if ($Analysis.PSObject.Properties.Name -contains $prop) {
            $value = $Analysis.$prop
            if ($value -and ($value -is [System.Collections.IEnumerable]) -and -not ($value -is [string]) -and (@($value).Count -gt 0)) {
                return $true
            }
        }
    }

    if ($Analysis.PSObject.Properties.Name -contains 'AuthoritativeDkimTxtTtls') {
        $dkimMap = $Analysis.AuthoritativeDkimTxtTtls
        if ($dkimMap -is [System.Collections.IDictionary] -and $dkimMap.Count -gt 0) {
            foreach ($entry in $dkimMap.GetEnumerator()) {
                if ($entry.Value -and (@($entry.Value).Count -gt 0)) {
                    return $true
                }
            }
        }
    }

    if ($Analysis.PSObject.Properties.Name -contains 'AuthoritativeSoaTtl' -and $null -ne $Analysis.AuthoritativeSoaTtl) {
        return $true
    }

    return $false
}

function Get-DSAAuthoritativeTtlAnalysis {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        $Raw,

        [string[]]$DkimSelectors,

        [string]$LogFile
    )

    $analysis = $null
    if ($Raw -and $Raw.PSObject.Properties.Name -contains 'DnsTtlAnalysis') {
        $analysis = $Raw.DnsTtlAnalysis
        if (Test-DSAAuthoritativeTtlPresent -Analysis $analysis) {
            return $analysis
        }
    }

    if (-not ("DomainDetective.DnsTtlAnalysis" -as [type])) {
        return $analysis
    }

    if (-not $analysis) {
        $analysis = [DomainDetective.DnsTtlAnalysis]::new()
    }

    if ($Raw -and $Raw.PSObject.Properties.Name -contains 'DnsConfiguration' -and $analysis.PSObject.Properties.Name -contains 'DnsConfiguration') {
        $analysis.DnsConfiguration = $Raw.DnsConfiguration
    }

    if ($DkimSelectors -and $analysis.PSObject.Properties.Name -contains 'DkimSelectors') {
        $analysis.DkimSelectors = $DkimSelectors
    }

    if ($analysis.PSObject.Properties.Name -contains 'CollectAuthoritativeTtls') {
        $analysis.CollectAuthoritativeTtls = $true
    }

    try {
        $logger = [DomainDetective.InternalLogger]::new()
        $null = $analysis.Analyze($Domain, $logger).GetAwaiter().GetResult()
        $null = $analysis.AnalyzeUniformityAcrossServers($Domain, $logger).GetAwaiter().GetResult()
    } catch {
        if ($LogFile) {
            Write-DSALog -Message ("Authoritative TTL lookup failed: $($_.Exception.Message)") -LogFile $LogFile -Level 'WARN'
        }
    }

    return $analysis
}

function Get-DSAMinimumIntFromValues {
    param (
        $Values
    )

    if (-not $Values) {
        return $null
    }

    $parsed = @()
    if ($Values -is [System.Collections.IEnumerable] -and -not ($Values -is [string])) {
        foreach ($val in $Values) {
            $converted = ConvertTo-DSAInt -Value $val
            if ($null -ne $converted) {
                $parsed += $converted
            }
        }
    } else {
        $convertedSingle = ConvertTo-DSAInt -Value $Values
        if ($null -ne $convertedSingle) {
            $parsed += $convertedSingle
        }
    }

    if ($parsed.Count -gt 0) {
        return ($parsed | Measure-Object -Minimum).Minimum
    }

    return $null
}

function Test-DSADkimSelectorName {
    param (
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $trimmed = $Value.Trim()
    $blocked = @('KeyLength', 'TTL', 'Ttl', 'IsValid', 'ValidPublicKey', 'ValidRsaKeyLength', 'DkimRecordExists', 'StartsCorrectly')
    if ($blocked -contains $trimmed) {
        return $false
    }

    return ($trimmed -match '^[A-Za-z0-9][A-Za-z0-9_-]*$')
}

function ConvertTo-DSAInt {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $parsed = 0
    if ([int]::TryParse($Value.ToString(), [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Get-DSAClassificationFromSummary {
    param (
        $Summary
    )

    if (-not $Summary) {
        return 'Unknown'
    }

    $hasMx = [bool]$Summary.HasMxRecord
    $hasSpf = [bool]$Summary.HasSpfRecord
    $hasDmarc = [bool]$Summary.HasDmarcRecord

    if ($hasMx -and ($hasSpf -or $hasDmarc)) {
        return 'SendingAndReceiving'
    }

    if ($hasMx) {
        return 'ReceivingOnly'
    }

    if ($hasSpf -or $hasDmarc) {
        return 'SendingOnly'
    }

    return 'Parked'
}
