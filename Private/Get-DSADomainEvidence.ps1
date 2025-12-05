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
            DomainName        = $Domain
            HealthCheckType   = $healthCheckTypes.ToArray()
            ErrorAction       = 'Stop'
            WarningAction     = 'SilentlyContinue'
            InformationAction = 'SilentlyContinue'
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedDnsEndpoint)) {
            $baseParams['DnsEndpoint'] = $resolvedDnsEndpoint
        }

        $overallResponse = Invoke-DSADomainDetectiveHealth -Parameters $baseParams
        $overall = $overallResponse.Result
        if ($LogFile -and $overallResponse.Warnings) {
            foreach ($warning in $overallResponse.Warnings) {
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
                $customResponse = Invoke-DSADomainDetectiveHealth -Parameters $dkimOnlyParams
                if ($LogFile -and $customResponse.Warnings) {
                    foreach ($warning in $customResponse.Warnings) {
                        if (-not [string]::IsNullOrWhiteSpace($warning)) {
                            Write-DSALog -Message ("DomainDetective warning: {0}" -f $warning) -LogFile $LogFile -Level 'WARN'
                        }
                    }
                }

                $customMap = ConvertTo-DSADkimAnalysisMap -Analysis $customResponse.Result.Raw.DKIMAnalysis
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

        $dkimDetails = @(Get-DSADkimSelectorDetails -Analysis $raw.DKIMAnalysis -Selectors $dkimSelectorsToEvaluate -IncludeMissing:$usingCustomSelectors -MissingSelectors $missingSelectors)
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

    $records = [pscustomobject]@{
        MX                    = @(Get-DSAMxHosts -Analysis $raw.MXAnalysis)
        MXRecordCount         = Get-DSAAnalysisProperty -Analysis $raw.MXAnalysis -PropertyName 'MxRecords' -AsCount
        MXHasNull             = Get-DSAAnalysisProperty -Analysis $raw.MXAnalysis -PropertyName 'HasNullMx'
        MXMinimumTtl          = $null

        SPFRecord             = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecord'
        SPFRecords            = @(Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecords')
        SPFRecordCount        = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'SpfRecords' -AsCount
        SPFLookupCount        = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'DnsLookupsCount'
        SPFTerminalMechanism  = Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'AllMechanism'
        SPFHasPtrMechanism    = [bool](Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'HasPtrType')
        SPFRecordLength       = Get-DSASpfRecordLength -Analysis $raw.SpfAnalysis
        SPFTtl                = $null
        SPFIncludes           = @(Get-DSASpfProperty -Analysis $raw.SpfAnalysis -Property 'IncludeRecords')
        SPFWildcardRecord     = $null
        SPFWildcardConfigured = $false
        SPFUnsafeMechanisms   = @(Get-DSASpfUnsafeMechanisms -Analysis $raw.SpfAnalysis)

        DKIMSelectors         = $dkimSelectorsPresent
        DKIMSelectorDetails   = $dkimDetails
        DKIMMinKeyLength      = Get-DSADkimMinimumKeyLength -Analysis $dkimDetails
        DKIMWeakSelectors     = Get-DSADkimWeakSelectorCount -Analysis $dkimDetails
        DKIMMinimumTtl        = $null

        DMARCRecord           = Get-DSADmarcProperty -Analysis $raw.DmarcAnalysis -Property 'DmarcRecord'
        DMARCPolicy           = Get-DSADmarcProperty -Analysis $raw.DmarcAnalysis -Property 'Policy'
        DMARCRuaAddresses     = @(Get-DSADmarcAddresses -Analysis $raw.DmarcAnalysis -PropertyNames @('MailtoRua', 'HttpRua'))
        DMARCRufAddresses     = @(Get-DSADmarcAddresses -Analysis $raw.DmarcAnalysis -PropertyNames @('MailtoRuf', 'HttpRuf'))
        DMARCTtl              = $null

        MTASTSRecordPresent   = [bool](Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'DnsRecordPresent')
        MTASTSPolicyValid     = [bool](Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'PolicyValid')
        MTASTSMode            = Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'Mode'
        MTASTSTtl             = Get-DSAAnalysisProperty -Analysis $raw.MTASTSAnalysis -PropertyName 'MaxAge'

        TLSRPTRecordPresent   = [bool](Get-DSAAnalysisProperty -Analysis $raw.TLSRPTAnalysis -PropertyName 'TlsRptRecordExists')
        TLSRPTAddresses       = @(Get-DSATlsRptAddresses -Analysis $raw.TLSRPTAnalysis)
        TLSRPTTtl             = $null
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

    if ($Analysis.HasPtrType) {
        $null = $unsafe.Add('ptr')
    }
    if ($Analysis.UnknownMechanisms) {
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
