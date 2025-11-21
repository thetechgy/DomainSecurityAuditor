function Get-DSADomainEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [string]$LogFile,

        [string[]]$DkimSelector
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

    $healthCheckTypes = [System.Collections.Generic.List[string]]::new()
    foreach ($type in @('SPF', 'DMARC', 'MX', 'MTASTS', 'TLSRPT')) {
        $null = $healthCheckTypes.Add($type)
    }
    if ($DkimSelector) {
        $null = $healthCheckTypes.Add('DKIM')
    }

    try {
        $healthParams = @{
            DomainName      = $Domain
            HealthCheckType = $healthCheckTypes.ToArray()
            ErrorAction     = 'Stop'
        }
        if ($DkimSelector) {
            $healthParams.DkimSelectors = $DkimSelector
        }

        $overall = Test-DDDomainOverallHealth @healthParams
    } catch {
        $message = "DomainDetective health check failed for '$Domain': $($_.Exception.Message)"
        if ($LogFile) {
            Write-DSALog -Message $message -LogFile $LogFile -Level 'ERROR'
        }
        throw $message
    }

    $raw = $overall.Raw
    $summary = $raw.Summary
    $classification = Get-DSAClassificationFromSummary -Summary $summary

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

        DKIMSelectors         = @(Get-DSADkimSelectorNames -Analysis $raw.DKIMAnalysis)
        DKIMSelectorDetails   = @(Get-DSADkimSelectorDetails -Analysis $raw.DKIMAnalysis)
        DKIMMinKeyLength      = Get-DSADkimMinimumKeyLength -Analysis $raw.DKIMAnalysis
        DKIMWeakSelectors     = Get-DSADkimWeakSelectorCount -Analysis $raw.DKIMAnalysis
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

function Get-DSADkimSelectorNames {
    param (
        $Analysis
    )

    if (-not $Analysis -or -not $Analysis.AnalysisResults) {
        return @()
    }

    return $Analysis.AnalysisResults.Keys
}

function Get-DSADkimSelectorDetails {
    param (
        $Analysis
    )

    if (-not $Analysis -or -not $Analysis.AnalysisResults) {
        return @()
    }

    $details = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($entry in $Analysis.AnalysisResults.GetEnumerator()) {
        $selector = $entry.Key
        $data = $entry.Value
        $record = [pscustomobject]@{
            Name      = $selector
            Status    = $data.Status
            KeyLength = $data.KeyLength
            Ttl       = $data.Ttl
            IsValid   = $data.Valid
        }
        $null = $details.Add($record)
    }

    return $details
}

function Get-DSADkimMinimumKeyLength {
    param (
        $Analysis
    )

    $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    if ($details.Count -eq 0) {
        return $null
    }

    $lengths = @($details | Where-Object { $_.KeyLength } | ForEach-Object { [int]$_.KeyLength })
    if ($lengths.Count -eq 0) {
        return $null
    }

    return ($lengths | Measure-Object -Minimum).Minimum
}

function Get-DSADkimWeakSelectorCount {
    param (
        $Analysis
    )

    $details = @(Get-DSADkimSelectorDetails -Analysis $Analysis)
    if ($details.Count -eq 0) {
        return 0
    }

    return ($details | Where-Object {
            (($_.KeyLength -as [int]) -lt 1024 -and $_.KeyLength) -or ($_.IsValid -eq $false)
        }).Count
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
