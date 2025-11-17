function Get-DSADomainEvidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [string]$LogFile,

        [switch]$DryRun
    )

    $log = {
        param (
            [string]$Message,
            [string]$Level = 'INFO'
        )

        if ($PSBoundParameters.ContainsKey('LogFile') -and $LogFile) {
            Write-DSALog -Message $Message -LogFile $LogFile -Level $Level
        }
    }

    if ($DryRun) {
        & $log -Message "DryRun evidence generated for domain '$Domain'." -Level 'DEBUG'
        return New-DSADomainEvidenceObject -Domain $Domain -Classification 'SendingAndReceiving' -Records (Get-DSADryRunRecords)
    }

    try {
        if (-not (Get-Module -Name DomainDetective -ErrorAction SilentlyContinue)) {
            Import-Module -Name DomainDetective -ErrorAction Stop | Out-Null
        }
    } catch {
        & $log -Message "Failed to import DomainDetective module: $($_.Exception.Message)" -Level 'ERROR'
        throw "DomainDetective module import failed: $($_.Exception.Message)"
    }

    $invokeCommand = Get-Command -Name Invoke-DomainDetective -ErrorAction SilentlyContinue
    if (-not $invokeCommand) {
        & $log -Message 'Invoke-DomainDetective command not found. Ensure DomainDetective is updated.' -Level 'ERROR'
        throw 'Invoke-DomainDetective command not found.'
    }

    try {
        $splat = @{
            Domain      = $Domain
            ErrorAction = 'Stop'
        }

        $rawResult = Invoke-DomainDetective @splat
        $domainData = if ($rawResult -is [System.Collections.IEnumerable] -and -not ($rawResult -is [string])) {
            $rawResult | Select-Object -First 1
        } else {
            $rawResult
        }
    } catch {
        & $log -Message "DomainDetective execution failed for '$Domain': $($_.Exception.Message)" -Level 'ERROR'
        throw "DomainDetective execution failed for '$Domain': $($_.Exception.Message)"
    }

    if (-not $domainData) {
        & $log -Message "DomainDetective returned no data for '$Domain'." -Level 'WARN'
        throw "No data returned for domain '$Domain'."
    }

    $classification = Get-DSAClassificationKey -Classification (Get-DSAPropertyValue -InputObject $domainData -PropertyNames @('Classification', 'DomainClassification', 'DomainType'))
    if (-not $classification) {
        $classification = 'Unknown'
    }

    $mxDetails = Get-DSAMxDetails -DomainData $domainData
    $spfDetails = Get-DSASpfDetails -DomainData $domainData
    $dkimDetails = Get-DSADkimDetails -DomainData $domainData
    $dmarcDetails = Get-DSADmarcDetails -DomainData $domainData
    $mtaStsDetails = Get-DSAMtaStsDetails -DomainData $domainData
    $tlsRptDetails = Get-DSATlsRptDetails -DomainData $domainData

    $records = [pscustomobject]@{
        MX                    = $mxDetails.Hosts
        MXRecordCount         = $mxDetails.RecordCount
        MXHasNull             = $mxDetails.HasNull
        MXMinimumTtl          = $mxDetails.MinimumTtl

        SPFRecord             = $spfDetails.PrimaryRecord
        SPFRecords            = $spfDetails.Records
        SPFRecordCount        = $spfDetails.RecordCount
        SPFLookupCount        = $spfDetails.LookupCount
        SPFTerminalMechanism  = $spfDetails.TerminalMechanism
        SPFHasPtrMechanism    = $spfDetails.HasPtr
        SPFRecordLength       = $spfDetails.RecordLength
        SPFTtl                = $spfDetails.Ttl
        SPFIncludes           = $spfDetails.Includes
        SPFWildcardRecord     = $spfDetails.WildcardRecord
        SPFWildcardConfigured = $spfDetails.WildcardConfigured
        SPFUnsafeMechanisms   = $spfDetails.UnsafeMechanisms

        DKIMSelectors         = $dkimDetails.SelectorNames
        DKIMSelectorDetails   = $dkimDetails.Selectors
        DKIMMinKeyLength      = $dkimDetails.MinKeyLength
        DKIMWeakSelectors     = $dkimDetails.WeakSelectors
        DKIMMinimumTtl        = $dkimDetails.MinimumTtl

        DMARCRecord           = $dmarcDetails.Record
        DMARCPolicy           = $dmarcDetails.Policy
        DMARCRuaAddresses     = $dmarcDetails.Rua
        DMARCRufAddresses     = $dmarcDetails.Ruf
        DMARCTtl              = $dmarcDetails.Ttl

        MTASTSRecordPresent   = $mtaStsDetails.RecordPresent
        MTASTSPolicyValid     = $mtaStsDetails.PolicyValid
        MTASTSMode            = $mtaStsDetails.Mode
        MTASTSTtl             = $mtaStsDetails.Ttl

        TLSRPTRecordPresent   = $tlsRptDetails.RecordPresent
        TLSRPTAddresses       = $tlsRptDetails.Addresses
        TLSRPTTtl             = $tlsRptDetails.Ttl
    }

    & $log -Message "Collected evidence for '$Domain' (classification: $classification)." -Level 'DEBUG'
    return New-DSADomainEvidenceObject -Domain $Domain -Classification $classification -Records $records
}

function Get-DSAPropertyValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames
    )

    foreach ($name in $PropertyNames) {
        if ($InputObject -and $InputObject.PSObject.Properties.Name -contains $name) {
            return $InputObject.$name
        }
    }

    return $null
}

function Get-DSAClassificationKey {
    [CmdletBinding()]
    param (
        [string]$Classification
    )

    if ([string]::IsNullOrWhiteSpace($Classification)) {
        return $null
    }

    $normalized = ($Classification -replace '[^a-zA-Z]', '').ToLowerInvariant()
    switch ($normalized) {
        'sendingonly' { return 'SendingOnly' }
        'receivingonly' { return 'ReceivingOnly' }
        'sendingandreceiving' { return 'SendingAndReceiving' }
        'parked' { return 'Parked' }
        default { return $Classification }
    }
}

function Get-DSADmarcPolicy {
    [CmdletBinding()]
    param (
        [string]$Record
    )

    if ([string]::IsNullOrWhiteSpace($Record)) {
        return $null
    }

    if ($Record -match 'p\s*=\s*([a-zA-Z]+)') {
        return $matches[1].ToLowerInvariant()
    }

    return $null
}

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

function ConvertTo-DSAArray {
    param (
        $Value
    )

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function Get-DSAMxDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $rawRecords = ConvertTo-DSAArray (Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('MXRecords', 'MX', 'MailExchanger', 'MailExchangers'))
    $records = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $rawRecords) {
        if ($null -eq $entry) {
            continue
        }

        if ($entry -is [pscustomobject]) {
            $record = [pscustomobject]@{
                Host       = $entry.Exchange ?? $entry.Host ?? $entry.Target ?? $entry.Value ?? $entry.Server ?? $entry.ToString()
                Preference = $entry.Preference ?? $entry.Priority ?? $entry.Preference
                TTL        = $entry.TTL ?? $entry.Ttl ?? $entry.TimeToLive
                IsNullMx   = ($entry.PSObject.Properties.Name -contains 'IsNullMx') -and [bool]$entry.IsNullMx
            }
        } else {
            $stringValue = $entry.ToString()
            $record = [pscustomobject]@{
                Host       = $stringValue
                Preference = $null
                TTL        = $null
                IsNullMx   = ($stringValue -match '0\s+\.$') -or ($stringValue.Trim() -eq '.')
            }
        }

        $records.Add($record)
    }

    $hosts = $records | ForEach-Object { $_.Host }
    $ttlValues = $records | Where-Object { $_.TTL -ne $null } | ForEach-Object { [int]$_.TTL }
    $minTtl = if ($ttlValues) { ($ttlValues | Measure-Object -Minimum).Minimum } else { $null }
    $hasNull = ($records | Where-Object { $_.IsNullMx -or ($_.Host -and $_.Host.Trim() -eq '.') -or ($_.Host -match '0\s+\.$') }).Count -gt 0

    return [pscustomobject]@{
        Records     = $records
        Hosts       = @($hosts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        RecordCount = $records.Count
        HasNull     = $hasNull
        MinimumTtl  = $minTtl
    }
}

function Get-DSASpfDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $records = ConvertTo-DSAArray (Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('SPFRecords', 'SPFRecord', 'SenderPolicyFramework'))
    $primaryRecord = if ($records.Count -gt 0) { $records[0] } else { $null }
    $ttlValue = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('SPFRecordTTL', 'SPFTtl', 'SPFRecordTtl')
    $wildcardRecord = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('SPFWildcardRecord', 'WildcardSPFRecord')

    $lookupCount = 0
    $includes = [System.Collections.Generic.List[string]]::new()
    $unsafe = [System.Collections.Generic.List[string]]::new()
    $hasPtr = $false
    $terminal = $null
    $recordLength = if ($primaryRecord) { $primaryRecord.Length } else { 0 }

    if ($primaryRecord) {
        $tokens = [regex]::Split($primaryRecord, '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($token in $tokens) {
            $trimmed = $token.Trim()
            if ($trimmed -like 'include:*') {
                $includes.Add($trimmed.Substring(8))
                $lookupCount++
            } elseif ($trimmed -like 'redirect=*') {
                $lookupCount++
            } elseif ($trimmed -like 'exists:*') {
                $lookupCount++
            } elseif ($trimmed -like 'a*' -and -not ($trimmed -eq 'all')) {
                $lookupCount++
            } elseif ($trimmed -like 'mx*') {
                $lookupCount++
            } elseif ($trimmed -like 'ptr*') {
                $lookupCount++
                $hasPtr = $true
                $unsafe.Add('ptr')
            } elseif ($trimmed -like 'exp=*') {
                $lookupCount++
            }
        }

        $lastToken = if ($tokens.Count -gt 0) { $tokens[-1] } else { $null }
        if ($lastToken -and $lastToken -match '([+\-~?]?)all') {
            $terminal = $lastToken
        }
    }

    return [pscustomobject]@{
        Records            = @($records)
        RecordCount        = $records.Count
        PrimaryRecord      = $primaryRecord
        LookupCount        = $lookupCount
        Includes           = @($includes)
        UnsafeMechanisms   = @($unsafe)
        HasPtr             = $hasPtr
        TerminalMechanism  = $terminal
        RecordLength       = $recordLength
        Ttl                = if ($ttlValue -ne $null) { [int]$ttlValue } else { $null }
        WildcardRecord     = $wildcardRecord
        WildcardConfigured = -not [string]::IsNullOrWhiteSpace($wildcardRecord)
    }
}

function Get-DSADkimDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $rawSelectors = ConvertTo-DSAArray (Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('DKIMSelectors', 'DKIM', 'DKIMKeys'))
    $selectors = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $rawSelectors) {
        if ($null -eq $entry) {
            continue
        }

        if ($entry -is [pscustomobject]) {
            $selector = [pscustomobject]@{
                Name      = $entry.Selector ?? $entry.Name ?? $entry.Id ?? $entry.ToString()
                KeyLength = $entry.KeyLength ?? $entry.KeySize ?? $entry.BitStrength
                IsValid   = if ($entry.PSObject.Properties.Name -contains 'IsValid') { [bool]$entry.IsValid } elseif ($entry.Status) { ($entry.Status -match 'valid') } else { $true }
                TTL       = $entry.TTL ?? $entry.Ttl ?? $entry.TimeToLive
            }
        } else {
            $selector = [pscustomobject]@{
                Name      = $entry.ToString()
                KeyLength = $null
                IsValid   = $true
                TTL       = $null
            }
        }

        $selectors.Add($selector)
    }

    $keyLengths = $selectors | Where-Object { $_.KeyLength -ne $null } | ForEach-Object { [int]$_.KeyLength }
    $minKey = if ($keyLengths) { ($keyLengths | Measure-Object -Minimum).Minimum } else { $null }
    $weakSelectors = ($selectors | Where-Object { ($_.KeyLength -and $_.KeyLength -lt 1024) -or ($_.IsValid -eq $false) }).Count
    $ttlValues = $selectors | Where-Object { $_.TTL -ne $null } | ForEach-Object { [int]$_.TTL }
    $minTtl = if ($ttlValues) { ($ttlValues | Measure-Object -Minimum).Minimum } else { $null }

    return [pscustomobject]@{
        Selectors     = $selectors.ToArray()
        SelectorNames = @($selectors | ForEach-Object { $_.Name })
        MinKeyLength  = $minKey
        WeakSelectors = $weakSelectors
        MinimumTtl    = $minTtl
    }
}

function Get-DSADmarcDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $record = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('DMARCRecord', 'DMARC', 'DMARCPolicy')
    $ttlValue = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('DMARCRecordTTL', 'DMARCTtl')
    $tags = Get-DSARecordTags -Record $record

    $resolveAddresses = {
        param ($value)
        if ([string]::IsNullOrWhiteSpace($value)) {
            return @()
        }

        return @(
            $value -split ',' | ForEach-Object {
                $_.Trim() -replace '^mailto:', ''
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    $policy = if ($tags.ContainsKey('p')) {
        $tags['p'].ToLowerInvariant()
    } else {
        Get-DSADmarcPolicy -Record $record
    }

    return [pscustomobject]@{
        Record = $record
        Policy = $policy
        Rua    = & $resolveAddresses ($tags['rua'])
        Ruf    = & $resolveAddresses ($tags['ruf'])
        Ttl    = if ($ttlValue -ne $null) { [int]$ttlValue } else { $null }
    }
}

function Get-DSAMtaStsDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $record = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('MTASTSRecord', 'MTASTSTxtRecord', 'MTASTS')
    $mode = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('MTASTSMode', 'MtaStsMode')
    $policyValid = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('MTASTSPolicyValid', 'MtaStsPolicyValid', 'MTASTSPolicyStatus')
    $ttlValue = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('MTASTSTtl', 'MTASTSRecordTTL')

    $isValid = switch ($policyValid) {
        { $_ -is [bool] } { $_ }
        { [string]::IsNullOrWhiteSpace($_) } { $false }
        default { $_ -match 'valid|success' }
    }

    return [pscustomobject]@{
        RecordPresent = -not [string]::IsNullOrWhiteSpace($record)
        Mode          = $mode
        PolicyValid   = [bool]$isValid
        Ttl           = if ($ttlValue -ne $null) { [int]$ttlValue } else { $null }
    }
}

function Get-DSATlsRptDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$DomainData
    )

    $record = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('TLSRPT', 'TlsRpt', 'TLSReportingRecord')
    $ttlValue = Get-DSAPropertyValue -InputObject $DomainData -PropertyNames @('TLSRPTTtl', 'TLSReportingTTL')
    $tags = Get-DSARecordTags -Record $record

    $addresses = @()
    if ($tags.ContainsKey('rua')) {
        $addresses = $tags['rua'] -split ',' | ForEach-Object {
            $_.Trim() -replace '^mailto:', ''
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    return [pscustomobject]@{
        RecordPresent = -not [string]::IsNullOrWhiteSpace($record)
        Addresses     = $addresses
        Ttl           = if ($ttlValue -ne $null) { [int]$ttlValue } else { $null }
    }
}

function Get-DSARecordTags {
    [CmdletBinding()]
    param (
        [string]$Record
    )

    $tags = @{}
    if ([string]::IsNullOrWhiteSpace($Record)) {
        return $tags
    }

    foreach ($segment in $Record -split ';') {
        $pair = $segment.Trim()
        if ([string]::IsNullOrWhiteSpace($pair)) {
            continue
        }

        if ($pair -match '^\s*([a-zA-Z]+)\s*=\s*(.+)$') {
            $key = $matches[1].ToLowerInvariant()
            $value = $matches[2].Trim()
            $tags[$key] = $value
        }
    }

    return $tags
}
