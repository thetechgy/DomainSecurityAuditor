function New-DSARunContext {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogRoot,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$RetentionCount = 30
    )

    $resolvedLogRoot = Resolve-DSAPath -Path $LogRoot -EnsureExists
    $resolvedOutputRoot = Resolve-DSAPath -Path $OutputRoot -EnsureExists
    Invoke-DSALogRetention -LogDirectory $resolvedLogRoot -RetentionCount $RetentionCount

    $runDate = Get-Date
    $timestamp = $runDate.ToString('yyyyMMdd_HHmmss')
    $logFile = Join-Path -Path $resolvedLogRoot -ChildPath "${timestamp}_DomainSecurityAuditor.log"
    $transcriptFile = Join-Path -Path $resolvedLogRoot -ChildPath "${timestamp}_Transcript.log"

    $transcriptStarted = $false
    try {
        Start-Transcript -Path $transcriptFile -Append | Out-Null
        $transcriptStarted = $true
    } catch {
        $transcriptStarted = $false
        Write-DSALog -Message ("Failed to start transcript: {0}" -f $_.Exception.Message) -LogFile $logFile -Level 'WARN'
    }

    return [pscustomobject]@{
        OutputRoot        = $resolvedOutputRoot
        LogRoot           = $resolvedLogRoot
        LogFile           = $logFile
        TranscriptFile    = $transcriptFile
        TranscriptStarted = $transcriptStarted
        RunDate           = $runDate
        Timestamp         = $timestamp
    }
}

function Get-DSADomainInputState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$CollectedDomains,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [hashtable]$DomainMetadata,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$DirectDomainSet,

        [string]$InputFile,

        [string]$DefaultClassificationOverride,

        [string[]]$GlobalDkimSelectors,

        [string]$ResolvedDnsEndpoint,

        [string]$LogFile
    )

    if ($PSBoundParameters.ContainsKey('InputFile')) {
        $resolvedInput = Resolve-DSAPath -Path $InputFile -PathType 'File'
        $importedCount = 0
        [array]$inputRecords = @()
        try {
            $inputRecords = @(Import-Csv -Path $resolvedInput -ErrorAction Stop)
        } catch {
            if ($LogFile) {
                Write-DSALog -Message "CSV import failed for '$resolvedInput': $($_.Exception.Message). Attempting line-based fallback." -LogFile $LogFile -Level 'WARN'
            }
            $inputRecords = @()
        }

        foreach ($record in $inputRecords) {
            if (-not $record) {
                continue
            }
            if ($record.PSObject.Properties.Name -contains 'Domain' -and -not [string]::IsNullOrWhiteSpace($record.Domain)) {
                $domainValue = $record.Domain.Trim()
                $record.Domain = $domainValue
                if ($record.PSObject.Properties.Name -contains 'Classification' -and -not [string]::IsNullOrWhiteSpace($record.Classification)) {
                    $sourceDescription = "CSV row for '$domainValue'"
                    $record.Classification = Resolve-DSAClassificationOverride -Value $record.Classification -SourceDescription $sourceDescription
                    $record | Add-Member -NotePropertyName 'ClassificationSource' -NotePropertyValue 'CSV' -Force
                }

                $dkimSelectorsFromCsv = @()
                $dkimSelectorProperty = $record.PSObject.Properties | Where-Object { $_.Name -in @('DkimSelectors', 'DKIMSelectors') } | Select-Object -First 1
                if ($dkimSelectorProperty) {
                    $rawSelectors = $dkimSelectorProperty.Value
                    if ($rawSelectors -is [System.Collections.IEnumerable] -and -not ($rawSelectors -is [string])) {
                        $dkimSelectorsFromCsv = @($rawSelectors | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    } else {
                        $selectorString = "$rawSelectors"
                        $dkimSelectorsFromCsv = @($selectorString -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    }
                }
                if ($dkimSelectorsFromCsv) {
                    $record | Add-Member -NotePropertyName 'DkimSelectors' -NotePropertyValue $dkimSelectorsFromCsv -Force
                }

                $null = $CollectedDomains.Add($domainValue)
                $DomainMetadata[$domainValue] = $record
                $importedCount++
            }
        }

        if ($importedCount -eq 0) {
            $lines = Get-Content -Path $resolvedInput -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($line in $lines) {
                $null = $CollectedDomains.Add($line.Trim())
            }
            if ($LogFile) {
                Write-DSALog -Message "Loaded domains from '$resolvedInput' as newline-delimited text." -LogFile $LogFile
            }
        } else {
            if ($LogFile) {
                Write-DSALog -Message "Loaded $importedCount domain(s) from '$resolvedInput' (CSV)." -LogFile $LogFile
            }
        }
    }

    $targetDomains = @($CollectedDomains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if (-not $targetDomains) {
        throw 'No domains were supplied. Provide -Domain or -InputFile.'
    }

    return [pscustomobject]@{
        TargetDomains               = $targetDomains
        DomainMetadata              = $DomainMetadata
        DirectDomainSet             = $DirectDomainSet
        DefaultClassificationOverride = $DefaultClassificationOverride
        GlobalDkimSelectors         = $GlobalDkimSelectors
        ResolvedDnsEndpoint         = $ResolvedDnsEndpoint
    }
}

function Invoke-DSADomainRun {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainMetadata,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$DirectDomainSet,

        [string]$DefaultClassificationOverride,

        [string[]]$GlobalDkimSelectors,

        [string]$ResolvedDnsEndpoint,

        [Parameter(Mandatory = $true)]
        [hashtable]$BaselineProfiles,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputRoot,

        [string]$LogFile,

        [int]$CurrentIndex,

        [int]$TotalCount,

        [switch]$ShowProgress
    )

    if ($ShowProgress) {
        $progressSplat = @{
            Activity        = 'Domain Security Baseline'
            Status          = "Processing $DomainName (${CurrentIndex}/$TotalCount)"
            PercentComplete = [int](($CurrentIndex / [math]::Max($TotalCount, 1)) * 100)
        }
        Write-Progress @progressSplat
    }

    $classificationOverride = $null
    $classificationSource = $null
    $metadataRecord = $null
    if ($DomainMetadata.ContainsKey($DomainName)) {
        $metadataRecord = $DomainMetadata[$DomainName]
        if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'Classification') {
            $classificationCandidate = $metadataRecord.Classification
            if (-not [string]::IsNullOrWhiteSpace($classificationCandidate)) {
                $classificationOverride = $classificationCandidate.Trim()
            }
        }
        if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'ClassificationSource') {
            $classificationSource = $metadataRecord.ClassificationSource
        }
    } elseif ($DefaultClassificationOverride -and $DirectDomainSet.Contains($DomainName)) {
        $classificationOverride = $DefaultClassificationOverride
        $classificationSource = 'Parameter'
    }

    if ($classificationOverride) {
        $sourceText = switch ($classificationSource) {
            'CSV' { 'CSV metadata' }
            'Parameter' { 'command parameter' }
            default { 'metadata' }
        }
        if ($LogFile) {
            Write-DSALog -Message ("Classification override '{0}' detected for '{1}' from {2}." -f $classificationOverride, $DomainName, $sourceText) -LogFile $LogFile -Level 'INFO'
        }
    }

    $effectiveDkimSelectors = $null
    if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'DkimSelectors') {
        $effectiveDkimSelectors = @($metadataRecord.DkimSelectors | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    if (-not $effectiveDkimSelectors -and $GlobalDkimSelectors) {
        $effectiveDkimSelectors = $GlobalDkimSelectors
    }

    if ($LogFile) {
        Write-DSALog -Message "Collecting evidence for '$DomainName'." -LogFile $LogFile -Level 'DEBUG'
    }

    $evidenceParams = @{
        Domain  = $DomainName
        LogFile = $LogFile
    }
    if ($effectiveDkimSelectors) {
        $evidenceParams.DkimSelector = $effectiveDkimSelectors
        if ($LogFile) {
            Write-DSALog -Message ("Using custom DKIM selectors for '{0}': {1}" -f $DomainName, ($effectiveDkimSelectors -join ', ')) -LogFile $LogFile -Level 'DEBUG'
        }
    } elseif ($LogFile) {
        Write-DSALog -Message ("Using DomainDetective default DKIM selectors for '{0}'." -f $DomainName) -LogFile $LogFile -Level 'DEBUG'
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedDnsEndpoint)) {
        $evidenceParams.DNSEndpoint = $ResolvedDnsEndpoint
        if ($LogFile) {
            Write-DSALog -Message ("Using DNS endpoint '{0}' for '{1}'." -f $ResolvedDnsEndpoint, $DomainName) -LogFile $LogFile -Level 'DEBUG'
        }
    }

    $evidence = Get-DSADomainEvidence @evidenceParams
    $profile = Invoke-DSABaselineTest -DomainEvidence $evidence -BaselineDefinition $BaselineProfiles -ClassificationOverride $classificationOverride

    if ($profile.Checks -and $evidence.PSObject.Properties.Name -contains 'Records' -and $evidence.Records.PSObject.Properties.Name -contains 'DKIMSelectorDetails') {
        $dkimSelectors = $evidence.Records.DKIMSelectorDetails
        $adjustedChecks = [System.Collections.Generic.List[object]]::new()
        foreach ($check in $profile.Checks) {
            if ($check.Area -eq 'DKIM' -and $dkimSelectors) {
                $effectiveStatus = Get-DSADkimEffectiveStatus -Check $check -Selectors $dkimSelectors
                $clone = $check.PSObject.Copy()
                $clone | Add-Member -NotePropertyName 'Status' -NotePropertyValue $effectiveStatus -Force
                $null = $adjustedChecks.Add($clone)
            } else {
                $null = $adjustedChecks.Add($check)
            }
        }
        $profile.Checks = $adjustedChecks.ToArray()
        $profile.OverallStatus = Get-DSAOverallStatus -Checks $profile.Checks
    }

    $profileWithMetadata = [pscustomobject]@{
        Domain                 = $profile.Domain
        Classification         = $profile.Classification
        OriginalClassification = $profile.OriginalClassification
        ClassificationOverride = $profile.ClassificationOverride
        OverallStatus          = $profile.OverallStatus
        Checks                 = $profile.Checks
        Evidence               = $evidence.Records
        OutputPath             = $OutputRoot
        Timestamp              = (Get-Date)
        ReportPath             = $null
    }

    if ($LogFile) {
        Write-DSALog -Message ("Completed baseline for '{0}' with status '{1}'." -f $DomainName, $profile.OverallStatus) -LogFile $LogFile
    }

    return $profileWithMetadata
}

function Write-DSABaselineConsoleSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$Profiles,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ReportPath
    )

    $statusCounts = @{
        Pass    = 0
        Fail    = 0
        Warning = 0
    }

    foreach ($profile in $Profiles) {
        foreach ($check in ($profile.Checks | Where-Object { $_ })) {
            switch ($check.Status) {
                'Pass' { $statusCounts.Pass++ }
                'Fail' { $statusCounts.Fail++ }
                'Warning' { $statusCounts.Warning++ }
            }
        }
    }

    $domainCount = ($Profiles | Measure-Object).Count
    Write-Host ''
    Write-Host "Baselines complete ($domainCount domain$(if ($domainCount -ne 1) { 's' }))"
    Write-Host "  Pass:    $($statusCounts.Pass)" -ForegroundColor Green
    Write-Host "  Warning: $($statusCounts.Warning)" -ForegroundColor Yellow
    Write-Host "  Fail:    $($statusCounts.Fail)" -ForegroundColor Red
    Write-Host "Report: $ReportPath"
}
