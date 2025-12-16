<#
.SYNOPSIS
    Create a run context with log/output paths and transcript metadata.
.DESCRIPTION
    Resolves output/log directories, enforces retention, starts a transcript, and returns contextual data for the baseline run.
.PARAMETER OutputRoot
    Target root directory for generated artifacts.
.PARAMETER LogRoot
    Target root directory for logs and transcripts.
.PARAMETER RetentionCount
    Maximum number of log files to keep before pruning oldest entries.
#>
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
        $null = Start-Transcript -Path $transcriptFile -Append
        $transcriptStarted = $true
    }
    catch {
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

<#
.SYNOPSIS
    Build the effective domain input state for a baseline run.
.DESCRIPTION
    Aggregates domains from parameters or files, normalizes metadata (classification, DKIM selectors), and enforces presence of at least one target domain.
.PARAMETER CollectedDomains
    Domains supplied directly through parameters or accumulated from file input.
.PARAMETER DomainMetadata
    Per-domain metadata such as classification overrides or DKIM selectors.
.PARAMETER DirectDomainSet
    Set of domains explicitly provided via parameters (used for override precedence).
.PARAMETER InputFile
    Optional path to a CSV or newline-delimited text file containing domains.
.PARAMETER DefaultClassificationOverride
    Classification override applied to directly supplied domains when provided.
.PARAMETER GlobalDkimSelectors
    DKIM selectors to apply when domain-specific selectors are absent.
.PARAMETER ResolvedDnsEndpoint
    Custom DNS endpoint string passed through to DomainDetective.
.PARAMETER LogFile
    Path to the run log for diagnostic entries.
#>
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

    function Get-DSADkimSelectorsFromRecord {
        <#
        .SYNOPSIS
            Extract DKIM selectors from a CSV or object record.
        .DESCRIPTION
            Normalizes selector values into a trimmed string array, handling collection and delimited string inputs.
        .PARAMETER Record
            Input record containing DKIM selector metadata.
        .OUTPUTS
            System.String[]
        #>
        [CmdletBinding()]
        [OutputType([string[]])]
        param (
            [Parameter(Mandatory = $true)]
            $Record
        )

        $dkimSelectorProperty = $Record.PSObject.Properties | Where-Object { $_.Name -in @('DkimSelectors', 'DKIMSelectors') } | Select-Object -First 1
        if (-not $dkimSelectorProperty) {
            return [string[]]@()
        }

        $rawSelectors = $dkimSelectorProperty.Value
        if ($rawSelectors -is [System.Collections.IEnumerable] -and -not ($rawSelectors -is [string])) {
            return [string[]]@($rawSelectors | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        $selectorString = "$rawSelectors".Trim()
        if ([string]::IsNullOrWhiteSpace($selectorString)) {
            return [string[]]@()
        }

        return [string[]]@($selectorString -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ($PSBoundParameters.ContainsKey('InputFile')) {
        $resolvedInput = Resolve-DSAPath -Path $InputFile -PathType 'File'
        $importedCount = 0
        [array]$inputRecords = @()
        try {
            $inputRecords = @(Import-Csv -Path $resolvedInput -ErrorAction Stop)
        }
        catch {
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

                $dkimSelectorsFromCsv = Get-DSADkimSelectorsFromRecord -Record $record
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
        }
        else {
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
        TargetDomains                 = $targetDomains
        DomainMetadata                = $DomainMetadata
        DirectDomainSet               = $DirectDomainSet
        DefaultClassificationOverride = $DefaultClassificationOverride
        GlobalDkimSelectors           = $GlobalDkimSelectors
        ResolvedDnsEndpoint           = $ResolvedDnsEndpoint
    }
}

<#
.SYNOPSIS
    Resolve per-domain execution context prior to evidence collection.
.DESCRIPTION
    Determines effective classification, DKIM selectors, and DNS endpoint for a domain using metadata, defaults, and overrides.
.PARAMETER DomainName
    The domain being processed.
.PARAMETER DomainMetadata
    Metadata hash keyed by domain name with optional classification or selector overrides.
.PARAMETER DirectDomainSet
    Set of domains provided directly via parameters.
.PARAMETER DefaultClassificationOverride
    Classification override applied to directly supplied domains.
.PARAMETER GlobalDkimSelectors
    DKIM selectors applied when per-domain selectors are not supplied.
.PARAMETER ResolvedDnsEndpoint
    DNS endpoint string to forward to DomainDetective.
.PARAMETER LogFile
    Path to the log file for informational messages.
#>
function Resolve-DSADomainContext {
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

        [string]$LogFile
    )

    $classificationOverride = $null
    $classificationSource = $null
    $metadataRecord = $null
    $dkimSelectors = $null

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

        if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'DkimSelectors') {
            $dkimSelectors = @($metadataRecord.DkimSelectors | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
    }

    if (-not $classificationOverride -and $DefaultClassificationOverride -and $DirectDomainSet.Contains($DomainName)) {
        $classificationOverride = $DefaultClassificationOverride
        $classificationSource = 'Parameter'
    }

    if (-not $dkimSelectors -and $GlobalDkimSelectors) {
        $dkimSelectors = $GlobalDkimSelectors
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

    if ($LogFile) {
        if ($dkimSelectors) {
            Write-DSALog -Message ("Using custom DKIM selectors for '{0}': {1}" -f $DomainName, ($dkimSelectors -join ', ')) -LogFile $LogFile -Level 'DEBUG'
        }
        else {
            Write-DSALog -Message ("Using DomainDetective default DKIM selectors for '{0}'." -f $DomainName) -LogFile $LogFile -Level 'DEBUG'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedDnsEndpoint) -and $LogFile) {
        Write-DSALog -Message ("Using DNS endpoint '{0}' for '{1}'." -f $ResolvedDnsEndpoint, $DomainName) -LogFile $LogFile -Level 'DEBUG'
    }

    return [pscustomobject]@{
        ClassificationOverride = $classificationOverride
        ClassificationSource   = $classificationSource
        DkimSelectors          = $dkimSelectors
        ResolvedDnsEndpoint    = $ResolvedDnsEndpoint
    }
}

<#
.SYNOPSIS
    Execute the baseline workflow for a single domain.
.DESCRIPTION
    Resolves domain context, collects evidence, evaluates against baseline profiles, and returns a compliance profile with metadata.
.PARAMETER DomainName
    Domain to process.
.PARAMETER DomainMetadata
    Hash table of domain metadata loaded from inputs.
.PARAMETER DirectDomainSet
    Set of domains provided directly via parameters.
.PARAMETER DefaultClassificationOverride
    Classification override applied to directly provided domains when present.
.PARAMETER GlobalDkimSelectors
    DKIM selectors to use when none are supplied per domain.
.PARAMETER ResolvedDnsEndpoint
    DNS endpoint string forwarded to DomainDetective.
.PARAMETER BaselineProfiles
    Baseline profile definitions keyed by classification.
.PARAMETER OutputRoot
    Output root for generated artifacts.
.PARAMETER LogFile
    Path to the log file for progress and debug messages.
.PARAMETER CurrentIndex
    Current domain position within the batch.
.PARAMETER TotalCount
    Total number of domains in the batch.
.PARAMETER ShowProgress
    Controls Write-Progress output.
#>
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
            Activity        = 'Domain Security Auditor'
            Status          = "Processing $DomainName (${CurrentIndex}/$TotalCount)"
            PercentComplete = [int](($CurrentIndex / [math]::Max($TotalCount, 1)) * 100)
        }
        Write-Progress @progressSplat
    }

    $domainContext = Resolve-DSADomainContext -DomainName $DomainName -DomainMetadata $DomainMetadata -DirectDomainSet $DirectDomainSet -DefaultClassificationOverride $DefaultClassificationOverride -GlobalDkimSelectors $GlobalDkimSelectors -ResolvedDnsEndpoint $ResolvedDnsEndpoint -LogFile $LogFile

    if ($LogFile) {
        Write-DSALog -Message "Collecting evidence for '$DomainName'." -LogFile $LogFile -Level 'DEBUG'
    }

    $evidenceParams = @{
        Domain  = $DomainName
        LogFile = $LogFile
    }
    if ($domainContext.ClassificationOverride) {
        $evidenceParams.ClassificationOverride = $domainContext.ClassificationOverride
    }
    if ($domainContext.DkimSelectors) {
        $evidenceParams.DkimSelector = $domainContext.DkimSelectors
    }

    if (-not [string]::IsNullOrWhiteSpace($domainContext.ResolvedDnsEndpoint)) {
        $evidenceParams.DNSEndpoint = $domainContext.ResolvedDnsEndpoint
    }

    $evidence = Get-DSADomainEvidence @evidenceParams
    $baselineProfile = Invoke-DSABaselineTest -DomainEvidence $evidence -BaselineDefinition $BaselineProfiles -ClassificationOverride $domainContext.ClassificationOverride

    $effectiveChecks = if ($baselineProfile.Checks) { @($baselineProfile.Checks | Where-Object { $_ }) } else { @() }
    $statusCounts = Get-DSAStatusCounts -Checks $effectiveChecks

    $profileWithMetadata = [pscustomobject]@{
        Domain                 = $baselineProfile.Domain
        Classification         = $baselineProfile.Classification
        OriginalClassification = $baselineProfile.OriginalClassification
        ClassificationOverride = $baselineProfile.ClassificationOverride
        OverallStatus          = $baselineProfile.OverallStatus
        Checks                 = $effectiveChecks
        EffectiveChecks        = $effectiveChecks
        StatusCounts           = $statusCounts
        Evidence               = $evidence.Records
        OutputPath             = $OutputRoot
        Timestamp              = (Get-Date)
        ReportPath             = $null
    }

    if ($LogFile) {
        Write-DSALog -Message ("Completed baseline for '{0}' with status '{1}'." -f $DomainName, $baselineProfile.OverallStatus) -LogFile $LogFile
    }

    return $profileWithMetadata
}

<#
.SYNOPSIS
    Emit a console summary of baseline results.
.DESCRIPTION
    Computes aggregated pass/warning/fail counts across processed domains and writes a short summary to the information stream.
.PARAMETER Profiles
    Compliance profiles produced by Invoke-DSADomainRun.
.PARAMETER ReportPath
    Path to the generated HTML report.
#>
function Write-DSABaselineConsoleSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$Profiles,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ReportPath
    )

    $domainSummaries = [System.Collections.Generic.List[object]]::new()

    foreach ($baselineProfile in $Profiles) {
        $selectorDetails = $null
        if ($baselineProfile -and $baselineProfile.PSObject.Properties.Name -contains 'Evidence' -and $baselineProfile.Evidence -and $baselineProfile.Evidence.PSObject.Properties.Name -contains 'DKIMSelectorDetails') {
            $selectorDetails = $baselineProfile.Evidence.DKIMSelectorDetails
        }

        $checks = if ($baselineProfile.PSObject.Properties.Name -contains 'EffectiveChecks' -and $baselineProfile.EffectiveChecks) {
            @($baselineProfile.EffectiveChecks | Where-Object { $_ })
        }
        else {
            Get-DSAEffectiveChecks -Checks ($baselineProfile.Checks | Where-Object { $_ }) -SelectorDetails $selectorDetails
        }

        $counts = if ($baselineProfile.PSObject.Properties.Name -contains 'StatusCounts' -and $baselineProfile.StatusCounts) {
            $baselineProfile.StatusCounts
        }
        else {
            Get-DSAStatusCounts -Checks $checks
        }
        $rank = switch ($baselineProfile.OverallStatus) {
            'Fail' { 0 }
            'Warning' { 1 }
            default { 2 }
        }

        $summaryItem = [pscustomobject]@{
            Rank   = $rank
            Domain = $baselineProfile.Domain
            Status = $baselineProfile.OverallStatus
            Pass   = $counts.Pass
            Warn   = $counts.Warning
            Fail   = $counts.Fail
        }
        $domainSummaries.Add($summaryItem)
    }

    $sortedSummaries = $domainSummaries | Sort-Object -Property @{ Expression = { $_.Rank } }, @{ Expression = { $_.Domain } }
    $passWidth = if ($sortedSummaries) { ($sortedSummaries | ForEach-Object { $_.Pass.ToString().Length } | Measure-Object -Maximum).Maximum } else { 1 }
    $warnWidth = if ($sortedSummaries) { ($sortedSummaries | ForEach-Object { $_.Warn.ToString().Length } | Measure-Object -Maximum).Maximum } else { 1 }
    $failWidth = if ($sortedSummaries) { ($sortedSummaries | ForEach-Object { $_.Fail.ToString().Length } | Measure-Object -Maximum).Maximum } else { 1 }
    $domainCount = ($Profiles | Measure-Object).Count

    Write-Information -MessageData '' -InformationAction Continue
    Write-Information -MessageData ("Baselines complete ({0} domain{1})" -f $domainCount, $(if ($domainCount -ne 1) { 's' } else { '' })) -InformationAction Continue
    foreach ($summary in $sortedSummaries) {
        $indicator = switch ($summary.Status) {
            'Fail' { '[FAIL]' }
            'Warning' { '[WARN]' }
            default { '[PASS]' }
        }

        $line = "  {0} {1} (Pass {2,$passWidth} | Warn {3,$warnWidth} | Fail {4,$failWidth})" -f $indicator, $summary.Domain, $summary.Pass, $summary.Warn, $summary.Fail
        Write-Information -MessageData $line -InformationAction Continue
    }

    Write-Information -MessageData '' -InformationAction Continue
    Write-Information -MessageData 'Report:' -InformationAction Continue
    Write-Information -MessageData ("  {0}" -f $ReportPath) -InformationAction Continue
    Write-Information -MessageData '' -InformationAction Continue
}
