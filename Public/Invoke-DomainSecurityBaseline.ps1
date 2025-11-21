function Invoke-DomainSecurityBaseline {
<#
.SYNOPSIS
    Execute the Domain Security Auditor baseline workflow for one or more domains.
.DESCRIPTION
    Gathers domain data (via DomainDetective), validates it with Pester-driven baselines, and emits structured logs plus report-ready data.
.PARAMETER Domain
    One or more domains to analyze. Accepts pipeline input or explicit arrays.
.PARAMETER ClassificationOverride
    Override the DomainDetective-provided classification for directly supplied domains (single-domain CLI usage). Valid values: SendingOnly, ReceivingOnly, SendingAndReceiving, Parked.
.PARAMETER InputFile
    Optional path to a text or CSV file containing domain names (one per line or column header named 'Domain').
.PARAMETER OutputRoot
    Destination folder for generated reports and machine-readable artifacts.
.PARAMETER LogRoot
    Folder used for transcripts and operational logs.
.PARAMETER RetentionCount
    Maximum number of log/transcript files to retain before pruning oldest entries.
.PARAMETER SkipDependencies
    Bypass automatic dependency checks and exit after logging the decision.
.PARAMETER DkimSelector
    Optional DKIM selectors to verify via DomainDetective; if omitted, DKIM evaluation is skipped.
.PARAMETER Baseline
    Name of the built-in baseline profile to load (defaults to 'Default').
.PARAMETER BaselineProfilePath
    Optional path to a .psd1 file describing a full baseline profile. Copy the default profile, adjust values, and pass the new file to this parameter.
.PARAMETER SkipReportLaunch
    Prevents automatic opening of the generated HTML report. Use this in CI/CD or other non-interactive scenarios.
.PARAMETER ShowProgress
    Toggle Write-Progress output for long-running collections.
.EXAMPLE
    Invoke-DomainSecurityBaseline -Domain 'example.com'
    Runs the baseline workflow for example.com and writes the report to the default Output folder.
.OUTPUTS
    PSCustomObject
.NOTES
    Author: Travis McDade
    Date: 11/20/2025
    Version: 0.1.1
    Purpose: Provide a consistent baseline entry point for the Domain Security Auditor module.

Revision History:
      0.1.1 - 11/20/2025 - Add classification override support through CSV metadata and direct parameters.
      0.1.0 - 11/16/2025 - Initial scaffolded implementation with logging/transcript plumbing.

Known Issues:
      - TTL evidence fields require DomainDetective updates to expose DNS record TTLs.

Resources:
      - https://github.com/thetechgy/DomainSecurityAuditor
#>

    [CmdletBinding()]
    param (
        #region Parameters
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Domains')]
        [string[]]$Domain,

        [Parameter()]
        [Alias('Classification')]
        [string]$ClassificationOverride,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$InputFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputRoot = (Join-Path -Path $script:ModuleRoot -ChildPath 'Output'),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$LogRoot = (Join-Path -Path $script:ModuleRoot -ChildPath 'Logs'),

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$RetentionCount = 30,

        [switch]$SkipDependencies,
        [string[]]$DkimSelector,
        [string]$Baseline = 'Default',
        [string]$BaselineProfilePath,
        [switch]$SkipReportLaunch,
        [switch]$ShowProgress = $true
        #endregion Parameters
    )

    begin {
        $collectedDomains = [System.Collections.Generic.List[string]]::new()
        $domainMetadata = @{}
        $directDomainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $defaultClassificationOverride = $null

        if ($PSBoundParameters.ContainsKey('ClassificationOverride')) {
            $defaultClassificationOverride = Resolve-DSAClassificationOverride -Value $ClassificationOverride -SourceDescription 'ClassificationOverride parameter'
        }
    }

    process {
        if ($PSBoundParameters.ContainsKey('Domain')) {
            foreach ($domainValue in $Domain) {
                if (-not [string]::IsNullOrWhiteSpace($domainValue)) {
                    $trimmedDomain = $domainValue.Trim()
                    $null = $collectedDomains.Add($trimmedDomain)
                    $null = $directDomainSet.Add($trimmedDomain)
                    if ($defaultClassificationOverride) {
                        $domainMetadata[$trimmedDomain] = [pscustomobject]@{
                            Domain                = $trimmedDomain
                            Classification        = $defaultClassificationOverride
                            ClassificationSource  = 'Parameter'
                        }
                    }
                }
            }
        }
    }

    end {
        $transcriptStarted = $false
        $logFile = $null

        try {
            #region PathResolution
            $resolvedLogRoot = Resolve-DSAPath -Path $LogRoot -EnsureExists
            $resolvedOutputRoot = Resolve-DSAPath -Path $OutputRoot -EnsureExists
            Invoke-DSALogRetention -LogDirectory $resolvedLogRoot -RetentionCount $RetentionCount
            #endregion PathResolution

            $runDate = Get-Date
            $timestamp = $runDate.ToString('yyyyMMdd_HHmmss')
            $logFile = Join-Path -Path $resolvedLogRoot -ChildPath "${timestamp}_DomainSecurityAuditor.log"
            $transcriptFile = Join-Path -Path $resolvedLogRoot -ChildPath "${timestamp}_Transcript.log"

            Start-Transcript -Path $transcriptFile -Append
            $transcriptStarted = $true

            $parameterSummary = $PSBoundParameters.GetEnumerator() | ForEach-Object {
                $value = if ($_.Value -is [System.Array]) { $_.Value -join ';' } else { $_.Value }
                '{0}={1}' -f $_.Key, $value
            }
            Write-DSALog -Message 'Starting Domain Security Baseline invocation.' -LogFile $logFile
            Write-DSALog -Message ("Effective parameters: {0}" -f ($parameterSummary -join ', ')) -LogFile $logFile -Level 'DEBUG'

            if ($PSBoundParameters.ContainsKey('InputFile')) {
                $resolvedInput = Resolve-DSAPath -Path $InputFile -PathType 'File'
                $importedCount = 0
                [array]$inputRecords = @()
                try {
                    $inputRecords = @(Import-Csv -Path $resolvedInput -ErrorAction Stop)
                } catch {
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
                        $null = $collectedDomains.Add($domainValue)
                        $domainMetadata[$domainValue] = $record
                        $importedCount++
                    }
                }

                if ($importedCount -eq 0) {
                    $lines = Get-Content -Path $resolvedInput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    foreach ($line in $lines) {
                        $null = $collectedDomains.Add($line.Trim())
                    }
                    Write-DSALog -Message "Loaded domains from '$resolvedInput' as newline-delimited text." -LogFile $logFile
                } else {
                    Write-DSALog -Message "Loaded $importedCount domain(s) from '$resolvedInput' (CSV)." -LogFile $logFile
                }
            }

            $targetDomains = @($collectedDomains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            if (-not $targetDomains) {
                throw 'No domains were supplied. Provide -Domain or -InputFile.'
            }

            if ($SkipDependencies) {
                Write-DSALog -Message 'Dependency verification skipped for modules: DomainDetective, Pester, PSScriptAnalyzer.' -LogFile $logFile -Level 'WARN'
                return
            }

            $dependencyResult = Test-DSADependency -Name @('DomainDetective', 'Pester', 'PSScriptAnalyzer') -AttemptInstallation -LogFile $logFile
            if (-not $dependencyResult.IsCompliant) {
                $missing = $dependencyResult.MissingModules -join ', '
                Write-DSALog -Message "Missing dependencies: $missing" -LogFile $logFile -Level 'ERROR'
                throw "Missing dependencies: $missing"
            }

            $results = [System.Collections.Generic.List[object]]::new()
            $domainCount = $targetDomains.Count
            $currentIndex = 0
            if ($PSBoundParameters.ContainsKey('BaselineProfilePath')) {
                $loadedBaseline = Get-DSABaseline -ProfilePath $BaselineProfilePath
            } else {
                $loadedBaseline = Get-DSABaseline -ProfileName $Baseline
            }
            $baselineProfiles = $loadedBaseline.Profiles

            foreach ($domainName in $targetDomains) {
                $currentIndex++
                if ($ShowProgress) {
                    $progressSplat = @{
                        Activity        = 'Domain Security Baseline'
                        Status          = "Processing $domainName (${currentIndex}/$domainCount)"
                        PercentComplete = [int](($currentIndex / [math]::Max($domainCount, 1)) * 100)
                    }
                    Write-Progress @progressSplat
                }

                $classificationOverride = $null
                $classificationSource = $null
                if ($domainMetadata.ContainsKey($domainName)) {
                    $metadataRecord = $domainMetadata[$domainName]
                    if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'Classification') {
                        $classificationCandidate = $metadataRecord.Classification
                        if (-not [string]::IsNullOrWhiteSpace($classificationCandidate)) {
                            $classificationOverride = $classificationCandidate.Trim()
                        }
                    }
                    if ($metadataRecord -and $metadataRecord.PSObject.Properties.Name -contains 'ClassificationSource') {
                        $classificationSource = $metadataRecord.ClassificationSource
                    }
                }
                elseif ($defaultClassificationOverride -and $directDomainSet.Contains($domainName)) {
                    $classificationOverride = $defaultClassificationOverride
                    $classificationSource = 'Parameter'
                }

                if ($classificationOverride) {
                    $sourceText = switch ($classificationSource) {
                        'CSV' { 'CSV metadata' }
                        'Parameter' { 'command parameter' }
                        default { 'metadata' }
                    }
                    Write-DSALog -Message ("Classification override '{0}' detected for '{1}' from {2}." -f $classificationOverride, $domainName, $sourceText) -LogFile $logFile -Level 'INFO'
                }

                Write-DSALog -Message "Collecting evidence for '$domainName'." -LogFile $logFile -Level 'DEBUG'

                $evidence = Get-DSADomainEvidence -Domain $domainName -LogFile $logFile -DkimSelector $DkimSelector
                $profile = Invoke-DSABaselineTest -DomainEvidence $evidence -BaselineDefinition $baselineProfiles -ClassificationOverride $classificationOverride
                $profileWithMetadata = [pscustomobject]@{
                    Domain                 = $profile.Domain
                    Classification         = $profile.Classification
                    OriginalClassification = $profile.OriginalClassification
                    ClassificationOverride = $profile.ClassificationOverride
                    OverallStatus          = $profile.OverallStatus
                    Checks                 = $profile.Checks
                    Evidence               = $evidence.Records
                    OutputPath             = $resolvedOutputRoot
                    Timestamp              = (Get-Date)
                    ReportPath             = $null
                }

                Write-DSALog -Message ("Completed baseline for '{0}' with status '{1}'." -f $domainName, $profile.OverallStatus) -LogFile $logFile
                $null = $results.Add($profileWithMetadata)
            }

            if ($ShowProgress) {
                Write-Progress -Activity 'Domain Security Baseline' -Completed
            }

            Write-DSALog -Message "Processed $domainCount domain(s)." -LogFile $logFile

            $resultArray = $results.ToArray()
            $reportPath = Publish-DSAHtmlReport -Profiles $resultArray -OutputRoot $resolvedOutputRoot -GeneratedOn $runDate -BaselineName $loadedBaseline.Name -BaselineVersion $loadedBaseline.Version -LogFile $logFile
            foreach ($item in $resultArray) {
                $item | Add-Member -NotePropertyName 'ReportPath' -NotePropertyValue $reportPath -Force
            }

            if (-not $SkipReportLaunch -and $reportPath) {
                Open-DSAReport -Path $reportPath -LogFile $logFile
            }

            return $resultArray
        } catch {
            if ($logFile) {
                Write-DSALog -Message "Unhandled error: $($_.Exception.Message)" -LogFile $logFile -Level 'ERROR'
            }
            throw
        } finally {
            if ($transcriptStarted) {
                Stop-Transcript | Out-Null
            }
        }
    }
}
