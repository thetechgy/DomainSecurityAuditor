function Invoke-DomainSecurityAuditor {
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
    Optional DKIM selectors to verify via DomainDetective; if omitted, DomainDetective defaults are used.
    When using -InputFile with CSV, per-domain selectors in a 'DkimSelectors' column override this parameter.
.PARAMETER DNSEndpoint
    Optional DNS endpoint forwarded to DomainDetective. If omitted, DomainDetective uses its system resolver.
.PARAMETER Baseline
    Name of the built-in baseline profile to load (defaults to 'Default').
.PARAMETER BaselineProfilePath
    Optional path to a .psd1 file describing a full baseline profile. Copy the default profile, adjust values, and pass the new file to this parameter.
.PARAMETER SkipReportLaunch
    Prevents automatic opening of the generated HTML report. Use this in CI/CD or other non-interactive scenarios.
.PARAMETER ShowProgress
    Toggle Write-Progress output for long-running collections.
.PARAMETER PassThru
    Returns the compliance profile objects to the pipeline instead of writing a summary to the console.
    Use this when you need to process results programmatically or in scripts.
.EXAMPLE
    Invoke-DomainSecurityAuditor -Domain 'example.com'
    Runs the baseline workflow for example.com and writes the report to the default Output folder.
.OUTPUTS
    None by default. Writes a summary to the information stream.
    PSCustomObject[] when -PassThru is specified, containing compliance profiles for each domain.
.NOTES
    Author: Travis McDade
    Date: 11/21/2025
    Version: 0.2.0
    Purpose: Provide a consistent baseline entry point for the Domain Security Auditor module.

Revision History:
      0.2.0 - 11/22/2025 - BREAKING: Rename entry point to Invoke-DomainSecurityAuditor and align report naming (timestamp after report name).
      0.1.2 - 11/21/2025 - BREAKING: Default output changed from returning objects to writing summary.
                          Add -PassThru parameter to return compliance profile objects for pipeline use.
                          Capture and log DomainDetective warnings.
      0.1.1 - 11/20/2025 - Add classification override support through CSV metadata and direct parameters.
      0.1.0 - 11/16/2025 - Initial scaffolded implementation with logging/transcript plumbing.

Known Issues:
      - TTL evidence fields require DomainDetective updates to expose DNS record TTLs.

Resources:
      - https://github.com/thetechgy/DomainSecurityAuditor
#>

    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
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
        [Alias('DkimSelectors')]
        [string[]]$DkimSelector,
        [string]$DNSEndpoint,
        [string]$Baseline = 'Default',
        [string]$BaselineProfilePath,
        [switch]$SkipReportLaunch,
        [switch]$ShowProgress,
        [switch]$PassThru
        #endregion Parameters
    )

    begin {
        $collectedDomains = [System.Collections.Generic.List[string]]::new()
        $domainMetadata = @{}
        $directDomainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $defaultClassificationOverride = $null
        $globalDkimSelectors = @()
        $resolvedDnsEndpoint = $null

        if ($PSBoundParameters.ContainsKey('ClassificationOverride')) {
            $defaultClassificationOverride = Resolve-DSAClassificationOverride -Value $ClassificationOverride -SourceDescription 'ClassificationOverride parameter'
        }

        if ($PSBoundParameters.ContainsKey('DkimSelector')) {
            $globalDkimSelectors = @($DkimSelector | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        if ($PSBoundParameters.ContainsKey('DNSEndpoint')) {
            $resolvedDnsEndpoint = "$DNSEndpoint".Trim()
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
                            Domain               = $trimmedDomain
                            Classification       = $defaultClassificationOverride
                            ClassificationSource = 'Parameter'
                        }
                    }
                }
            }
        }
    }

    end {
        $context = $null
        $logFile = $null

        try {
            $context = New-DSARunContext -OutputRoot $OutputRoot -LogRoot $LogRoot -RetentionCount $RetentionCount
            $logFile = $context.LogFile

            $parameterSummary = $PSBoundParameters.GetEnumerator() | ForEach-Object {
                $value = if ($_.Value -is [System.Array]) { $_.Value -join ';' } else { $_.Value }
                '{0}={1}' -f $_.Key, $value
            }
            Write-DSALog -Message 'Starting Domain Security Auditor invocation.' -LogFile $logFile
            Write-DSALog -Message ("Effective parameters: {0}" -f ($parameterSummary -join ', ')) -LogFile $logFile -Level 'DEBUG'

            $inputSplat = @{
                CollectedDomains              = $collectedDomains
                DomainMetadata                = $domainMetadata
                DirectDomainSet               = $directDomainSet
                DefaultClassificationOverride = $defaultClassificationOverride
                GlobalDkimSelectors           = $globalDkimSelectors
                ResolvedDnsEndpoint           = $resolvedDnsEndpoint
                LogFile                       = $logFile
            }
            if ($PSBoundParameters.ContainsKey('InputFile')) {
                $inputSplat.InputFile = $InputFile
            }

            $inputState = Get-DSADomainInputState @inputSplat
            $targetDomains = $inputState.TargetDomains

            if ($SkipDependencies) {
                Write-DSALog -Message 'Dependency verification skipped for modules: DomainDetective, Pester, PSScriptAnalyzer.' -LogFile $logFile -Level 'WARN'
                return
            }

            Confirm-DSADependencies -Name @('DomainDetective', 'Pester', 'PSScriptAnalyzer') -AttemptInstallation -LogFile $logFile

            $results = [System.Collections.Generic.List[object]]::new()
            $domainCount = $targetDomains.Count
            $currentIndex = 0
            $showProgressEnabled = if ($PSBoundParameters.ContainsKey('ShowProgress')) { [bool]$ShowProgress } else { $true }
            if ($PSBoundParameters.ContainsKey('BaselineProfilePath')) {
                $loadedBaseline = Get-DSABaseline -ProfilePath $BaselineProfilePath
            }
            else {
                $loadedBaseline = Get-DSABaseline -ProfileName $Baseline
            }
            $baselineProfiles = $loadedBaseline.Profiles

            foreach ($domainName in $targetDomains) {
                $currentIndex++
                $runResult = Invoke-DSADomainRun -DomainName $domainName `
                    -DomainMetadata $inputState.DomainMetadata `
                    -DirectDomainSet $inputState.DirectDomainSet `
                    -DefaultClassificationOverride $inputState.DefaultClassificationOverride `
                    -GlobalDkimSelectors $inputState.GlobalDkimSelectors `
                    -ResolvedDnsEndpoint $inputState.ResolvedDnsEndpoint `
                    -BaselineProfiles $baselineProfiles `
                    -OutputRoot $context.OutputRoot `
                    -LogFile $logFile `
                    -CurrentIndex $currentIndex `
                    -TotalCount $domainCount `
                    -ShowProgress:$showProgressEnabled
                $null = $results.Add($runResult)
            }

            if ($showProgressEnabled) {
                Write-Progress -Activity 'Domain Security Auditor' -Completed
            }

            Write-DSALog -Message "Processed $domainCount domain(s)." -LogFile $logFile

            $resultArray = $results.ToArray()
            $reportPath = Publish-DSAHtmlReport -Profiles $resultArray -OutputRoot $context.OutputRoot -GeneratedOn $context.RunDate -BaselineName $loadedBaseline.Name -BaselineVersion $loadedBaseline.Version -LogFile $logFile
            foreach ($item in $resultArray) {
                $item | Add-Member -NotePropertyName 'ReportPath' -NotePropertyValue $reportPath -Force
            }

            if (-not $SkipReportLaunch -and $reportPath) {
                Open-DSAReport -Path $reportPath -LogFile $logFile
            }

            if ($PassThru) {
                return [pscustomobject[]]$resultArray
            }

            Write-DSABaselineConsoleSummary -Profiles $resultArray -ReportPath $reportPath
            return
        }
        catch {
            if ($logFile) {
                Write-DSALog -Message "Unhandled error: $($_.Exception.Message)" -LogFile $logFile -Level 'ERROR'
            }
            throw
        }
        finally {
            if ($context -and $context.TranscriptStarted) {
                $null = Stop-Transcript
            }
        }
    }
}
