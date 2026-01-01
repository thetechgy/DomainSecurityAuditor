<#
.SYNOPSIS
    Run Pester compliance tests against domain evidence.
.DESCRIPTION
    Executes Pester tests from Tests/Compliance/ against pre-collected evidence,
    applies classification-based profile filtering, and returns results in the
    compliance profile format expected by the report generator.
.PARAMETER Evidence
    The domain evidence object from Get-DSADomainEvidence.
.PARAMETER ClassificationOverride
    Optional classification override (takes precedence over detected classification).
.PARAMETER LogFile
    Optional path to the log file for diagnostic messages.
.OUTPUTS
    PSCustomObject matching the compliance profile schema.
.EXAMPLE
    $evidence = Get-DSADomainEvidence -Domain 'example.com'
    $profile = Invoke-DSAComplianceTests -Evidence $evidence
#>
function Invoke-DSAComplianceTests {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Evidence,

        [string]$ClassificationOverride,

        [string]$LogFile
    )

    # Determine effective classification
    $effectiveClassification = if ($ClassificationOverride) {
        $ClassificationOverride
    }
    elseif ($Evidence.Classification) {
        $Evidence.Classification
    }
    else {
        'Default'
    }

    # Normalize classification for profile lookup
    $classificationKey = Get-DSAClassificationKey -Classification $effectiveClassification

    # Load profile configuration
    $profilePath = Join-Path -Path $script:ModuleRoot -ChildPath "Configs/Profiles/${classificationKey}.psd1"
    if (-not (Test-Path -Path $profilePath)) {
        $profilePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Configs/Profiles/Default.psd1'
        if ($LogFile) {
            Write-DSALog -Message "Profile '$classificationKey' not found, using Default." -LogFile $LogFile -Level 'WARN'
        }
    }

    $profileConfig = Import-PowerShellDataFile -Path $profilePath

    # Load metadata
    $metadataPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Tests/Metadata.psd1'
    $metadata = Import-PowerShellDataFile -Path $metadataPath

    # Inject evidence into global scope for Pester tests
    # Using global scope because Pester tests run in a separate runspace
    $global:ComplianceTestEvidence = $Evidence

    # Configure Pester
    $complianceTestPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Tests/Compliance'
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $complianceTestPath
    $pesterConfig.Run.PassThru = $true
    $pesterConfig.Output.Verbosity = 'None'

    # Apply profile-based tag filtering
    if ($profileConfig.IncludeTags -and $profileConfig.IncludeTags.Count -gt 0) {
        $pesterConfig.Filter.Tag = $profileConfig.IncludeTags
    }
    if ($profileConfig.ExcludeTags -and $profileConfig.ExcludeTags.Count -gt 0) {
        $pesterConfig.Filter.ExcludeTag = $profileConfig.ExcludeTags
    }

    if ($LogFile) {
        Write-DSALog -Message "Running compliance tests for '$($Evidence.Domain)' with classification '$effectiveClassification'." -LogFile $LogFile -Level 'DEBUG'
    }

    # Run Pester
    $pesterResult = Invoke-Pester -Configuration $pesterConfig

    # Convert Pester results to compliance profile format
    $complianceProfile = ConvertFrom-PesterResult -PesterResult $pesterResult -Metadata $metadata -Evidence $Evidence

    # Add classification metadata
    $complianceProfile | Add-Member -NotePropertyName 'OriginalClassification' -NotePropertyValue $Evidence.Classification -Force
    $complianceProfile | Add-Member -NotePropertyName 'ClassificationOverride' -NotePropertyValue $ClassificationOverride -Force
    $complianceProfile.Classification = $effectiveClassification

    if ($LogFile) {
        Write-DSALog -Message "Compliance tests complete for '$($Evidence.Domain)': $($complianceProfile.OverallStatus)" -LogFile $LogFile
    }

    # Clean up global scope
    Remove-Variable -Name 'ComplianceTestEvidence' -Scope Global -ErrorAction SilentlyContinue

    return $complianceProfile
}
