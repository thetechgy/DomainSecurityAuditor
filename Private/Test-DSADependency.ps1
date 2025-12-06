<#
.SYNOPSIS
    Check for required modules and optionally attempt installation.
.DESCRIPTION
    Verifies module availability, tries to install missing modules when requested, and returns compliance details with missing list.
.PARAMETER Name
    Module names to validate.
.PARAMETER AttemptInstallation
    Attempt to install missing modules using Install-Module.
.PARAMETER LogFile
    Path to the log file for warnings and install results.
#>
function Test-DSADependency {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [switch]$AttemptInstallation,

        [string]$LogFile
    )

    $uniqueModules = $Name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
    $missingModules = [System.Collections.Generic.List[string]]::new()

    foreach ($moduleName in $uniqueModules) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            $null = $missingModules.Add($moduleName)
        }
    }

    if ($missingModules.Count -gt 0 -and $AttemptInstallation) {
        $installCommand = Get-Command -Name Install-Module -ErrorAction SilentlyContinue
        if ($null -eq $installCommand) {
            if ($LogFile) {
                Write-DSALog -Message 'Install-Module not available; cannot remediate missing dependencies automatically.' -LogFile $LogFile -Level 'WARN'
            }
        }
        else {
            foreach ($module in @($missingModules.ToArray())) {
                try {
                    $splat = @{
                        Name        = $module
                        Scope       = 'CurrentUser'
                        Force       = $true
                        ErrorAction = 'Stop'
                    }

                    Install-Module @splat
                    if (Get-Module -ListAvailable -Name $module) {
                        $null = $missingModules.Remove($module)
                        if ($LogFile) {
                            Write-DSALog -Message "Installed dependency '$module'." -LogFile $LogFile
                        }
                    }
                }
                catch {
                    if ($LogFile) {
                        Write-DSALog -Message "Failed to install dependency '$module': $($_.Exception.Message)" -LogFile $LogFile -Level 'WARN'
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        MissingModules = $missingModules.ToArray()
        IsCompliant    = ($missingModules.Count -eq 0)
    }
}

