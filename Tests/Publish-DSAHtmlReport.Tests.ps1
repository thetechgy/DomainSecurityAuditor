BeforeAll {
    $stubModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Stubs'
    if (Test-Path -Path $stubModuleRoot) {
        $env:PSModulePath = "{0}{1}{2}" -f $stubModuleRoot, [System.IO.Path]::PathSeparator, $env:PSModulePath
    }

    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force
}

Describe 'Publish-DSAHtmlReport' {
    It 'renders expected header and footer metadata' {
        InModuleScope DomainSecurityAuditor {
            $profile = [pscustomobject]@{
                Domain                 = 'example.com'
                Classification         = 'Default'
                OriginalClassification = 'SendingOnly'
                ClassificationOverride = $null
                OverallStatus          = 'Pass'
                Checks                 = @()
                Timestamp              = (Get-Date)
                Evidence               = [pscustomobject]@{}
            }

            $outputRoot = Join-Path -Path $TestDrive -ChildPath 'Output'
            $reportPath = Publish-DSAHtmlReport -Profiles $profile -OutputRoot $outputRoot -GeneratedOn (Get-Date)
            Test-Path -Path $reportPath | Should -BeTrue

            $content = Get-Content -Path $reportPath -Raw
            ($content -like '*Collected:*') | Should -BeTrue
            ($content -match 'Test Suite') | Should -BeTrue
            $content.Contains('DomainSecurityAuditor v') | Should -BeTrue
            $content.Contains('DomainSecurityAuditor on GitHub') | Should -BeTrue
        }
    }
}

Describe 'Resolve-DSAClassificationOverride' {
    It 'rejects blank override values' {
        InModuleScope DomainSecurityAuditor {
            { Resolve-DSAClassificationOverride -Value '' -SourceDescription 'test parameter' } | Should -Throw -ExpectedMessage '*cannot be empty*Allowed values*'
        }
    }
}
