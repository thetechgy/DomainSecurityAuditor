BeforeAll {
    $moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\DomainSecurityAuditor.psd1'
    Import-Module -Name (Resolve-Path -Path $moduleManifest) -Force
}

Describe 'Invoke-DomainSecurityBaseline' {
    It 'is exported by the module' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor -ErrorAction Stop
        $command | Should -Not -BeNullOrEmpty
    }

    It 'includes required parameters' {
        $command = Get-Command -Name Invoke-DomainSecurityBaseline -Module DomainSecurityAuditor
        $command.Parameters.Keys | Should -Contain 'DryRun'
        $command.Parameters.Keys | Should -Contain 'ShowProgress'
        $command.Parameters.Keys | Should -Contain 'SkipDependencies'
    }
}
