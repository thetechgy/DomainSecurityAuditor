@{
    Severity = @('Error', 'Warning', 'Information')

    # Default rules stay enabled; the Rules block below tweaks the ones that matter most to DSA.
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @('7.0') # README mandates PowerShell 7+, so fail anything outside that syntax surface.
        }
        PSUseCompatibleCmdlets = @{
            Enable = $true
            # Compatibility profiles shipped with PSScriptAnalyzer 1.24.0 (PS 7.0 on Windows/Ubuntu).
            TargetProfiles = @(
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
                'ubuntu_x64_18.04_7.0.0_x64_3.1.2_core'
            )
        }

        # Enforce the authoring standards from AGENTS.md
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $false # Internal helpers also require comment-based help blocks.
        }
        PSUseApprovedVerbs = @{
            Enable = $true # Keeps Public\ & Private\ functions aligned with PowerShell-approved verbs.
        }
        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true # Ensures future state-changing commands wire up -WhatIf/-Confirm.
        }
        PSAvoidDefaultValueSwitchParameter = @{
            Enable = $true # Ensures switches like -SkipDependencies behave predictably.
        }
        PSAvoidUsingCmdletAliases = @{
            Enable = $true # Log/CI output stays automatable and readable.
        }
        PSAvoidUsingWriteHost = @{
            Enable = $true # Forces Write-Verbose/Information + centralized logging instead of console-only output.
        }
        PSAvoidGlobalVars = @{
            Enable = $true # Protects reusable modules/tests from state bleed.
        }
        PSAvoidUsingInvokeExpression = @{
            Enable = $true # Aligns with secure-by-default dependency handling.
        }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }
        PSAvoidUsingPlainTextForPassword = @{
            Enable = $true
        }

        # Style/readability rules that match the module template (4-space indent, braces on same line, etc.)
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            Kind = 'space'
        }
        PSUseConsistentWhitespace = @{
            Enable = $false
        }
        PSAlignAssignmentStatement = @{
            Enable = $false
        }
        PSPlaceOpenBrace = @{
            Enable = $true
            OnSameLine = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace = @{
            Enable = $true
            NoEmptyLineBefore = $true
            IgnoreOneLineBlock = $true
        }
    }
}
