@{
  Severity         = @('Error', 'Warning', 'Information')

  # Default rules stay enabled; the Rules block below tweaks the ones that matter most to DSA.
  Rules            = @{
    PSUseCompatibleSyntax                          = @{
      Enable         = $true
      TargetVersions = @('7.0')          # README mandates PowerShell 7+, so fail anything outside that syntax surface.
    }
    PSUseCompatibleCmdlets                         = @{
      Enable        = $true
      TargetProfile = @(
        @{
          PowerShellVersion = '7.0'
          Modules           = @('DomainDetective', 'PSWriteHTML', 'Pester', 'PSScriptAnalyzer')
        }
      )
    }

    # Enforce the authoring standards from AGENTS.md
    PSProvideCommentHelp                           = @{
      Enable       = $true
      ExportedOnly = $false              # Internal helpers also require comment-based help blocks.
    }
    PSUseApprovedVerbs                             = @{
      Enable = $true              # Keeps Public\ & Private\ functions aligned with “PowerShell-approved verbs”.
    }
    PSUseShouldProcessForStateChangingFunctions    = @{
      Enable = $true              # Guarantees exported commands surface -WhatIf/-Confirm per the -DryRun requirement.
    }
    PSAvoidDefaultValueSwitchParameter             = @{
      Enable = $true              # Ensures switches like -SkipDependencies behave predictably.
    }
    PSAvoidUsingCmdletAliases                      = @{
      Enable = $true              # Log/CI output stays automatable and readable.
    }
    PSAvoidUsingWriteHost                          = @{
      Enable = $true              # Forces Write-Verbose/Information + centralized logging instead of console-only output.
    }
    PSAvoidGlobalVars                              = @{
      Enable = $true              # Protects reusable modules/tests from state bleed.
    }
    PSAvoidUsingInvokeExpression                   = @{
      Enable = $true              # Aligns with secure-by-default dependency handling.
    }
    PSAvoidUsingConvertToSecureStringWithPlainText = @{
      Enable = $true
    }
    PSAvoidUsingPlainTextForPassword               = @{
      Enable = $true
    }

    # Style/readability rules that match the module template (4-space indent, braces on same line, etc.)
    PSUseConsistentIndentation                     = @{
      Enable          = $true
      IndentationSize = 4
      Kind            = 'space'
    }
    PSUseConsistentWhitespace                      = @{ Enable = $true }
    PSAlignAssignmentStatement                     = @{ Enable = $true }
    PSPlaceOpenBrace                               = @{
    }
    PSPlaceCloseBrace                              = @{
      Enable             = $true
      NoEmptyLineBefore  = $true
      IgnoreOneLineBlock = $true
    }
  }

  # Wrapper scripts in Examples may legitimately surface informational output, so relax just that rule there.
  RuleSuppressions = @(
    @{
      RuleName      = 'PSAvoidUsingWriteHost'
      Justification = 'Example wrappers are user-facing shims per AGENTS.md; they can echo status while the module logs centrally.'
      Target        = 'Examples\*.ps1'
    }
  )
}
