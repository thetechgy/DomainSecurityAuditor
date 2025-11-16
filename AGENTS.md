### Module & Script Structure

- Use modular, reusable functions with PowerShell-approved verbs in names; exported entry points (e.g., `Invoke-DomainSecurityBaseline`) belong in the module's `Public\` folder and call private helpers.
- Keep the DomainSecurityAuditor layout consistent: `Public\`, `Private\`, `Tests\`, `Examples\`, `Output\`, and `Logs\`. Wrapper scripts stored in `Examples\` must only import the module and call exported commands.
- Maintain a `DomainSecurityAuditor.psd1` manifest with accurate metadata, `RootModule`, and `RequiredModules` so consumers understand the supported entry points.
- Parameterize scripts with defaults, type validation, and safe fallbacks.
- Include comment-based help and the standard header template (see below).
- Implement `try / catch / finally` with centralized logging.
- Log all major actions to `Logs\` and optionally output reports to `Output\`.
- Log filenames must be timestamped and follow pruning/retention rules.
- Reuse logic via private module functions to avoid duplication; do not copy/paste script blocks when a helper would suffice.
- Detect required dependencies and, if any are missing, attempt to install them by default. If the `-SkipDependencies` switch is specified, do not attempt installation; instead, log a message listing the missing dependencies and noting that `-SkipDependencies` was used, then exit.
- Comply with **PSScriptAnalyzer** rules.
- Use **Pester 5+** for unit-testable logic; keep tests in `Tests\`, import the DomainSecurityAuditor module once per file, and rely on `InModuleScope` to exercise private helpers.
- Avoid long paths — keep script and output paths under **180 characters**.
- Assume non-interactive, non-GUI, privileged shell execution.
- Use `#region` / `#endregion` blocks for clear logical grouping (e.g., `#region Parameters`, `#region PublicFunctions`, `#region PrivateHelpers`, `#region Cleanup`). Keep nesting shallow and labels descriptive so module files remain readable.
- Employ **parameter splatting** when a cmdlet call uses three or more parameters or when the same parameter set recurs. Keep each splat hashtable local to the script—declare it immediately above the invocation or group it in a local `#region SplatDefinitions`. Do **not** centralize splats across multiple scripts.

### Transcription Logging

```powershell
$TranscriptPath = Join-Path -Path "$PSScriptRoot\Logs" -ChildPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_Transcript.log"
Start-Transcript -Path $TranscriptPath -Append
```

Stop the transcript in `finally` or `#region Cleanup` with:

```powershell
Stop-Transcript
```

> Only the top-level orchestrator (module entry point or CLI wrapper) should start/stop transcripts so that importing the module into CI/CD does not spawn nested transcripts. Internal helpers must accept a logger/transcript path instead of calling `Start-Transcript`. Transcripts are stored in `Logs\` (same `<RetentionCount>` policy as other logs), and callers should be able to override the log/output roots through parameters.

---

## Additional Script Requirements (Internal Standards)

- Every exported module command must expose a `-DryRun` (or `SupportsShouldProcess`) switch and a `-ShowProgress` switch so behavior remains consistent when called directly or via wrapper scripts.
- Provide usage examples, either in comment-based help or a README-adjacent example block.
- Use descriptive, self-explanatory variable names — avoid single-letter or ambiguous loop/control variables.
- Add inline comments explaining non-obvious logic.
- Do not use `Read-Host`, GUI prompts, or write outside the `Output\` structure.
- Ensure long-term maintainability, auditability, and reuse across the codebase.
- Provide progress feedback (`Write-Progress`) for loops likely to exceed ~5 seconds or 50 items; respect a `-ShowProgress` switch (`$true` by default) to silence output in pipelines.
- Request unbounded result sets by default (e.g., `-ResultSize Unlimited`, `-All`, or module-specific parameters); only apply smaller caps when explicitly documented and implement paging if the provider enforces a hard limit.
- Version the module semantically; update the `.psd1` `ModuleVersion` and `ReleaseNotes` for every baseline or report schema change so CI/CD consumers can pin compatible releases.

> ⚠️ This best-practice list is **not exhaustive**. Where applicable, follow authoritative sources such as Microsoft Learn, vendor KBs, and community standards (e.g., *PS Style Guide*).

---

## Standard Comment Block Template

```powershell
<#
.SYNOPSIS
    <Short summary of what the DomainSecurityAuditor module provides>
.DESCRIPTION
    <Detailed description of module scope, key entry points, and integration paths>
.REQUIRES
    Modules: DomainDetective, PSWriteHTML, Pester, PSScriptAnalyzer
.NOTES
    Module: DomainSecurityAuditor
    Author: <Author Name>
    Date: <MM/DD/YYYY>
    Version: <ModuleVersion>
    Requestor: <Requestor Name>
    Purpose: <Why the module exists>

Release Notes:
      <ModuleVersion> - <Date> - <Change summary>

Resources:
      - <Links to documentation or references>
#>
```

```powershell
<#
.SYNOPSIS
    <Short summary of what the exported function does>
.DESCRIPTION
    <Detailed description of the function, assumptions, and DSA workflows>
.PARAMETER Domain
    <Describe the parameter; repeat for each parameter>
.PARAMETER SkipDependencies
    Bypass automatic module installation; logs missing dependencies and exits early.
.PARAMETER DryRun
    Simulate the action without making changes.
.PARAMETER ShowProgress
    Toggle `Write-Progress` output.
.EXAMPLE
    Invoke-DomainSecurityBaseline -Domain "example.com" -DryRun
    Runs baseline tests without persisting artifacts.
.OUTPUTS
    PSCustomObject describing compliance results.
.NOTES
    Author: <Author Name>
    Date: <MM/DD/YYYY>
    Version: <Function version>
    Purpose: <Why the function exists>

Revision History:
      x.x - <Date> - <Change summary>

Known Issues:
      - <Any current limitations>

Resources:
      - <Links to documentation or references>
#>
```
