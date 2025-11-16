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
- Use **Pester 5+** for unit-testable logic; keep tests in `Tests\`.
- Avoid long paths — keep script and output paths under **180 characters**.
- Assume non-interactive, non-GUI, privileged shell execution.
- Use `#region` / `#endregion` blocks for clear logical grouping (e.g., `#region Parameters`, `#region MainProcess`, `#region Cleanup`). Keep nesting shallow and labels descriptive.
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

> Transcripts are stored in `Logs\` and follow the same `<RetentionCount>` policy as standard logs.

---

## Additional Script Requirements (Internal Standards)

- Include a `-DryRun` switch in every script to simulate actions without applying changes.
- Provide usage examples, either in comment-based help or a README-adjacent example block.
- Use descriptive, self-explanatory variable names — avoid single-letter or ambiguous loop/control variables.
- Add inline comments explaining non-obvious logic.
- Do not use `Read-Host`, GUI prompts, or write outside the `Output\` structure.
- Ensure long-term maintainability, auditability, and reuse across the codebase.
- Provide progress feedback (`Write-Progress`) for loops likely to exceed ~5 seconds or 50 items; respect a `-ShowProgress` switch (`$true` by default) to silence output in pipelines.
- Request unbounded result sets by default (e.g., `-ResultSize Unlimited`, `-All`, or module-specific parameters); only apply smaller caps when explicitly documented and implement paging if the provider enforces a hard limit.

> ⚠️ This best-practice list is **not exhaustive**. Where applicable, follow authoritative sources such as Microsoft Learn, vendor KBs, and community standards (e.g., *PS Style Guide*).

---

## Standard Comment Block Template

```powershell
<#
.SYNOPSIS
    <Short summary of what the script does>
.DESCRIPTION
    <Detailed description of functionality and use case>
.PARAMETER <ParameterName>
    <Description of what this parameter does>
.NOTES
    Author: <Author Name>
    Date: <MM/DD/YYYY>
    Version: <Version Number>
    Requestor: <Requestor Name>
    Purpose: <Why the script exists>

Revision History:
      x.x - <Date> - <Change summary>

Future Enhancements:
      - <Optional planned improvements>

Known Issues:
      - <Any current limitations>

Resources:
      - <Links to documentation or references>
#>
```
