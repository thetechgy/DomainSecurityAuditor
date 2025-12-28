# DomainSecurityAuditor — Agent Guidelines

> **For AI coding assistants** (Claude Code, Codex, Copilot, etc.) working in this repo.

---

## Quick Reference

| Task | Command |
|------|---------|
| Run all tests | `Invoke-Pester -Path ./Tests` |
| Lint all scripts | `Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1` |
| Import module | `Import-Module ./DomainSecurityAuditor.psd1 -Force` |
| Run auditor | `Invoke-DomainSecurityAuditor -Domain 'example.com'` |
| Search code | `rg "pattern"` (not `grep`) |
| Find files | `fd name` (not `find`) |

---

## Project Context

**What this is:** A PowerShell 7+ module that audits domain/email security (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) using [DomainDetective](https://github.com/EvotecIT/DomainDetective) for data and Pester for testing, outputting HTML reports.

**Key entry points:**
- `Invoke-DomainSecurityAuditor` — Main orchestrator (Public/)
- `Get-DSABaselineProfile` — Retrieve baseline configs
- `New-DSABaselineProfile` — Create custom baselines
- `Test-DSABaselineProfile` — Validate baseline configs

**Dependencies:** DomainDetective, Pester 5+, PSScriptAnalyzer

---

## File Structure

```
DomainSecurityAuditor/
├── Public/          # Exported functions (user-facing API)
├── Private/         # Internal helpers (not exported)
├── Tests/           # Pester test files
├── Configs/         # Baseline configs and reference data
├── Examples/        # Wrapper scripts and sample reports
├── Output/          # Generated reports (Reports/, Raw/)
├── Logs/            # Timestamped logs and transcripts
├── .github/         # CI workflows (Pester, PSScriptAnalyzer)
└── DomainSecurityAuditor.psd1  # Module manifest
```

---

## DO NOT

- **Do not** use `grep`, `egrep`, or `find` — use `rg` and `fd` instead
- **Do not** use `Read-Host` or GUI prompts — assume non-interactive execution
- **Do not** write outside `Output/` or `Logs/` directories
- **Do not** skip `Invoke-ScriptAnalyzer` before commits
- **Do not** mix formatting changes with behavioral changes in commits
- **Do not** use `--pre`, `-z`, `--search-zip` flags with ripgrep
- **Do not** parse JSON with regex — use `jaq` or `jq`
- **Do not** start transcripts in helper functions (only in entry points)
- **Do not** commit files with paths > 180 characters

---

## CLI Tooling (Rust-First)

These standards apply whenever an agent interacts with the **DomainSecurityAuditor** repo via a shell (local or remote). The goal is: **fast, safe, Rust-first tooling**.

### ripgrep (`rg`) — Content Search

```bash
rg "pattern"                    # Basic search
rg -n -A 3 -B 3 "pattern"       # With line numbers and context
rg -t powershell "function"     # Filter by language
rg --files                      # List tracked files
```

**Constraints:** Never use `--pre`, `-z`, `--search-zip`, `--hostname-bin`. Quote untrusted input. Cap output to ~250 lines unless explicitly needed.

### fd — File Discovery

```bash
fd name                         # Find by name
fd name src                     # Restrict scope
fd -e ps1                       # Match extension
fd -0 pattern | xargs -0 cmd -- # Safe piping for destructive ops
```

On Debian/Ubuntu/WSL, use `fdfind` (alias to `fd`).

### jaq/jq — JSON Processing

```bash
jaq '.key' file.json            # Extract field
jaq '.items[] | {id, name}'     # Transform array
pwsh -c '... | ConvertTo-Json' | jaq '.'  # From PowerShell
```

Prefer `jaq` (Rust); fall back to `jq` if unavailable. Never parse JSON with grep/regex.

---

## PowerShell Standards

### Module Structure

| Folder | Purpose |
|--------|---------|
| `Public/` | Exported functions (user API) — use approved verbs |
| `Private/` | Internal helpers — not exported |
| `Tests/` | Pester 5+ tests with `InModuleScope` for private helpers |
| `Examples/` | Wrapper scripts — import module, call exported commands only |
| `Configs/` | Baseline configurations and reference data |

### Coding Conventions

- **Parameters:** Defaults, type validation, safe fallbacks; use splatting for 3+ params
- **Error handling:** `try/catch/finally` with centralized `Write-DSALog`
- **Regions:** Use `#region`/`#endregion` for logical grouping (shallow nesting)
- **Dependencies:** Check via `Test-DSADependency`; respect `-SkipDependencies` switch
- **Progress:** Use `Write-Progress` for loops >5s or >50 items; respect `-ShowProgress`
- **Paths:** Keep under 180 characters

### Transcription (Entry Points Only)

```powershell
# Start (in entry point only)
$TranscriptPath = Join-Path "$PSScriptRoot\Logs" "$(Get-Date -Format 'yyyyMMdd_HHmmss')_Transcript.log"
Start-Transcript -Path $TranscriptPath -Append

# Stop (in finally/cleanup)
Stop-Transcript
```

> Only top-level orchestrators start/stop transcripts. Helpers accept logger paths as parameters.

### Pre-Commit Checklist

Before every commit:

```powershell
# Both must pass
Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1
Invoke-Pester -Path ./Tests
```

### Additional Requirements

- Honor `.editorconfig` for formatting consistency
- Exported commands must include `-ShowProgress` switch
- Use descriptive variable names (no single-letter vars)
- Add inline comments for non-obvious logic
- Use semantic versioning; update `.psd1` for schema changes
- GitHub Actions workflows must use `step-security/harden-runner`

---

## Common Pitfalls

| Issue | Solution |
|-------|----------|
| Tests fail in CI but pass locally | Import module with `-Force`; check for stale module state |
| PSScriptAnalyzer inconsistencies | Use `-Settings ./PSScriptAnalyzerSettings.psd1` explicitly |
| Transcript already running | Only start in entry points, never in helpers |
| Classification not detected | Provide explicit `-Classification` or CSV column override |
| DKIM selectors missing | Use `-DkimSelector` or CSV `DKIMSelectors` column |
| Path too long errors | Keep total path < 180 chars; use shorter output names |

---

## PR Checklist

Before opening a PR that changes functionality, baselines, or remediation guidance:

- [ ] Update `README.md` to reflect new behavior
- [ ] Regenerate `Examples/domain_security_auditor_report.html` if report schema changed
- [ ] Add/adjust Pester tests in `Tests/`
- [ ] Cite authoritative sources (RFCs, M3AAWG, dmarc.org) in code comments

---

## Commit & PR Standards

### Commit Format

```
<type>(<scope>): <imperative summary>  # max 72 chars

[Optional body with details]
Refs #123
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`
**Scopes:** `Public`, `Private`, `Tests`, `Examples`, `Docs`, `repo`

### Commit Hygiene

- Small, logically grouped commits
- Separate formatting from behavioral changes
- Every commit must pass PSScriptAnalyzer and Pester

### PR Requirements

- Title in imperative voice (e.g., "Add transcript logging")
- Describe **why** and **how** it affects operators
- Include testing evidence (commands run, environments tested)
- Stay focused — no unrelated features bundled

---

## Comment Block Templates

<details>
<summary>Module Header Template</summary>

```powershell
<#
.SYNOPSIS
    <Short summary>
.DESCRIPTION
    <Detailed description of module scope and entry points>
.REQUIRES
    Modules: DomainDetective, Pester, PSScriptAnalyzer
.NOTES
    Module: DomainSecurityAuditor
    Author: <Author>
    Date: <MM/DD/YYYY>
    Version: <ModuleVersion>
    Purpose: <Why the module exists>

Release Notes:
    <Version> - <Date> - <Change summary>
#>
```

</details>

<details>
<summary>Function Header Template</summary>

```powershell
<#
.SYNOPSIS
    <Short summary>
.DESCRIPTION
    <Detailed description of function behavior>
.PARAMETER Domain
    The domain(s) to audit.
.PARAMETER SkipDependencies
    Bypass automatic module installation.
.PARAMETER SkipReportLaunch
    Suppress auto-launch of HTML report (CI-friendly).
.PARAMETER ShowProgress
    Toggle Write-Progress output.
.EXAMPLE
    Invoke-DomainSecurityAuditor -Domain "example.com"
.OUTPUTS
    PSCustomObject with compliance results.
.NOTES
    Author: <Author>
    Version: <Version>
#>
```

</details>

---

## Appendix: Tool Installation

<details>
<summary>Debian/Ubuntu/WSL</summary>

```bash
sudo apt update && sudo apt install -y ripgrep fd-find jq
echo 'alias fd=fdfind' >> ~/.bashrc
# Optional: cargo install jaq
```

</details>

<details>
<summary>macOS (Homebrew)</summary>

```bash
brew install ripgrep fd jq jaq
```

</details>

<details>
<summary>PowerShell Modules</summary>

```powershell
Install-Module -Name DomainDetective, Pester, PSScriptAnalyzer -Scope CurrentUser
```

</details>
