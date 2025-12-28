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

**Local development:** DomainDetective source is available at `/mnt/c/Users/TravisMcDade/VSCode_Workspace/DomainDetective` for reference, debugging, or running DSA with the actual module.

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

## Agent Behavior Guidelines

These principles apply to all AI coding assistants working in this repository:

### Simplicity First

- **Avoid unnecessary complexity** — Only add abstraction, indirection, or advanced patterns when they provide concrete value or are specifically requested
- **Minimum viable implementation** — Solve the immediate problem without over-engineering for hypothetical future needs
- **Prefer clarity over cleverness** — Readable code is maintainable code; avoid premature optimization

### Scope Discipline

- **Stay focused** — Address only what's asked; don't bundle unrelated improvements
- **Ask before expanding** — If a change seems to require broader refactoring, confirm with the user first
- **Incremental changes** — Small, testable commits over large sweeping changes

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

### Additional Requirements

- Honor `.editorconfig` for formatting consistency
- Exported commands must include `-ShowProgress` switch
- Use descriptive variable names (no single-letter vars)
- Add inline comments for non-obvious logic
- Use semantic versioning; update `.psd1` for schema changes
- GitHub Actions workflows must use `step-security/harden-runner`

---

## Security Considerations

### Coding Practices

- **Never hardcode credentials** — Use environment variables or secure vaults for secrets
- **Validate untrusted input** — Sanitize domain names, file paths, and user-provided parameters
- **Avoid command injection** — Use parameterized commands; never interpolate user input directly into shell strings
- **Minimize data exposure** — Logs should not contain sensitive data (API keys, tokens, credentials)
- **Fail securely** — Error messages should be informative for debugging but not leak implementation details

### Dependencies

- **Audit before adding** — Verify new dependencies are actively maintained and have no known vulnerabilities
- **Pin versions** — Use specific versions in manifests to prevent supply chain attacks
- **Keep updated** — Regularly update dependencies to patch security issues

### CI/CD

- **Use `step-security/harden-runner`** — All GitHub Actions workflows must include this
- **Limit permissions** — Use least-privilege principles for workflow tokens
- **No secrets in logs** — Ensure CI output doesn't expose sensitive values

---

## Branching

Create feature branches from `develop` (not `main`):

**When to use dedicated branches and PRs:**
- Major features or significant new functionality
- Breaking changes or schema modifications
- Changes touching multiple files or subsystems
- Refactoring with risk of regression

**When direct commits to `develop` may be acceptable:**
- Trivial fixes (typos, formatting, minor doc updates)
- Single-file changes with low risk

**PR workflow:** All PRs target `develop` first; `main` only receives merges from `develop` (no direct PRs to main).

```bash
git checkout develop
git pull origin develop
git checkout -b <type>/<short-description>
```

**Branch naming:** `<type>/<kebab-case-description>`

| Type | Purpose |
|------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `refactor/` | Code restructuring |
| `docs/` | Documentation only |
| `test/` | Test additions/changes |
| `chore/` | Maintenance tasks |

**Examples:** `feat/add-bimi-support`, `fix/dkim-selector-parsing`, `docs/update-readme`

---

## Commit Workflow

Follow these steps **in order** before every commit:

### Step 1: Sync with Remote

```bash
git pull origin develop
```

### Step 2: Validate Code Quality

```powershell
# PSScriptAnalyzer — must pass with no violations
Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1

# Pester — must pass with ≥70% code coverage
Invoke-Pester -Path ./Tests
```

### Step 3: Update Documentation (if applicable)

| Change Type | Required Updates |
|-------------|------------------|
| New/changed behavior | Update `README.md` |
| Report schema changes | Regenerate `Examples/domain_security_auditor_report.html` |
| New parameters/functions | Update function help blocks |
| Breaking changes | Mark clearly in CHANGELOG and README |

### Step 4: Update CHANGELOG.md

Add entry under `## [Unreleased]` section:

- **Added** — new features
- **Changed** — behavior modifications
- **Fixed** — bug fixes
- **Removed** — deprecated features removed
- **Security** — vulnerability fixes

### Step 5: Version Bump (for releases only)

When preparing a release:

1. Update version in `DomainSecurityAuditor.psd1` (ModuleVersion)
2. Move CHANGELOG entries from `[Unreleased]` to new version section
3. Update release notes in manifest if significant

### Step 6: Stage and Commit

```bash
git add -A
git commit -m "<type>(<scope>): <summary>"
```

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

Before opening a PR:

- [ ] All commits follow the commit workflow above
- [ ] CHANGELOG.md updated for all changes
- [ ] README.md reflects new behavior (if applicable)
- [ ] Example report regenerated (if schema changed)
- [ ] Pester tests added/updated for new functionality
- [ ] Citations added for authoritative sources (RFCs, M3AAWG)
- [ ] CI passes (Pester + PSScriptAnalyzer workflows)

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

---

## Related Documentation

| File | Purpose |
|------|---------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to this project |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
