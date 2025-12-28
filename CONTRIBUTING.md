# Contributing to DomainSecurityAuditor

Thank you for your interest in contributing to DomainSecurityAuditor!

## Getting Started

1. **Fork and clone** the repository
2. **Install dependencies:**
   ```powershell
   Install-Module -Name DomainDetective, Pester, PSScriptAnalyzer -Scope CurrentUser
   ```
3. **Import the module:**
   ```powershell
   Import-Module ./DomainSecurityAuditor.psd1 -Force
   ```

## Development Workflow

1. **Branch from `develop`** — All work should branch from `develop`, not `main`
2. **Make your changes** — Follow the coding standards in [AGENTS.md](AGENTS.md)
3. **Test your changes:**
   ```powershell
   Invoke-Pester -Path ./Tests
   Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1
   ```
4. **Commit with conventional format:**
   ```
   <type>(<scope>): <description>
   ```
   Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`

5. **Open a pull request** to `develop`

## Coding Standards

See [AGENTS.md](AGENTS.md) for detailed coding standards including:

- PowerShell module structure (`Public/`, `Private/`, `Tests/`)
- Naming conventions (approved verbs, descriptive variables)
- Error handling patterns (`try/catch/finally`)
- Documentation requirements (comment-based help)
- Testing requirements (Pester 5+)

## Testing Requirements

All contributions must:

- [ ] Pass `Invoke-Pester` with no failures
- [ ] Pass `Invoke-ScriptAnalyzer` with the repo settings
- [ ] Include tests for new functionality
- [ ] Maintain or improve code coverage

## Pull Request Process

1. Ensure all tests pass locally
2. Update documentation if behavior changes
3. Fill out the PR template completely
4. Link any related issues
5. Wait for CI checks to pass
6. Address review feedback

## Questions?

Open a [discussion](https://github.com/thetechgy/DomainSecurityAuditor/discussions) or check the [README](README.md) for more information.
