# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-11-22

### Changed

- **BREAKING:** Rename entry point to `Invoke-DomainSecurityAuditor`
- Align report title/filenames to "Domain Security Auditor" with timestamp appended

## [0.1.2] - 2025-11-21

### Changed

- **BREAKING:** Default output now writes a summary instead of full object
- Add `-PassThru` parameter to return full result object
- Capture DomainDetective warnings in output

## [0.1.1] - 2025-11-20

### Added

- CSV and CLI classification overrides with validation

## [0.1.0] - 2025-11-16

### Added

- Initial scaffolding of module structure
- Public entry point stub (`Invoke-DomainSecurityAuditor`)

[Unreleased]: https://github.com/thetechgy/DomainSecurityAuditor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/thetechgy/DomainSecurityAuditor/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/thetechgy/DomainSecurityAuditor/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/thetechgy/DomainSecurityAuditor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thetechgy/DomainSecurityAuditor/releases/tag/v0.1.0
