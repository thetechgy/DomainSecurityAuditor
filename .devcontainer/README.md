# Development Container (`.devcontainer/`)

## Overview

This directory defines a reusable VS Code devcontainer for PowerShell development on a Wolfi base image.

Primary goals:

- Consistent PowerShell tooling across machines
- Fast onboarding with minimal host setup
- Reasonable hardening for development workloads without breaking day-to-day workflows

## Current Defaults

- Base image: `cgr.dev/chainguard/wolfi-base:latest`
- PowerShell version arg: `PS_VERSION=7.5.4`
- Core modules: `Pester`, `PSScriptAnalyzer`
- Optional AI tooling: disabled by default (`ENABLE_AI_TOOLS=false`)
- Runtime user: `vscode` (non-root)

## Security and Reliability Controls

The current config includes the following controls:

- Non-root development user (`remoteUser: vscode`)
- UID/GID alignment enabled (`updateRemoteUserUID: true`)
- `no-new-privileges` enabled in `devcontainer.json`
- Telemetry opt-out environment variables for .NET and PowerShell
- PowerShell tarball SHA-256 verification before extraction
- Strict shell behavior (`set -euo pipefail`) in the optional AI tooling setup block
- Build context locked down via `.dockerignore`
- OCI image labels for title/description/source/license/revision/created metadata

## Post-Create Validation

`postCreateCommand` validates tool availability and prints versions for:

- `pwsh`
- `Pester`
- `PSScriptAnalyzer`

## Files in This Directory

- `devcontainer.json`: Devcontainer runtime settings, security options, env vars, post-create validation
- `Dockerfile`: Image build logic and tooling installation
- `.dockerignore`: Restricts build context to devcontainer files
- `README.md`: This document

## Build Arguments

Supported Docker build args:

- `PS_VERSION` (default: `7.5.4`)
- `ENABLE_AI_TOOLS` (default: `false`)
- `TARGETARCH` (must be provided by BuildKit/devcontainer tooling)
- `BUILDKIT_INLINE_CACHE` (default: `1`, consumed to avoid noisy build warnings)
- `IMAGE_TITLE`
- `IMAGE_DESCRIPTION`
- `IMAGE_SOURCE`
- `IMAGE_LICENSES`
- `VCS_REF`
- `BUILD_DATE`

Notes:

- `TARGETARCH` has no fallback default by design. Builds fail fast if it is missing.
- The current image policy intentionally tracks latest Wolfi base and latest package/module versions at build time.

## Podman + VS Code Setup

This repo is tested with Podman on Linux.

Minimum VS Code setting:

```json
{
  "dev.containers.dockerPath": "podman"
}
```

Optional if you use compose-based devcontainers:

```json
{
  "dev.containers.dockerComposePath": "podman-compose"
}
```

## Optional AI Tooling

When `ENABLE_AI_TOOLS=true`, the image installs:

- `nvm` (from Wolfi `apk`)
- latest LTS Node.js via `nvm`
- `@openai/codex`
- Claude Code installer
- common CLI helpers (`ripgrep`, `fd`, `jq`, `yq`, `patch`, `diffutils`, `tree`, etc.)

This path is optional and is not required for PowerShell module development.

## Expected Log Noise (Can Be Ignored)

You may still see these warnings from VS Code/Podman internals during container startup:

- `SHELL is not supported for OCI image format ...`
- `Ignoring option 'skip-requirements-check' ...`

These come from generated helper images or VS Code server internals, not from functional issues in this repo's devcontainer configuration.

## Usage

1. Open the repository in VS Code.
2. Run `Dev Containers: Reopen in Container`.
3. Wait for the first build to complete.
4. Confirm post-create output includes `pwsh`, `Pester`, and `PSScriptAnalyzer` version lines.

## Non-Goals

This devcontainer is for development convenience and consistency. It is not intended as:

- A production runtime image
- A hardened service container profile
- A published, immutable release image
