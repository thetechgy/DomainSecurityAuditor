# Development Container (`.devcontainer/`)

## What this is

This directory defines a **VS Code Development Container** (“devcontainer”) for PowerShell projects.

A devcontainer provides a **fully reproducible development environment** using containers instead of relying on whatever tools happen to be installed on a developer’s machine.

In short:

> Open the repo in VS Code → VS Code builds a container with **Podman** → you get a ready-to-use PowerShell + tooling environment.

No local setup scripts. No “works on my machine”.

---

## Why we use a devcontainer

This project targets:

* PowerShell 7.x development
* Pester-based testing
* PSScriptAnalyzer linting
* Optional AI-assisted tooling (Codex CLI, Claude Code)
* Cross-platform consistency

Using a devcontainer ensures:

* **Identical tooling versions** for all developers
* **Clean separation** from the host OS
* **No dependency drift** over time
* **Fast onboarding** for new contributors
* A foundation that can later evolve into CI/CD

You do **not** need deep container knowledge to use this.

---

## Container runtime

This project **intentionally uses Podman**, not Docker.

Reasons:

* Rootless-by-default security model
* Better alignment with enterprise Linux environments
* No Docker daemon requirement
* Works cleanly with modern Linux distributions

---

## What’s inside this devcontainer

### Base environment (always installed)

* **Wolfi base image** (Chainguard)

  * Minimal, secure, glibc-based
* **PowerShell** (version pinned via build arg)
* **Pester**
* **PSScriptAnalyzer**

These are required to build, test, and lint PowerShell projects.

### Optional AI tooling

When enabled at build time (`ENABLE_AI_TOOLS=true`):

* Node.js + npm (installed via `nvm`)
* OpenAI Codex CLI
* Claude Code CLI
* Developer utilities commonly used by AI tools:

  * `ripgrep`, `fd`
  * `jq`, `yq`
  * `diffutils`, `patch`
  * `sed`, `gawk`
  * `coreutils`, `findutils`
  * `tree`, `gzip`, `unzip`, `xz`

These tools **support AI-assisted workflows only**. They are not required to run the project itself.

---

## Files in this directory

### `devcontainer.json`

This is the **entry point** for VS Code.

It tells VS Code:

* How to build the container
* That **Podman** is the container engine
* Which user to run as
* Which shell to use (`pwsh`)
* What validation runs after creation

You typically only edit this file when:

* PowerShell versions change
* Tooling is added or removed
* Editor behavior needs adjustment

### `Dockerfile`

This defines the **actual container image**.

It installs:

* OS packages
* PowerShell
* PowerShell modules
* Optional AI tooling

All environment changes belong here — not in ad-hoc setup scripts.

---

## Configuring VS Code to use Podman (not Docker)

VS Code defaults to Docker. You must explicitly configure Podman.

### Step 1: Install Podman

Ensure Podman is installed and working:

```bash
podman version
```

### Step 2: Configure Dev Containers to use Podman

Open **VS Code Settings (JSON)** and ensure the following are set:

```json
{
  "dev.containers.dockerPath": "podman",
  "dev.containers.dockerComposePath": "podman-compose",
  "containers.dockerPath": "podman"
}
```

Notes:

* `podman-compose` is required for compatibility with the Dev Containers extension
* These settings are **per-user**, not stored in the repo

### Step 3: Verify

Run the command:

> **Dev Containers: Open Container Configuration File**

Then reopen the project using:

> **Dev Containers: Reopen in Container**

The build logs should clearly reference **Podman**, not Docker.

---

## How to use the devcontainer

1. Open the repository in VS Code
2. When prompted, choose **“Reopen in Container”**

   * Or `Ctrl+Shift+P` → *Dev Containers: Reopen in Container*
3. Wait for the container to build (first run takes a few minutes)

You will land in a PowerShell terminal **inside the container** with all tooling ready.

---

## What this is *not* (yet)

This devcontainer is **not**:

* A production runtime image
* A CI/CD pipeline
* Published to a container registry
* Optimized for minimal image size

Those are intentional non-goals for now.

---

## Future direction (intentionally deferred)

This setup is designed so that it can later:

* Be reused in CI pipelines
* Be prebuilt and cached
* Be published to a registry if needed

None of that complexity is required today.

---

## TL;DR

* This directory makes the project easy to work on
* Podman is required
* Tooling versions are pinned and consistent
* AI tools are optional but supported
* If VS Code opens, you can contribute
