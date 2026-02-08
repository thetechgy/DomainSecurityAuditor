# syntax=docker/dockerfile:1
FROM cgr.dev/chainguard/wolfi-base:latest

ARG PS_VERSION=7.5.4
ARG TARGETARCH=amd64
ARG ENABLE_AI_TOOLS=false

# -----------------------------
# Base OS packages (always needed)
# -----------------------------
RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    openssh-client \
    icu-libs \
    libstdc++ \
    libgcc \
    && update-ca-certificates

# -----------------------------
# Install PowerShell
# -----------------------------
RUN case "${TARGETARCH}" in \
    amd64) PS_ARCH="x64" ;; \
    arm64) PS_ARCH="arm64" ;; \
    *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; \
    esac \
    && PS_TARBALL="powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz" \
    && mkdir -p "/opt/microsoft/powershell/${PS_VERSION}" \
    && curl -fsSL -o "/tmp/${PS_TARBALL}" \
    "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/${PS_TARBALL}" \
    && curl -fsSL -o /tmp/hashes.sha256 \
    "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/hashes.sha256" \
    && PS_EXPECTED_SHA256="" \
    && while IFS= read -r checksum_line; do \
        case "${checksum_line}" in \
            *"${PS_TARBALL}"*) PS_EXPECTED_SHA256="${checksum_line%% *}"; break ;; \
        esac; \
    done < /tmp/hashes.sha256 \
    && [ -n "${PS_EXPECTED_SHA256}" ] \
    && PS_EXPECTED_SHA256="$(printf '%s' "${PS_EXPECTED_SHA256}" | tr '[:upper:]' '[:lower:]')" \
    && set -- $(sha256sum "/tmp/${PS_TARBALL}") \
    && PS_ACTUAL_SHA256="$1" \
    && if [ "${PS_ACTUAL_SHA256}" != "${PS_EXPECTED_SHA256}" ]; then \
        echo "Checksum mismatch for ${PS_TARBALL}" >&2; \
        echo "Expected: ${PS_EXPECTED_SHA256}" >&2; \
        echo "Actual:   ${PS_ACTUAL_SHA256}" >&2; \
        exit 1; \
    fi \
    && tar -xzf "/tmp/${PS_TARBALL}" -C "/opt/microsoft/powershell/${PS_VERSION}" \
    && rm -f "/tmp/${PS_TARBALL}" /tmp/hashes.sha256 \
    && chmod 755 "/opt/microsoft/powershell/${PS_VERSION}/pwsh" \
    && chmod -R a+rX "/opt/microsoft/powershell/${PS_VERSION}" \
    && mkdir -p /usr/local/bin \
    && ln -sf "/opt/microsoft/powershell/${PS_VERSION}/pwsh" /usr/local/bin/pwsh \
    && ln -sf "/opt/microsoft/powershell/${PS_VERSION}/pwsh" /usr/bin/pwsh \
    && pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'

# -----------------------------
# PowerShell tooling (always needed)
# -----------------------------
RUN pwsh -NoLogo -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module Pester -Scope AllUsers -Force; \
    Install-Module PSScriptAnalyzer -Scope AllUsers -Force; \
    Import-Module Pester; \
    Import-Module PSScriptAnalyzer; \
    "

# -----------------------------
# Non-root user for devcontainers
# -----------------------------
RUN adduser -D -u 1000 vscode \
    && mkdir -p /home/vscode \
    && chown -R vscode:vscode /home/vscode

# -----------------------------
# AI tooling + CLIs (optional)
# -----------------------------
RUN if [ "${ENABLE_AI_TOOLS}" = "true" ]; then \
    echo 'Installing AI assist tooling + Node (nvm) + Codex + Claude...' && \
    apk add --no-cache \
    nvm \
    ripgrep \
    fd \
    jq \
    yq \
    patch \
    diffutils \
    sed \
    gawk \
    coreutils \
    findutils \
    tree \
    gzip \
    unzip \
    xz \
    && mkdir -p /etc/profile.d \
    && printf '%s\n' \
    'export NVM_DIR="$HOME/.nvm"' \
    'if [ -s /usr/share/nvm/init-nvm.sh ]; then . /usr/share/nvm/init-nvm.sh; elif [ -s /usr/share/nvm/nvm.sh ]; then . /usr/share/nvm/nvm.sh; elif [ -s /usr/lib/nvm/nvm.sh ]; then . /usr/lib/nvm/nvm.sh; fi' \
    '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"' \
    'export PATH="$HOME/.local/bin:$PATH"' \
    > /etc/profile.d/00-devcontainer-paths.sh \
    && su -s /bin/bash vscode -c ' \
    set -eu; \
    export NVM_DIR="$HOME/.nvm"; \
    if [ -s /usr/share/nvm/init-nvm.sh ]; then . /usr/share/nvm/init-nvm.sh; \
    elif [ -s /usr/share/nvm/nvm.sh ]; then . /usr/share/nvm/nvm.sh; \
    elif [ -s /usr/lib/nvm/nvm.sh ]; then . /usr/lib/nvm/nvm.sh; \
    else echo "nvm init script not found" >&2; exit 1; fi; \
    nvm install --lts; \
    nvm alias default "lts/*"; \
    node --version; npm --version; \
    npm i -g @openai/codex; \
    codex --version || true; \
    mkdir -p "$HOME/.local/bin"; \
    curl -fsSL https://claude.ai/install.sh | bash; \
    command -v claude >/dev/null 2>&1 && claude --version || true; \
    ' \
    ; else \
    echo 'AI tooling disabled (ENABLE_AI_TOOLS=false)'; \
    fi

USER vscode
WORKDIR /workspaces
