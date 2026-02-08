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
    && mkdir -p "/opt/microsoft/powershell/${PS_VERSION}" \
    && curl -fsSL -o /tmp/powershell.tgz \
    "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz" \
    && tar -xzf /tmp/powershell.tgz -C "/opt/microsoft/powershell/${PS_VERSION}" \
    && rm -f /tmp/powershell.tgz \
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
    && mkdir -p /usr/local/nvm \
    && chown -R vscode:vscode /usr/local/nvm \
    && mkdir -p /etc/profile.d \
    && printf '%s\n' \
    'export NVM_DIR=/usr/local/nvm' \
    '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"' \
    'export PATH="$HOME/.local/bin:$PATH"' \
    > /etc/profile.d/00-devcontainer-paths.sh \
    && su -s /bin/sh vscode -c ' \
    export NVM_DIR=/usr/local/nvm; \
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash; \
    . "$NVM_DIR/nvm.sh"; \
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
