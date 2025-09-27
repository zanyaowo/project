ARG BASE_IMAGE
ARG RUST_VERSION
ARG PYTHON_VERSION
ARG NODE_VERSION
ARG LLVM_VERSION

FROM ${BASE_IMAGE} AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    curl \
    wget \
    git \
    ca-certificates \
    # system tools
    sudo \
    vim \
    jq \
    unzip \
    # network tools
    net-tools \
    iputils-ping \
    tcpdump \
    # dev tools
    strace \
    ltrace \
    gdb \
    # delete chache
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean 

# 設定統一的開發環境
FROM base AS dev-env

ARG RUST_VERSION
ARG PYTHON_VERSION
ARG NODE_VERSION
ARG LLVM_VERSION

ARG USERNAME=vscode
ARG USER_UID=2000
ARG USER_GID=$USER_UID

# Create user and group
RUN groupadd --gid $USER_GID $USERNAME 2>/dev/null || true \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME 2>/dev/null || true

# Stage1: Install Rust and eBPF tools
# Align with devcontainer.json mounts for cargo and target caches.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/workspace/target \
    PATH=/usr/local/cargo/bin:$PATH

# Create directories for Rust, set ownership for the non-root user.
# This ensures that both 'root' during build and 'vscode' later have necessary permissions.
RUN mkdir -p $RUSTUP_HOME $CARGO_HOME $CARGO_TARGET_DIR /workspace \
    && chown -R $USERNAME:$USER_GID $RUSTUP_HOME $CARGO_HOME $CARGO_TARGET_DIR /workspace

# Install Rust toolchain as root
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal

# Install system dependencies for eBPF
RUN apt-get update && apt-get install -y --no-install-recommends \
    # LLVM/Clang for eBPF compilation
    clang-${LLVM_VERSION} \
    llvm-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev \
    # eBPF libraries
    libbpf-dev \
    libbpf1 \
    # Kernel headers (generic version for container compatibility)
    linux-headers-generic \
    linux-libc-dev \
    # Dependencies for cargo tools
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    libelf-dev \
    # eBPF tools & other dev tools
    linux-tools-common \
    linux-tools-generic

# Install essential Rust tools and eBPF-specific tooling
# This runs as root, but installs tools into the shared $CARGO_HOME
RUN rustup component add rustfmt clippy rust-analyzer \
    && rustup target add x86_64-unknown-linux-musl \
    && cargo install \
        cargo-watch \
        cargo-audit \
        bindgen-cli \
        cargo-deny \
        cargo-expand \
        bpf-linker \
    # 清除chache
    && rm -rf $CARGO_HOME/registry/* \
    && rm -rf $CARGO_HOME/git/*

# Set up eBPF environment variables
ENV CLANG_PATH=/usr/bin/clang-${LLVM_VERSION}
ENV LLC_PATH=/usr/bin/llc-${LLVM_VERSION}
ENV BPF_CLANG=clang-${LLVM_VERSION}

# --- Stage2: Python Development ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        python${PYTHON_VERSION} \
        python${PYTHON_VERSION}-dev \
        python${PYTHON_VERSION}-venv \
        python3-pip

# Create symlinks for python/pip
RUN ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3 \
    && ln -sf /usr/bin/python3 /usr/bin/python

# --- Stage 3: Node.js Development ---
# Install Node.js with specific version
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION%.*}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs

# Install global npm packages
RUN npm install -g \
    yarn \
    pnpm \
    @angular/cli \
    typescript \
    ts-node \
    nodemon

# ---stage 4: 安裝額外工具 ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Database tools
    # postgresql-client \
    # redis-tools \
    \
    # Container tools
    docker-compose \
    # Monitoring tools
    htop \
    iotop \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean

# Fix permissions for non-root user
RUN chown -R $USERNAME:$USER_GID $RUSTUP_HOME $CARGO_HOME

# --- Final Stage: Unified Development Environment ---
FROM dev-env AS final-dev-env

ARG USERNAME

# create venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"


# Switch to vscode user and set up workspace
USER $USERNAME
WORKDIR /workspace

# ---第二步: copy dependence file then install

# 複製rust dependence
COPY --chown=${USERNAME}:${USERNAME} service/firewall/Cargo.toml ./service/firewall/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-ebpf/Cargo.toml ./service/firewall/firewall-ebpf/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall/Cargo.toml ./service/firewall/firewall/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-common/Cargo.toml ./service/firewall/firewall-common/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/xtask/Cargo.toml ./service/firewall/xtask/

# 複製 main.rs and lib.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-ebpf/src/main.rs ./service/firewall/firewall-ebpf/src/main.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall/src/main.rs ./service/firewall/firewall/src/main.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-common/src/lib.rs ./service/firewall/firewall-common/src/lib.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/xtask/src/main.rs ./service/firewall/xtask/src/main.rs

# 複製python requirement
COPY --chown=${USERNAME}:${USERNAME} service/model/requirements.txt ./service/model/


# 複製前端dependence (未開發)
# COPY --chown=${USERNAME}:${USERNAME} /web/frontend/packages.json /web/frontend/packages-lock.json* /web/ 


# --- 第三步: 安裝 ---
# 安裝rust dependence
WORKDIR /workspace/service/firewall
RUN cargo fetch

# 安裝python requirements
WORKDIR /workspace/service/model
RUN pip install -r requirements.txt

# 安裝 node package
# WORKDIR /workspace/web
# RUN npm i

# 切換回根目錄
WORKDIR /workspace

# 複製所有檔案到docker的root
COPY --chown=${USERNAME}:${USERNAME} . .

# --- 第四步: 環境設定 -- 
RUN mkdir -p /home/$USERNAME/.config \
    && mkdir -p /home/$USERNAME/.cache \
    && mkdir -p /home/$USERNAME/workspace

# Set up shell environment
COPY --chown=$USER_UID:$USER_GID .devcontainer/bashrc /home/$USERNAME/.bashrc
COPY --chown=$USER_UID:$USER_GID .devcontainer/gitconfig /home/$USERNAME/.gitconfig

# Set up environment variables for development
# Note: CARGO_HOME, CARGO_TARGET_DIR, and PATH are inherited from the 'dev-env' stage
# and are aligned with the devcontainer.json mounts.
ENV RUST_BACKTRACE=full
ENV RUST_LOG=debug
ENV CARGO_INCREMENTAL=1
ENV PYTHONPATH="/workspace/service/model:$PYTHONPATH"

# Default command
CMD ["/bin/bash"]