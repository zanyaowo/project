ARG BASE_IMAGE=ubuntu:24.04
ARG RUST_VERSION=stable
ARG PYTHON_VERSION=3.12
ARG NODE_VERSION=20
ARG LLVM_VERSION=18

FROM ${BASE_IMAGE} AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# 合併所有 apt 操作以減少層數
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 基礎編譯工具
    gcc \
    libc6-dev \
    build-essential \
    curl \
    wget \
    git \
    ca-certificates \
    # 系統工具
    sudo \
    vim \
    jq \
    unzip \
    # 網路工具
    net-tools \
    iputils-ping \
    # 只保留必要的除錯工具
    gdb \
    # 清理
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

# 創建用戶
RUN groupadd --gid $USER_GID $USERNAME 2>/dev/null || true \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME 2>/dev/null || true

# 設定環境變數
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/workspace/target \
    PATH=/usr/local/cargo/bin:$PATH

# 合併所有開發環境安裝，減少映像層數
RUN mkdir -p $RUSTUP_HOME $CARGO_HOME $CARGO_TARGET_DIR /workspace \
    && chown -R $USERNAME:$USER_GID $RUSTUP_HOME $CARGO_HOME $CARGO_TARGET_DIR /workspace \
    # 安裝 Rust
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
       sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal \
    # 安裝系統依賴（一次性完成）
    && apt-get update && apt-get install -y --no-install-recommends \
        # eBPF 編譯工具
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        # eBPF 函式庫（最小化）
        libbpf-dev \
        # 核心開發標頭（只安裝必要的）
        linux-libc-dev \
        # Cargo 工具依賴
        pkg-config \
        libssl-dev \
        libelf-dev \
        # Python 環境
        python${PYTHON_VERSION} \
        python${PYTHON_VERSION}-dev \
        python${PYTHON_VERSION}-venv \
        python3-pip \
        # Node.js 依賴
        && curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION%.*}.x | bash - \
        && apt-get install -y --no-install-recommends nodejs \
    # 安裝最小化的 Rust 工具
    && rustup component add rustfmt clippy rust-analyzer \
    && rustup target add x86_64-unknown-linux-musl \
    && cargo install --locked \
        cargo-watch \
        bindgen-cli \
        bpf-linker \
    # 安裝最小化的 Node.js 全域套件
    && npm install -g --no-optional \
        typescript \
        ts-node \
    # Python 符號連結
    && ln -sf /usr/bin/python${PYTHON_VERSION} /usr/bin/python3 \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    # 徹底清理
    && rm -rf $CARGO_HOME/registry/* \
    && rm -rf $CARGO_HOME/git/* \
    && rm -rf /root/.cargo \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && npm cache clean --force \
    && rm -rf /tmp/* /var/tmp/* \
    && find /usr/share/doc -type f -delete \
    && find /usr/share/man -type f -delete

# 設定 eBPF 環境變數
ENV CLANG_PATH=/usr/bin/clang-${LLVM_VERSION} \
    LLC_PATH=/usr/bin/llc-${LLVM_VERSION} \
    BPF_CLANG=clang-${LLVM_VERSION}

# 修復權限
RUN chown -R $USERNAME:$USER_GID $RUSTUP_HOME $CARGO_HOME

# --- 最終階段 ---
FROM dev-env AS final-dev-env

ARG USERNAME

# 創建 Python 虛擬環境
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 切換到用戶
USER $USERNAME
WORKDIR /workspace

# 複製依賴檔案（分層優化）
COPY --chown=${USERNAME}:${USERNAME} service/firewall/Cargo.toml ./service/firewall/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-ebpf/Cargo.toml ./service/firewall/firewall-ebpf/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall/Cargo.toml ./service/firewall/firewall/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-common/Cargo.toml ./service/firewall/firewall-common/
COPY --chown=${USERNAME}:${USERNAME} service/firewall/xtask/Cargo.toml ./service/firewall/xtask/

# 複製最小源碼檔案
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-ebpf/src/main.rs ./service/firewall/firewall-ebpf/src/main.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall/src/main.rs ./service/firewall/firewall/src/main.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/firewall-common/src/lib.rs ./service/firewall/firewall-common/src/lib.rs
COPY --chown=${USERNAME}:${USERNAME} service/firewall/xtask/src/main.rs ./service/firewall/xtask/src/main.rs

# Python requirements
COPY --chown=${USERNAME}:${USERNAME} service/model/requirements.txt ./service/model/

# 安裝依賴（合併以減少層數）
WORKDIR /workspace/service/firewall
RUN cargo fetch \
    && cd /workspace/service/model \
    && pip install --no-cache-dir -r requirements.txt

# 複製完整源碼
WORKDIR /workspace
COPY --chown=${USERNAME}:${USERNAME} . .

# 設定用戶環境
RUN mkdir -p /home/$USERNAME/.config /home/$USERNAME/.cache /home/$USERNAME/workspace

# 環境變數
ENV RUST_BACKTRACE=full \
    RUST_LOG=debug \
    CARGO_INCREMENTAL=1 \
    PYTHONPATH="/workspace/service/model"

CMD ["/bin/bash"]