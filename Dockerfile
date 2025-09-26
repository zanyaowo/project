ARG BASE_IMAGE=ubuntu:24.04.03
ARG RUST_VERSION=1.89.0
ARG PYTHON_VERSION=3.12.4
ARG NODE_VERSION=24.7.0

FROM ${BASE_IMAGE} as base 

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential=12.9ubuntu3 \
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