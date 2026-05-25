IFACE ?= wlp3s0
CARGO := cargo

.PHONY: help clean build-ebpf build-ebpf-debug test run-firewall run-firewall-debug run-test clean-tc bpftool-maps

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build-ebpf: ## Build eBPF bytecode (release)
	@echo "Building eBPF (release)..."
	cd service/firewall && $(CARGO) +nightly build --package firewall-ebpf --target bpfel-unknown-none -Z build-std=core --release

build-ebpf-debug: ## Build eBPF bytecode (debug)
	@echo "Building eBPF (debug)..."
	cd service/firewall && $(CARGO) +nightly build --package firewall-ebpf --target bpfel-unknown-none -Z build-std=core

clean: ## Remove build artifacts
	@echo "Cleaning..."
	rm -rf service/firewall/target

FIREWALL_BPF_RELEASE := $(abspath service/firewall/target/bpfel-unknown-none/release/firewall-ebpf)
FIREWALL_BPF_DEBUG   := $(abspath service/firewall/target/bpfel-unknown-none/debug/firewall-ebpf)

test: build-ebpf-debug ## Run unit tests (no root needed)
	@echo "Running unit tests..."
	cd service/firewall && FIREWALL_BPF=$(FIREWALL_BPF_DEBUG) $(CARGO) test --package firewall

FIREWALL_BIN_RELEASE := $(abspath service/firewall/target/release/firewall)
FIREWALL_BIN_DEBUG   := $(abspath service/firewall/target/debug/firewall)

run-firewall: build-ebpf ## Build (release) and run firewall [IFACE=wlp3s0]
	@echo "Building userspace (release)..."
	cd service/firewall && FIREWALL_BPF=$(FIREWALL_BPF_RELEASE) $(CARGO) build --package firewall --release
	@echo "Running firewall on $(IFACE)..."
	cd service/firewall/firewall && sudo env "PATH=$(PATH)" $(FIREWALL_BIN_RELEASE) --iface $(IFACE)

run-firewall-debug: build-ebpf-debug ## Build (debug) and run firewall [IFACE=wlp3s0]
	@echo "Building userspace (debug)..."
	cd service/firewall && FIREWALL_BPF=$(FIREWALL_BPF_DEBUG) $(CARGO) build --package firewall
	@echo "Running firewall (debug) on $(IFACE)..."
	cd service/firewall/firewall && sudo env "PATH=$(PATH)" $(FIREWALL_BIN_DEBUG) --iface $(IFACE)

run-test: ## Run session tracking integration test (requires root + NIC)
	@echo "Running session tracking test (requires root + NIC)..."
	cd service/firewall && FIREWALL_BPF=$(FIREWALL_BPF_DEBUG) sudo env "PATH=$(PATH)" \
		$(CARGO) test --package firewall -- tests::test::test_session_tracking --nocapture --ignored

clean-tc: ## Remove leftover clsact qdisc after a forced kill [IFACE=wlp3s0]
	@echo "Removing clsact qdisc on $(IFACE)..."
	sudo tc qdisc del dev $(IFACE) clsact 2>/dev/null || true

bpftool-maps: ## Dump all loaded BPF map contents for debugging
	@echo "BPF maps:"
	sudo bpftool map show
	@echo ""
	@echo "SCORE_TABLE:"
	sudo bpftool map dump name SCORE_TABLE 2>/dev/null || echo "  (not loaded)"
	@echo "QUANTILE_BOUNDS:"
	sudo bpftool map dump name QUANTILE_BOUNDS 2>/dev/null || echo "  (not loaded)"
	@echo "BLOCK_LIST:"
	sudo bpftool map dump name BLOCK_LIST 2>/dev/null || echo "  (not loaded)"