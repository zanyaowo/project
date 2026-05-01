.PHONY: help clean

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build-ebpf: ## Build ebpf program
	@echo "start build:"
	cd service/firewall && RUSTC_BOOTSTRAP=1 /home/zanya/.cargo/bin/cargo +nightly build --package firewall-ebpf --target bpfel-unknown-none -Z build-std=core --release

clean:
	@echo "clean target folder"
	rm -rf service/firewall/target

FIREWALL_BPF_PATH := $(abspath service/firewall/target/bpfel-unknown-none/release/firewall-ebpf)

run-firewall: build-ebpf ## Build and run eBPF firewall
	@echo "build firewall userspace..."
	cd service/firewall && FIREWALL_BPF=$(FIREWALL_BPF_PATH) /home/zanya/.cargo/bin/cargo build --package firewall --release
	@echo "run ebpf firewall"
	cd service/firewall && sudo -E ./target/release/firewall

run-test:
	@echo "run test"
	cd service/firewall && RUSTC_BOOTSTRAP=1 sudo -E /home/zanya/.cargo/bin/cargo +nightly test --package firewall --release -- tests::test::test_session_tracking --nocapture