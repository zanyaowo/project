.PHONY: help clean

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build-ebpf: ## Build ebpf program
	@echo "start build:"
	cd service/firewall && cargo +nightly build --package firewall-ebpf --target bpfel-unknown-none -Z build-std=core --release

clean:
	@echo "clean taregt folder"
	rm -rf service/firewall/target

run-firewall:
	@echo "run ebpf firewall"
	cd service/firewall && RUSTC_BOOTSTRAP=1 sudo -E /home/zanya/.cargo/bin/cargo run --package xtask -- run --release

run-test:
	@echo "run test"
	cd service/firewall && RUSTC_BOOTSTRAP=1 sudo -E /home/zanya/.cargo/bin/cargo test --package firewall --release -- tests::test::test_session_tracking --nocapture