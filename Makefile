DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}/.cargo/git:/cargo/git -v ${DIRECTORY}:/src andrewstucki/libbpf-rust-builder:0.3

build: generate
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release && cp target/release/probe . && strip probe"

debug: generate
	@echo "Compiling debug binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build && cp target/debug/probe ."

clean:
	@echo "Cleaning"
	@rm -rf probe-sys/src/.output # target probe

bootstrap-vm:
	@echo "Bringing up fresh VM and installing BPF Kernel"
	@vagrant up --provider virtualbox
	@echo "Stopping VM"
	@vagrant halt
	@echo "Bringing VM back up with new kernel"
	@vagrant up

venv:
	@python3 -m venv ./venv
	@. ./venv/bin/activate && pip install -r requirements.txt

generate: venv
	@. ./venv/bin/activate && ./scripts/generate-structures

toolchain-llvm:
	cd toolchain/llvm && \
	docker build . -t andrewstucki/llvm10rc3-musl-toolchain
	docker push andrewstucki/llvm10rc3-musl-toolchain

toolchain-libbpf:
	cd toolchain/libbpf && \
	docker build . -t andrewstucki/libbpf-builder:0.3
	docker push andrewstucki/libbpf-builder:0.3

toolchain-rust:
	cd toolchain/rust && \
	docker build . -t andrewstucki/libbpf-rust-builder:0.3
	#docker push andrewstucki/libbpf-rust-builder:0.3
