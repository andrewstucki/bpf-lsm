DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}:/src andrewstucki/libbpf-rust-builder:0.3

build:
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "cargo build --release && cp target/release/probe . && strip probe"

clean:
	@echo "Cleaning"
	@rm -rf probe-sys/src/.output target probe

bootstrap-vm:
	@echo "Bringing up fresh VM and installing BPF Kernel"
	@vagrant up --provider virtualbox
	@echo "Stopping VM"
	@vagrant halt
	@echo "Bringing VM back up with new kernel"
	@vagrant up

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
	docker push andrewstucki/libbpf-rust-builder:0.3
