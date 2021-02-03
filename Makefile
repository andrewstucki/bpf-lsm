DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}/.cargo/git:/cargo/git -v ${DIRECTORY}:/src andrewstucki/bpf-lsm-builder:latest

.PHONY: build
build:
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "make -C probe-sys && RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release && cp target/release/probe . && strip probe"

.PHONY: debug
debug:
	@echo "Compiling debug binary"
	@$(CONTAINER) /bin/sh -c "make -C probe-sys && RUSTFLAGS=-Ctarget-feature=+crt-static cargo build && cp target/debug/probe ."

.PHONY: generate
generate:
	@$(CONTAINER) /bin/sh -c "make -C probe-sys generate"
