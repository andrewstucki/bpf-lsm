DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}/.cargo/git:/cargo/git -v ${DIRECTORY}:/src andrewstucki/bpf-lsm-builder:latest

.DEFAULT_GOAL := build

libprobe/libprobe.a:
	@$(CONTAINER) /bin/sh -c "make -C libprobe"

.PHONY: build
build:
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release && cp target/release/probe . && strip probe"

.PHONY: debug
debug:
	@echo "Compiling debug binary"
	@$(CONTAINER) /bin/sh -c "make -C probe-sys && RUSTFLAGS=-Ctarget-feature=+crt-static cargo build && cp target/debug/probe ."

.PHONY: test
test:
	@echo "Running tests"
	@$(CONTAINER) /bin/sh -c "make -C probe-sys && RUSTFLAGS=-Ctarget-feature=+crt-static cargo test"

.PHONY: test-rule-compiler
test-rule-compiler:
	@echo "Running rule-compiler tests"
	@$(CONTAINER) /bin/sh -c "cd rule-compiler && RUSTFLAGS=-Ctarget-feature=+crt-static cargo test"

.PHONY: generate
generate:
	@$(CONTAINER) /bin/sh -c "make -C probe-sys generate"
