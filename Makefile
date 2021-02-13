DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
GENERATOR_SCRIPT = scripts/generate-structures
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}/.cargo/git:/cargo/git -v ${DIRECTORY}:/src andrewstucki/bpf-lsm-builder:latest

.DEFAULT_GOAL := build

libprobe/libprobe.a:
	@$(CONTAINER) /bin/sh -c "make -C libprobe"

.PHONY: build
build: libprobe/libprobe.a
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release && cp target/release/probe . && strip probe"

.PHONY: debug
debug: libprobe/libprobe.a
	@echo "Compiling debug binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build && cp target/debug/probe ."

.PHONY: test
test: libprobe/libprobe.a
	@echo "Running tests"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo test"

.PHONY: lint
lint:
	@echo "Running lint"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo clippy"

.PHONY: lint-fix
lint-fix:
	@echo "Running lint fix"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo clippy --fix -Z unstable-options"

.PHONY: test-rule-compiler
test-rule-compiler:
	@echo "Running rule-compiler tests"
	@$(CONTAINER) /bin/sh -c "cd rule-compiler && RUSTFLAGS=-Ctarget-feature=+crt-static cargo test"

venv:
	@echo "Setting up virtualenv"
	@$(CONTAINER) /bin/sh -c "python3 -m venv ./venv && source ./venv/bin/activate && pip install -r requirements.txt"

.PHONY: generate
generate: venv
	@echo "Generating files"
	@rm -rf libprobe/libprobe.a libprobe/.output target/*/build/probe-sys*
	@$(CONTAINER) /bin/sh -c "source ./venv/bin/activate && $(GENERATOR_SCRIPT)"
