DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}/.cargo:/cargo/registry -v ${DIRECTORY}/.cargo/git:/cargo/git -v ${DIRECTORY}:/src andrewstucki/libbpf-rust-builder:0.3

build:
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --release && cp target/release/probe . && strip probe"

debug:
	@echo "Compiling debug binary"
	@$(CONTAINER) /bin/sh -c "RUSTFLAGS=-Ctarget-feature=+crt-static cargo build && cp target/debug/probe ."

clean:
	@echo "Cleaning"
	@rm -rf venv probe-sys/src/{.output,lib.rs,probe.bpf.h,probe.c,probe.h,struct_pb.rs,struct.proto} probe target

venv:
	@python3 -m venv ./venv
	@. ./venv/bin/activate && pip install -r requirements.txt

generate: venv
	@. ./venv/bin/activate && ./probe-sys/scripts/generate-structures
