OUTPUT := src/.output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/bin/bpftool
INCLUDES := -I$(OUTPUT)
CFLAGS := -O3 -Os -fdata-sections -ffunction-sections -fvisibility=hidden
BPFFLAGS := -g -O2 -DBPF -D__TARGET_ARCH_x86 -D__KERNEL__ -target bpf
LIB = libprobe.a
SOURCES = src/probe.c
BPF_SOURCES = src/probe.bpf.c
GENERATED_SOURCES = src/lib.rs src/probe.bpf.h src/probe.c src/probe.h src/struct.proto
GENERATOR_SCRIPT = scripts/generate-structures
GENERATOR_TEMPLATES = $(GENERATED_SOURCES:src/%=templates/%.j2)
OBJECTS = $(SOURCES:src/%.c=$(OUTPUT)/%.o)
BPF_OBJECTS = $(BPF_SOURCES:src/%.bpf.c=$(OUTPUT)/%.bpf.o)
BPF_HEADERS = $(BPF_SOURCES:src/%.bpf.c=$(OUTPUT)/%.skel.h)

.DEFAULT_GOAL := $(OUTPUT)/$(LIB)

.PHONY: clean
clean:
	rm -rf $(OUTPUT) $(GENERATED_SOURCES) src/struct_pb.rs venv

$(OUTPUT):
	mkdir -p $@

$(GENERATED_SOURCES) &: $(GENERATOR_TEMPLATES) venv
	source ./venv/bin/activate && $(GENERATOR_SCRIPT)

$(OUTPUT)/$(LIB): $(OBJECTS) $(BPF_OBJECTS)
	$(AR) rcs $@ $(OBJECTS) $(BPF_OBJECTS)

$(OUTPUT)/%.o: src/%.c | $(BPF_HEADERS)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPF_OBJECTS)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: src/%.bpf.c src/$(wildcard %.h) | $(OUTPUT) $(GENERATED_SOURCES)
	$(CLANG) $(BPFFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@

venv:
	python3 -m venv ./venv
	source ./venv/bin/activate && pip install -r requirements.txt

.PHONY: generate
generate: venv
	source ./venv/bin/activate && $(GENERATOR_SCRIPT)
