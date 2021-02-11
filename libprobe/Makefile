OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/bin/bpftool
INCLUDES := -I$(OUTPUT) -Isrc/include
CFLAGS := -O3 -Os -fdata-sections -ffunction-sections -fvisibility=hidden
BPFFLAGS := -g -O2 -D__TARGET_ARCH_x86 -D__KERNEL__ -target bpf
LIB = libprobe.a
SOURCES = src/probe.c
BPF_SOURCES = src/probe.bpf.c
HEADERS = src/include/vmlinux.h src/include/probe_common.h src/include/probe_bpf.h src/include/probe_macros.h src/include/probe.h src/include/probe.generated.h 
OBJECTS = $(SOURCES:src/%.c=$(OUTPUT)/%.o)
BPF_OBJECTS = $(BPF_SOURCES:src/%.bpf.c=$(OUTPUT)/%.bpf.o)
BPF_HEADERS = $(BPF_SOURCES:src/%.bpf.c=$(OUTPUT)/%.skel.h)

.DEFAULT_GOAL := $(LIB)

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

$(OUTPUT):
	mkdir -p $@

$(LIB): $(OBJECTS) $(BPF_OBJECTS)
	$(AR) rcs $@ $(OBJECTS) $(BPF_OBJECTS)

$(OUTPUT)/%.o: src/%.c | $(BPF_HEADERS)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPF_OBJECTS)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: src/%.bpf.c | $(OUTPUT) $(HEADERS)
	$(CLANG) $(BPFFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@
