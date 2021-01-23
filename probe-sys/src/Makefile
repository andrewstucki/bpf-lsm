OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/bin/bpftool
INCLUDES := -I$(OUTPUT)
CFLAGS := -O3 -Os -fdata-sections -ffunction-sections -fvisibility=hidden
LDFLAGS := -Wl,--gc-sections -static -lbcc -lbpf -lelf -lz
BPFFLAGS := -g -O2 -D__TARGET_ARCH_x86 -D__KERNEL__ -target bpf
LIB = libprobe.a
SOURCES = probe.c
BPF_SOURCES = probe.bpf.c
OBJECTS = $(SOURCES:%.c=$(OUTPUT)/%.o)
BPF_OBJECTS = $(BPF_SOURCES:%.bpf.c=$(OUTPUT)/%.bpf.o)
BPF_HEADERS = $(BPF_SOURCES:%.bpf.c=$(OUTPUT)/%.skel.h)

.PHONY: all
all: $(OUTPUT)/$(LIB)

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/$(LIB): $(OBJECTS) $(BPF_OBJECTS)
	$(AR) rcs $@ $(OBJECTS) $(BPF_OBJECTS)

$(OUTPUT)/%.o: %.c | $(BPF_HEADERS)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPF_OBJECTS)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) | $(OUTPUT)
	$(CLANG) $(BPFFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@

