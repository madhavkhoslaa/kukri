CLANG      := clang
BPFTOOL    := bpftool
BUILD_DIR  := build

BPF_SRC    := bpf/kukri.bpf.c
VMLINUX    := bpf/vmlinux.h
BPF_OBJ    := $(BUILD_DIR)/kukri.bpf.o
SKEL_C     := $(BUILD_DIR)/kukri.skel.h
SKEL_RS    := $(BUILD_DIR)/kukri.skel.rs
BIN        := $(BUILD_DIR)/kukri

.PHONY: all vmlinux bpf skel-c skel-rust rust-build binary run clean hooks

all: vmlinux bpf skel-c skel-rust binary

# Enable the tracked git hooks (auto-licenses new *.bpf.c files on commit).
hooks:
	git config core.hooksPath .githooks

$(BUILD_DIR):
	mkdir -p $@

# Regenerate the CO-RE header from the running kernel's BTF. Only needed
# when targeting kernel structs/fields not yet in the checked-in header.
vmlinux: $(VMLINUX)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile the BPF C program to an ELF object with clang.
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -I bpf -c $(BPF_SRC) -o $@

# Generate the C skeleton header from the compiled object (for C tooling /
# inspection; the Rust build below does not depend on this).
skel-c: $(SKEL_C)

$(SKEL_C): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# Generate the Rust skeleton. build.rs already does this on every
# `cargo build` via libbpf_cargo::SkeletonBuilder; this target just runs
# that and copies the result out of Cargo's OUT_DIR so it's inspectable.
skel-rust: $(SKEL_RS)

$(SKEL_RS): $(BPF_SRC) $(VMLINUX) build.rs | $(BUILD_DIR)
	cargo build
	cp "$$(ls -t target/debug/build/kukri-*/out/kukri.skel.rs | head -1)" $(SKEL_RS)

# Build the Rust project in release mode.
rust-build: skel-rust
	cargo build --release

# Copy out the final, shareable binary.
binary: rust-build | $(BUILD_DIR)
	cp target/release/kukri $(BIN)

run:
	cargo run

clean:
	cargo clean
	rm -rf $(BUILD_DIR)
