CLANG      := clang
BPFTOOL    := bpftool
BUILD_DIR  := target/bpf

BPF_SRC    := bpf/kukri.bpf.c
BPF_FILES  := $(shell find bpf -type f)
VMLINUX    := bpf/vmlinux.h
BPF_OBJ    := $(BUILD_DIR)/kukri.bpf.o
SKEL_C     := $(BUILD_DIR)/kukri.skel.h
SKEL_RS    := $(BUILD_DIR)/kukri.skel.rs
BIN        := target/release/kukri

.PHONY: all vmlinux bpf skel-c skel-rust rust-build binary run test-docker clean hooks

# Full release build: compiles the BPF object, generates both skeletons,
# builds the Rust binary in release mode. All generated artifacts stay under
# target/.
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

$(BPF_OBJ): $(BPF_SRC) $(BPF_FILES) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -I bpf -I bpf/common -I bpf/maps -c $(BPF_SRC) -o $@

# Generate the C skeleton header from the compiled object (for C tooling /
# inspection; the Rust build below does not depend on this).
skel-c: $(SKEL_C)

$(SKEL_C): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# Generate the Rust skeleton. build/build.rs already does this on every
# `cargo build` via libbpf_cargo::SkeletonBuilder; this target just runs
# that and copies the result out of Cargo's OUT_DIR so it is inspectable.
skel-rust: $(SKEL_RS)

$(SKEL_RS): $(BPF_SRC) $(BPF_FILES) $(VMLINUX) build/build.rs | $(BUILD_DIR)
	cargo build
	cp "$$(ls -t target/debug/build/kukri-*/out/kukri.skel.rs | head -1)" $(SKEL_RS)

# Build the Rust project in release mode.
rust-build: skel-rust
	cargo build --release

# The release binary is already produced under target/release.
binary: rust-build | $(BUILD_DIR)
	@test -x $(BIN)

run:
	cargo run

test-docker:
	docker compose up --build -d callee
	trap 'docker compose down' EXIT; \
	docker compose run --rm --no-deps --build host bash -lc 'make bpf skel-c skel-rust binary && bash /app/tests/docker/host.sh blocked-ip'; \
	docker compose run --rm --no-deps host bash -lc 'make bpf skel-c skel-rust binary && bash /app/tests/docker/host.sh allowed'; \
	docker compose run --rm --no-deps host bash -lc 'make bpf skel-c skel-rust binary && bash /app/tests/docker/host.sh blocked-port'; \
	docker compose run --rm --no-deps host bash -lc 'make bpf skel-c skel-rust binary && bash /app/tests/docker/host.sh blocked-rate'; \
	KUKRI_TEST_MODE=blocked-ingress-ip docker compose up -d --build host; \
	for i in $$(seq 1 180); do \
		docker compose exec -T host test -x /app/target/release/kukri && break; \
		sleep 1; \
	done; \
	sleep 3; \
	if docker compose exec -T callee curl --connect-timeout 2 --max-time 4 --fail http://172.28.0.2:8081/; then \
		echo 'expected ingress IPv4 ACL to block the callee'; exit 1; \
	fi; \
	docker compose stop host >/dev/null

clean:
	cargo clean
