# CI/lint/test image only — not a deployment image. The real kukri binary
# needs to run on bare metal against real interfaces and the host's BPF/BTF
# support, which a generic container doesn't have.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
     bpftool \
     pkg-config \
     build-essential \
     iproute2 \
     python3 \
     ca-certificates \
    curl \
    git \
  && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal -c rustfmt,clippy
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# `make bpf skel-c skel-rust binary` deliberately skips the `vmlinux` target:
# that target regenerates bpf/vmlinux.h from the HOST kernel's live BTF
# (/sys/kernel/btf/vmlinux) via bpftool, which isn't meaningful (or safe to
# rely on) inside a generic container. bpf/vmlinux.h is checked into the
# repo and copied in above, so make's dependency resolution never re-runs
# that rule once the file already exists.
CMD ["bash", "-c", "set -e; cargo fmt --check; cargo clippy --all-targets -- -D warnings; cargo test; make bpf skel-c skel-rust binary"]
