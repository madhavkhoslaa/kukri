# Ingress throughput comparison

Run from the repository root on Linux with Docker and a BPF-capable kernel:

```sh
make all
tar -C metrics -cf - Dockerfile bench.py kukri.json -C ../build kukri | docker build -t kukri-metrics -
docker run --rm --privileged --network none -v /lib/modules:/lib/modules:ro \
  -v "$PWD/metrics:/results" \
  -e RESULTS_UID="$(id -u)" -e RESULTS_GID="$(id -g)" kukri-metrics
```

`metrics/results.txt` is replaced **only after all three cases succeed**. Set `-e DURATION=10` on `docker run` to change the default five-second iperf3 TCP run per tool. The image uses the binary produced by `make all`; the tar build context is necessary because the repository's root `.dockerignore` excludes `build/`. Docker's legacy builder and BuildKit both accept this command.

The container has **no external Docker network**. The script creates `fw0` and its veth peer `client0` inside that container, then moves `client0` to a second *container-local* network namespace. The two namespaces are necessary: assigning both IPs in one namespace would let Linux route directly over `lo` and skip the measured veth ingress path. `--privileged` permits nested network namespaces and loading XDP/BPF; the read-only `/lib/modules` mount allows `iptables-legacy` to load the running kernel's `ip_tables`/`iptable_filter` modules when necessary (the modules are global, but the rules remain in the container's network namespace). The host kernel must provide those modules. No host interfaces, firewall rules or host network namespaces are changed. Container removal cleans up its network namespaces and rules.

The iperf3 client sends a single TCP stream from `client0` to the server on `fw0`. Each tool, in turn, blocks **ingress TCP source port 12345**, while the iperf3 flow uses a different ephemeral source port. Kukri's ingress TCP port stage, `iptables-legacy` `INPUT` and nftables `input` thus evaluate the same nonmatching ACL; all other rules/stages are off. We explicitly use `iptables-legacy`: this image's default `iptables` command uses the nftables backend, which would compare nftables against itself. Before timing each case, the script checks both a blocked connection from port 12345 and a permitted connection from port 12346, and it verifies kukri is attached to `fw0` via XDP. It aborts instead of writing a result on any failed check. Kukri's TUI is driven via a pseudo-terminal to switch ingress on (the current binary only attaches after the master switch is toggled); the script waits for detachment before the next case.

The table shows iperf3 **receiver** TCP throughput, decimal Gbits/sec, one run per tool in the fixed kukri → iptables → nftables order. These are local veth CPU/stack measurements, not physical NIC wire speeds or isolated CPU-overhead measurements. `results.txt` reports the actual XDP attach mode: native/driver (mode 1) or generic/SKB (mode 2). Veth supports native XDP on the machine used for the recorded run; do not interpret these numbers as physical-NIC XDP throughput or as generic/SKB XDP results. Kernel, image, duration and topology are recorded with each run.
