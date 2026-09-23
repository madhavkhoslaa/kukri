# Kukri
```
Kukri is not a production grade ACL right now. Metrics show that it is almost 5X slow than iptables and nftables
Date (UTC): 2026-09-23T13:01:03+00:00
Kernel: 7.2.6-arch2-1
iptables backend: legacy (not iptables-nft)
kukri XDP mode: native/driver (kernel mode 1)
iperf3: single TCP stream, 5s per tool, receiver rate

tool       | TCP throughput (Gbits/sec)
-----------|----------------------------
kukri      | 14.809
iptables   | 77.441
nftables   | 76.471
```
[![CI](https://github.com/madhavkhoslaa/kukri/actions/workflows/ci.yml/badge.svg)](https://github.com/madhavkhoslaa/kukri/actions/workflows/ci.yml)

# Development tracker
Task list / tracker is here:
[Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vRe9IGTGjjrvLBAb20-S_kR6-Bu-5yjoS62JbkyRxaxArCrkbpESklHBgN3lkNOOXbJdaxtkgW0KoFw/pubhtml?gid=1246660885&single=true)


![kukri](assets/kukri.png)

An eBPF backed firewall with a terminal UI.

The idea is simple. You choose the interface, turn on the rules, and Kukri puts
small BPF programs in the packet path. Ingress runs with XDP. Egress runs with
TC. The UI is there so you do not have to remember every `bpftool`, `ip`, and
map update command while testing rules.

## What is it?

Imagine packets are walking into your machine.

Kukri stands at the door and asks questions like:

- is this source IP blocked?
- is this source port blocked?
- is this MAC address blocked?
- is this flow going too fast?

If the answer is yes, the packet is dropped early. If not, it keeps moving.

So in a way, Kukri is not trying to be a giant firewall framework. It is a small
Rust + eBPF project that makes packet filtering easy to see, easy to toggle, and
easy to test.

## What can it do right now?

- attach an ingress firewall with XDP
- attach an egress firewall with TC
- select interfaces from the TUI
- block IPv4 and IPv6 addresses / CIDR ranges
- block TCP and UDP ports / port ranges
- block MAC addresses
- enable simple rate limit stages
- show basic runtime status in the Summary tab

## Building

This is the command you want:

```bash
make all
```

This compiles the BPF object, generates the skeletons, and builds the Rust
release binary.

The binary you should run is:

```bash
sudo ./target/release/kukri examples/kukri.config.json
```

Important thing because it bit me too: `make all` builds `target/release/kukri`.
Do not run an old `./build/kukri` and then wonder why the new changes are not
showing up.

You need these on your machine:

- Rust / Cargo
- clang
- bpftool
- libbpf dependencies
- root privileges or the required BPF/network capabilities

## Running it

```bash
sudo ./target/release/kukri examples/kukri.config.json
```

In the TUI:

1. Go to `Settings -> Interfaces`.
2. Select the interface, for example `wlan0`.
3. Go to `Settings -> IP`.
4. Turn on `Ingress -> Enable rules`.

Why the IP tab? Because that `Enable rules` is the master switch. The TCP, UDP,
MAC, IPv4, IPv6 toggles are feature/stage switches. They decide what logic runs
after the main program is attached.

## Checking if XDP is actually attached

Use this while Kukri is still running:

```bash
sudo bpftool net show dev wlan0
ip -d link show dev wlan0
```

On WiFi cards, native XDP may fail depending on the driver. Kukri tries native
first and then falls back to generic/SKB XDP. If the attach worked, you should
see XDP information from the commands above.

## Config file

The config lives in JSON. The example file is:

```bash
examples/kukri.config.json
```

You can edit it by hand, or use the TUI and press `s` to save.

Small note: selecting an interface and saving only saves the interface. The BPF
program attaches when the master rule switch is on.
