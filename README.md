# Kukri

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

## Tour of every screen

The UI is split into two tabs — **Summary** and **Settings**. The Settings tab is
split into five sections: **IP**, **TCP**, **UDP**, **MAC**, and **Interfaces**.
That is the whole app: one read-only "what is actually running" page, plus five
editable rule pages.

| Screen | Shows |
| --- | --- |
| [Summary](assets/screenshots/01-summary.png) | live attachment state, Layer 2/3/4 rule summaries, event stream |
| [Settings -> IP](assets/screenshots/02-settings-ip.png) | IPv4 + IPv6 rules per direction, loopback handling, rate limit settings |
| [Settings -> TCP](assets/screenshots/03-settings-tcp.png) | blocked TCP ports and port ranges per direction |
| [Settings -> UDP](assets/screenshots/04-settings-udp.png) | blocked UDP ports and port ranges per direction |
| [Settings -> MAC](assets/screenshots/05-settings-mac.png) | blocked MAC addresses per direction |
| [Settings -> Interfaces](assets/screenshots/06-settings-interfaces.png) | which interfaces the hooks are attached to |

Navigation is simple: Tab switches between the two tabs, Left/Right moves between
the five Settings sections, Up/Down moves the selection, Space toggles a switch
or an interface, d deletes a rule, Enter confirms a toggle or opens the add-value
prompt, s saves the config file, and q quits.

### TCP and UDP (Layer 4)

The TCP and UDP sections look the same, one for each protocol. Each direction has
its own "Enable rules" switch, its own blocked-port list, and its own blocked-port
range list. On ingress Kukri blocks by **source port**; on engress it blocks by
**destination port**. Ranges are entered as start-end, so blocking 0-1023 knocks
out all the privileged ports in one line. Port blocking is protocol-specific (a
TCP rule never touches UDP and vice versa) but IP-version-agnostic: one port map
serves packets carried over IPv4 and IPv6 alike.

### IP (Layer 3)

The IP section carries IPv4 and IPv6 side by side, for both directions. Kukri
blocks individual addresses and CIDR ranges; on ingress that means blocked
**source** addresses, on engress blocked **destination** addresses. A per-direction
"Disable loopback" switch drops the loopback address family so local traffic never
counts against the rule lists. Each direction also gets a master "Enable rules"
switch, and that master switch is what actually attaches or detaches the eBPF
program on the chosen interfaces — the finer switches (IPv4, IPv6, MAC, ports,
rate limits) just decide which rule stages sit inside the running program.

### MAC (Layer 2)

The MAC section blocks by Ethernet hardware address, entered as aa:bb:cc:dd:ee:ff.
Ingress blocks **source** MACs, engress blocks **destination** MACs, each with its
own enable switch and its own list. MAC rules are evaluated before anything else:
if the hardware address is blocked, the frame never gets to the IP or port logic.

### Rate limiting

Rate limits live inside the IP section. There are two independent limiters per
direction:

- a per-source-IP limiter on ingress (per-destination-IP on engress), and
- a per-destination-port limiter

Both are expressed in packets per second, and 0 means unlimited. Each limiter has
its own enable switch, so you can rate limit by IP without touching port limits,
or the other way round. When a flow trips the limiter, the offending packets are
dropped and logged as isolated rate-limit events rather than ordinary ACL blocks.

### Logs and the event stream

The Summary tab ends with an Event stream section. It shows a running packets
processed counter, then per-reason drop counters — MAC, IPv4 ACL, TCP port, UDP
port, IP rate limit, and port rate limit — followed by the specific blocked IPs
and rate-limited IPs/ports that accumulated while Kukri was running. Drop events
travel from kernel space to the UI through an eBPF ring buffer, so the numbers on
screen are the same packets the kernel actually rejected, not a UI-side estimate.

### Interfaces

The Interfaces section lists every network interface Kukri can see, with a
checkbox marking the selected ones. The selection is capped at two interfaces at
a time. Choosing an interface is a hot change: the hooks detach and re-attach to
the new set immediately, so you never restart the app just to point the firewall
at a different NIC. The Attachment block on the Summary tab always shows which
interfaces the programs are actually live on, and the XDP mode they ended up in.

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

## Development tracker

Task list / tracker is here:

[Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vRe9IGTGjjrvLBAb20-S_kR6-Bu-5yjoS62JbkyRxaxArCrkbpESklHBgN3lkNOOXbJdaxtkgW0KoFw/pubhtml?gid=1246660885&single=true)
