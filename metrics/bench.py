"""Isolated veth/netns TCP ingress benchmark; run inside the metrics image."""

import datetime
import json
import os
import pty
import select
import subprocess
import time
from pathlib import Path


SERVER = "198.19.0.1"
CLIENT = "198.19.0.2"
NS = "kukri-bench-client"
CONFIG = "/opt/metrics/kukri.json"
RESULTS = Path("/results/results.txt")
DURATION = int(os.environ.get("DURATION", "5"))


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def netns(*args):
    return run("ip", "netns", "exec", NS, *args)


def xdp_info():
    link = json.loads(run("ip", "-j", "-d", "link", "show", "dev", "fw0"))[0]
    return link.get("xdp", {})


def wait_for(predicate, message, seconds=10):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(message)


def start_kukri():
    master, slave = pty.openpty()
    proc = subprocess.Popen(["kukri", CONFIG], stdin=slave, stdout=slave,
                            stderr=slave, start_new_session=True, env={**os.environ, "TERM": "xterm"})
    os.close(slave)
    output = bytearray()
    try:
        # The current TUI applies ACL stages at startup, but attaches the XDP
        # hook only when the master switch is toggled. Config starts disabled:
        # Tab opens Settings/IP, where the first selectable row is the switch.
        time.sleep(1)
        if proc.poll() is not None:
            raise RuntimeError(f"kukri exited before attach: {output!r}")
        os.write(master, b"\t")
        time.sleep(0.3)
        os.write(master, b" ")
        until = time.monotonic() + 10
        while time.monotonic() < until and not xdp_info():
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    break
        info = xdp_info()
        if not info:
            raise RuntimeError(f"kukri did not attach XDP on fw0: {output[-4000:]!r}")
        return proc, master, info
    except Exception:
        proc.terminate()
        proc.wait(timeout=5)
        os.close(master)
        raise


def setup_network():
    # Both veth ends are inside this Docker container. Moving the client end
    # into a second netns prevents Linux from shortcutting via a local route.
    run("ip", "netns", "add", NS)
    run("ip", "link", "add", "fw0", "type", "veth", "peer", "name", "client0")
    run("ip", "link", "set", "client0", "netns", NS)
    run("ip", "addr", "add", SERVER + "/30", "dev", "fw0")
    netns("ip", "addr", "add", CLIENT + "/30", "dev", "client0")
    run("ip", "link", "set", "fw0", "up")
    netns("ip", "link", "set", "lo", "up")
    netns("ip", "link", "set", "client0", "up")


def check_acl():
    # Bind exactly the blocked source port to catch absent/bypassed rules.
    # The server must already be listening. An ordinary source port must work.
    for source_port, expect_blocked in [(12345, True), (12346, False)]:
        code = """import socket,sys
s=socket.socket(); s.settimeout(0.8); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('198.19.0.2',int(sys.argv[1])))
try: s.connect(('198.19.0.1',5201)); sys.exit(0)
except (TimeoutError, OSError): sys.exit(1)
"""
        probe = subprocess.run(["ip", "netns", "exec", NS, "python", "-c", code,
                                str(source_port)], capture_output=True)
        if (probe.returncode != 0) != expect_blocked:
            raise RuntimeError(f"ACL probe from source port {source_port} failed: {probe.stderr!r}")


def measure():
    raw = netns("iperf3", "-c", SERVER, "-t", str(DURATION), "-J")
    report = json.loads(raw)
    if "error" in report:
        raise RuntimeError(f"iperf3: {report['error']}")
    return report["end"]["sum_received"]["bits_per_second"] / 1e9


def main():
    if DURATION < 1:
        raise ValueError("DURATION must be at least 1 second")
    setup_network()
    server = subprocess.Popen(["iperf3", "-s", "-B", SERVER], stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE)
    kukri = None
    master = None
    try:
        wait_for(lambda: subprocess.run(["ss", "-ltn", "sport", "=", ":5201"],
                                         capture_output=True, text=True).stdout.count(":5201") > 0,
                 "iperf3 server failed to start")
        rows = []
        mode = ""
        for tool in ("kukri", "iptables", "nftables"):
            if tool == "kukri":
                kukri, master, info = start_kukri()
                modes = {1: "native/driver", 2: "generic/SKB", 3: "hardware", 4: "multi"}
                mode_id = info.get("mode")
                mode = f"{modes.get(mode_id, 'unknown')} (kernel mode {mode_id})"
            elif tool == "iptables":
                run("iptables-legacy", "-A", "INPUT", "-i", "fw0", "-p", "tcp", "--sport", "12345", "-j", "DROP")
            else:
                run("nft", "add", "table", "ip", "bench")
                run("nft", "add", "chain", "ip", "bench", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}")
                run("nft", "add", "rule", "ip", "bench", "input", "iifname", "fw0", "tcp", "sport", "12345", "drop")
            check_acl()
            gbps = measure()
            rows.append((tool, gbps))
            print(f"{tool}: {gbps:.3f} Gbits/sec", flush=True)
            if tool == "kukri":
                os.write(master, b"q")
                kukri.wait(timeout=5)
                os.close(master)
                kukri, master = None, None
                wait_for(lambda: not xdp_info(), "kukri XDP link did not detach")
            elif tool == "iptables":
                run("iptables-legacy", "-D", "INPUT", "-i", "fw0", "-p", "tcp", "--sport", "12345", "-j", "DROP")
            else:
                run("nft", "delete", "table", "ip", "bench")
        text = (f"Date (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n"
                f"Kernel: {os.uname().release}\n"
                f"Docker image: metrics/Dockerfile (Arch Linux), --privileged --network none\n"
                f"Topology: isolated veth fw0 <-> client0 (client in container-local netns)\n"
                f"ACL: ingress TCP source port 12345 DROP; iperf3 source port != 12345\n"
                f"iptables backend: legacy (not iptables-nft)\n"
                f"kukri XDP mode: {mode}\n"
                f"iperf3: single TCP stream, {DURATION}s per tool, receiver rate\n\n"
                "tool       | TCP throughput (Gbits/sec)\n"
                "-----------|----------------------------\n" +
                "".join(f"{tool:<11}| {gbps:.3f}\n" for tool, gbps in rows))
        RESULTS.write_text(text)
        if "RESULTS_UID" in os.environ and "RESULTS_GID" in os.environ:
            os.chown(RESULTS, int(os.environ["RESULTS_UID"]), int(os.environ["RESULTS_GID"]))
        print(text, flush=True)
    finally:
        if kukri is not None:
            kukri.terminate()
            kukri.wait(timeout=5)
        if master is not None:
            os.close(master)
        server.terminate()
        server.wait(timeout=5)
        run("ip", "netns", "del", NS)


if __name__ == "__main__":
    main()
