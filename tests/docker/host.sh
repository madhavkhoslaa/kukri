#!/usr/bin/env bash
set -euo pipefail

trap 'kill "${KUKRI_PID:-}" "${SERVER_PID:-}" 2>/dev/null || true' EXIT
if [ "$#" -gt 1 ]; then
    echo "usage: host.sh blocked-ip|allowed|blocked-port" >&2
    exit 2
fi
MODE="${1:-${KUKRI_TEST_MODE:-}}"
if [ -z "$MODE" ]; then
    echo "usage: host.sh blocked-ip|allowed|blocked-port|blocked-rate|blocked-ingress-ip" >&2
    exit 2
fi

write_config() {
python3 - "$1" "$2" <<'PY'
import ipaddress
import json
import sys

path = "/app/examples/kukri.config.json"
with open(path) as file:
    config = json.load(file)

mode = sys.argv[1]
output = sys.argv[2]
config["interfaces"]["names"] = ["eth0"]
config["ingress"]["enable_rules"] = False
config["engress"]["enable_rules"] = True
config["engress"]["ipv4_rules"]["disable_loopback"] = False
config["engress"]["ipv4_rules"]["blocked_destination_ranges"] = []
config["engress"]["ipv4_rules"]["blocked_destination_ips"] = []
config["engress"]["tcp_rules"]["blocked_destination_ranges"] = []
config["engress"]["tcp_rules"]["blocked_destination_ports"] = []

if mode == "blocked-ip":
    config["engress"]["ipv4_rules"]["enable_ip_rules"] = True
    config["engress"]["ipv4_rules"]["blocked_destination_ips"] = [
        int(ipaddress.IPv4Address("172.28.0.3"))
    ]
    config["engress"]["tcp_rules"]["enable_port_rules"] = False
elif mode == "blocked-port":
    # The IPv4 stage is also the egress protocol router, so keep it enabled
    # with empty maps to reach the TCP-port stage.
    config["engress"]["ipv4_rules"]["enable_ip_rules"] = True
    config["engress"]["tcp_rules"]["enable_port_rules"] = True
    config["engress"]["tcp_rules"]["blocked_destination_ports"] = [8080]
elif mode == "blocked-ingress-ip":
    config["ingress"]["enable_rules"] = True
    config["ingress"]["ipv4_rules"]["enable_ip_rules"] = True
    config["ingress"]["ipv4_rules"]["disable_loopback"] = False
    config["ingress"]["ipv4_rules"]["blocked_source_ranges"] = ["172.28.0.0/24"]
    config["ingress"]["ipv4_rules"]["blocked_source_ips"] = []
    config["engress"]["enable_rules"] = False
elif mode == "blocked-rate":
    config["engress"]["rate_limit"]["enable_ip_rate_limit"] = True
    config["engress"]["rate_limit"]["ip_rate_limit_pps"] = 1
    config["engress"]["rate_limit"]["enable_port_rate_limit"] = False
    config["engress"]["ipv4_rules"]["enable_ip_rules"] = False
    config["engress"]["tcp_rules"]["enable_port_rules"] = False
elif mode == "allowed":
    config["engress"]["ipv4_rules"]["enable_ip_rules"] = False
    config["engress"]["tcp_rules"]["enable_port_rules"] = False
else:
    raise SystemExit(f"unknown mode: {mode}")

with open(output, "w") as file:
    json.dump(config, file)
PY
}

start_kukri() {
    /app/target/release/kukri --headless "$1" >/tmp/kukri.log 2>&1 &
    KUKRI_PID=$!
    sleep 3
    if ! kill -0 "$KUKRI_PID" 2>/dev/null; then
        cat /tmp/kukri.log
        echo "Kukri exited before the integration request"
        exit 1
    fi
}

stop_kukri() {
    kill "$KUKRI_PID" 2>/dev/null || true
    wait "$KUKRI_PID" 2>/dev/null || true
    KUKRI_PID=""
}

request_must_fail() {
    if curl --connect-timeout 2 --max-time 4 http://172.28.0.3:8080/ >/tmp/callee-response; then
        echo "expected Kukri to block $1"
        cat /tmp/kukri.log
        exit 1
    fi
}

request_must_succeed() {
    curl --connect-timeout 2 --max-time 4 http://172.28.0.3:8080/ >/tmp/callee-response
}

request_rate_limited() {
    local failures=0
    for _ in 1 2 3 4 5; do
        if ! curl --connect-timeout 2 --max-time 4 http://172.28.0.3:8080/ >/tmp/callee-response; then
            failures=$((failures + 1))
        fi
    done
    if [ "$failures" -eq 0 ]; then
        echo "expected the IP rate limit to drop at least one request"
        cat /tmp/kukri.log
        exit 1
    fi
}

config_path="/tmp/kukri-${MODE}.json"
write_config "$MODE" "$config_path"
start_kukri "$config_path"
case "$MODE" in
    blocked-ip) request_must_fail "the IPv4 destination" ;;
    blocked-port) request_must_fail "TCP destination port 8080" ;;
    allowed) request_must_succeed ;;
    blocked-rate) request_rate_limited ;;
    blocked-ingress-ip)
        python3 -m http.server 8081 --bind 0.0.0.0 >/tmp/callee-on-host.log 2>&1 &
        SERVER_PID=$!
        while kill -0 "$KUKRI_PID" 2>/dev/null; do
            sleep 1
        done
        ;;
esac
stop_kukri

echo "docker BPF integration test passed: $MODE"
