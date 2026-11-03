#!/usr/bin/env bash
# Route containers' host.docker.internal (the Docker bridge gateway) to host
# loopback, as Docker Desktop does, so the census's runtime runner can run on
# the bridge (TRSTCTL_DOD_RUNNER_NETWORK=bridge): its hostname is then its
# container ID and it can join the private networks proofs create (the
# managed-key proof's PostgreSQL network), while the parent's loopback-only
# broker and substrates stay unpublished. Owner queue item 2d (2026-11-02).
# GitHub-hosted Linux runners only; needs sudo.
set -euo pipefail
gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
if [[ ! "$gateway" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
  echo "route-docker-host-to-loopback: no IPv4 bridge gateway (got '$gateway')" >&2
  exit 1
fi
# A packet for 127.0.0.1 arriving on a bridge is a martian unless route_localnet
# allows it; the DNAT then hands the bridge gateway's TCP to loopback.
sudo sysctl -q -w net.ipv4.conf.all.route_localnet=1
if ! sudo iptables -t nat -C PREROUTING -d "$gateway" -p tcp -j DNAT --to-destination 127.0.0.1 2>/dev/null; then
  sudo iptables -t nat -I PREROUTING 1 -d "$gateway" -p tcp -j DNAT --to-destination 127.0.0.1
fi
echo "route-docker-host-to-loopback: $gateway -> 127.0.0.1 (tcp)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "TRSTCTL_DOD_RUNNER_NETWORK=bridge" >> "$GITHUB_ENV"
fi
