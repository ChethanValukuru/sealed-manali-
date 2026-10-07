#!/usr/bin/env bash
# Helper to apply the host-level default-deny ruleset (Phase 2 defense-in-depth).
# Prints the subnets compose assigned so you can fill default-deny.nft, then
# loads it. Run AFTER `make up`. Requires root (nft).
set -euo pipefail

echo ">> Networks created by the stack (fill these into default-deny.nft):"

# Ask the container engine for each sealed network's subnet.
if command -v docker >/dev/null 2>&1; then
  for net in $(docker network ls --format '{{.Name}}' | grep -E 'sealed.*-net'); do
    sub=$(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
    echo "   $net -> $sub"
  done
elif command -v podman >/dev/null 2>&1; then
  for net in $(podman network ls --format '{{.Name}}' | grep -E 'sealed.*-net'); do
    sub=$(podman network inspect "$net" -f '{{range .Subnets}}{{.Subnet}}{{end}}')
    echo "   $net -> $sub"
  done
fi

echo
echo ">> Edit isolation/nftables/default-deny.nft with the subnets above, then:"
echo "   sudo nft -f isolation/nftables/default-deny.nft"
echo "   sudo nft list table inet sealed    # verify"
