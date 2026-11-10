#!/bin/sh
# Usage: bridge.sh <port> [<port> ...]
# Transparent L2 switch: bridge br0 with the given ports, no IPv6 of its own.
set -e
ip link add br0 type bridge stp_state 0 mcast_snooping 0
for p in "$@"; do
  sysctl -qw net.ipv6.conf.$p.disable_ipv6=1
  ip link set "$p" up
  ip link set "$p" master br0
done
sysctl -qw net.ipv6.conf.br0.disable_ipv6=1
ip link set br0 up