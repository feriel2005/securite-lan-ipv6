#!/bin/bash
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.eth0.disable_ipv6=1 net.ipv6.conf.eth1.disable_ipv6=0
sysctl -qw net.ipv6.conf.eth1.accept_ra=1 net.ipv6.conf.eth1.autoconf=1
ip link set eth1 up
# attendre la route par defaut venant du RA (max 30 s)
for i in $(seq 1 30); do
  ip -6 route show default dev eth1 | grep -q . && break
  sleep 1
done
ip -6 route del default dev eth0 2>/dev/null
dhclient -6 -N -v eth1 > /tmp/dhclient6.log 2>&1 &
# Attacker fixed address, ONLY if Feriel approves:
# ip -6 addr add 2001:db8:10:10::66/64 dev eth1
