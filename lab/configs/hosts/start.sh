#!/bin/bash
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
sysctl -qw net.ipv6.conf.eth1.accept_ra=1 net.ipv6.conf.eth1.autoconf=1
ip link set eth1 up
sleep 3
ip -6 route del default dev eth0 2>/dev/null
dhclient -6 -N -v eth1 > /tmp/dhclient6.log 2>&1 &
# Attacker fixed address, ONLY if Feriel approves:
# ip -6 addr add 2001:db8:10:10::66/64 dev eth1
