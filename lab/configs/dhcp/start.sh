#!/bin/bash
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
ip link set eth1 up
ip -6 addr add 2001:db8:10:20::10/64 dev eth1
ip -6 route add 2001:db8:10:10::/64 via 2001:db8:10:20::1 dev eth1
mkdir -p /var/lib/kea /run/kea
pkill kea-dhcp6 2>/dev/null; sleep 1; rm -f /run/kea/*.pid
kea-dhcp6 -c /config/kea-dhcp6.conf > /var/log/kea.log 2>&1 &
