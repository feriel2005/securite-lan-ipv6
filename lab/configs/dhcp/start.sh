#!/bin/bash
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.eth0.disable_ipv6=1 net.ipv6.conf.eth1.disable_ipv6=0
ip link set eth1 up
# attendre que le lien eth1 soit actif (max 30 s), sinon Kea n'ouvre aucun socket
for i in $(seq 1 30); do
  [ "$(cat /sys/class/net/eth1/carrier 2>/dev/null)" = "1" ] && break
  sleep 1
done
ip -6 addr add 2001:db8:10:20::10/64 dev eth1 nodad 2>/dev/null
ip -6 route add 2001:db8:10:10::/64 via 2001:db8:10:20::1 dev eth1 2>/dev/null
mkdir -p /var/lib/kea /run/kea
pkill kea-dhcp6 2>/dev/null; sleep 1; rm -f /run/kea/*.pid
kea-dhcp6 -c /config/kea-dhcp6.conf > /var/log/kea.log 2>&1 &
