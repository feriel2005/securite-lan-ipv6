#!/bin/sh
set -e

# --- L3 base ---
sysctl -qw net.ipv6.conf.all.disable_ipv6=0
sysctl -qw net.ipv6.conf.eth0.disable_ipv6=1      # Docker mgmt network: no IPv6 in the lab
sysctl -qw net.ipv6.conf.all.forwarding=1
sysctl -qw net.ipv6.conf.eth1.accept_ra=0
sysctl -qw net.ipv6.conf.eth2.accept_ra=0

# VLAN 10 (hosts): fe80::1 must be the ONLY link-local address
sysctl -qw net.ipv6.conf.eth1.addr_gen_mode=1     # stop automatic link-local generation
ip link set eth1 up
ip -6 addr add fe80::1/64 dev eth1 nodad
for a in $(ip -6 -o addr show dev eth1 scope link | awk '{print $4}'); do
  [ "$a" = "fe80::1/64" ] || ip -6 addr del "$a" dev eth1
done
ip -6 addr add 2001:db8:10:10::1/64 dev eth1 nodad

# VLAN 20 (servers)
ip link set eth2 up
ip -6 addr add 2001:db8:10:20::1/64 dev eth2 nodad
# --- Router Advertisements ---
# radvd can refuse a config file that is group-writable, as bind-mounted files often are,
# so start it from a clean root-owned copy.
cp /config/radvd.conf /etc/radvd.conf
chown root:root /etc/radvd.conf
chmod 644 /etc/radvd.conf
radvd -C /etc/radvd.conf -p /run/radvd.pid -m logfile -l /var/log/radvd.log
