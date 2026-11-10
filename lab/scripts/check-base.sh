#!/bin/sh
P=clab-ipv6lab
echo "== router eth1 MAC =="; docker exec $P-router ip -br link show eth1
for n in victim1 victim2 attacker; do
  echo "== $n address ==";  docker exec $P-$n ip -6 -br addr show dev eth1
  echo "== $n default route =="; docker exec $P-$n ip -6 route show default
  echo "== $n neighbor cache =="; docker exec $P-$n ip -6 neigh show dev eth1
done
echo "== ping router (victim1) =="; docker exec $P-victim1 ping -6 -c2 2001:db8:10:10::1
echo "== ping dhcp across the router (victim1) =="; docker exec $P-victim1 ping -6 -c2 2001:db8:10:20::10
echo "== RAs seen by victim1 (15 s) =="; docker exec $P-victim1 tshark -i eth1 -a duration:15 -Y "icmpv6.type==134"
