#!/bin/sh
# Vérifie les deux points : Kea sert bien les victimes, et le nœud dhcp est configuré
# automatiquement à chaque déploiement (aucune manipulation manuelle).
P=clab-ipv6lab
ok=0; ko=0
res() { if [ "$1" = 0 ]; then echo "PASS  $2"; ok=$((ok+1)); else echo "FAIL  $2"; ko=$((ko+1)); fi; }

out=$(docker exec $P-dhcp ip -6 addr show dev eth1 2>/dev/null)
echo "$out" | grep -q '2001:db8:10:20::10/64'; res $? "dhcp : adresse 2001:db8:10:20::10/64 sur eth1"

out=$(docker exec $P-dhcp ip -6 route 2>/dev/null)
echo "$out" | grep -q '2001:db8:10:10::/64 via 2001:db8:10:20::1'; res $? "dhcp : route vers le VLAN 10 via 2001:db8:10:20::1"

out=$(docker exec $P-dhcp ps -eo args 2>/dev/null)
echo "$out" | grep -q 'kea-dhcp6 -c /config/kea-dhcp6.conf'; res $? "dhcp : Kea lancé avec /config/kea-dhcp6.conf"

for n in victim1 victim2 attacker; do
  a=$(docker exec $P-$n ip -6 addr show dev eth1 2>/dev/null)
  echo "$a" | grep -Eq 'inet6 2001:db8:10:10:[0-9a-f:]+/64'; res $? "$n : adresse SLAAC (/64)"
  echo "$a" | grep -Eq 'inet6 2001:db8:10:10::1[0-9a-f]{3}/128'; res $? "$n : adresse DHCPv6 du pool (/128)"
  r=$(docker exec $P-$n ip -6 route show default 2>/dev/null)
  [ "$(echo "$r" | grep -c default)" = 1 ] && echo "$r" | grep -q 'via fe80::1 dev eth1'; res $? "$n : une seule route par défaut, via fe80::1"
done

docker exec $P-victim1 ping -6 -c1 -W2 2001:db8:10:20::10 >/dev/null 2>&1; res $? "victim1 : ping du serveur DHCP à travers le routeur"

echo
echo "Résultat : $ok PASS, $ko FAIL"
[ "$ko" = 0 ]