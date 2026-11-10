# Lab de base (réseau non protégé)

## Commandes
- Construire l'image : `sh docker/build.sh`
- Démarrer le lab : `sh lab/scripts/deploy.sh`
- Détruire le lab : `sh lab/scripts/destroy.sh`
- Tester le relais DHCPv6 : `sh lab/scripts/test-relay.sh`
- Entrer dans un nœud : `docker exec -it clab-ipv6lab-<nœud> bash`

## Nœuds
Conteneurs : `clab-ipv6lab-` + router, dhcp, victim1, victim2, attacker, br-hosts, br-srv.

## Ports (conforme au CONTRAT.md)
| Pont | Port | Branché sur | Statut |
|---|---|---|---|
| br-hosts | eth1 | router (eth1) | de confiance |
| br-hosts | eth2 | victim1 | non fiable |
| br-hosts | eth3 | victim2 | non fiable |
| br-hosts | eth4 | attacker | non fiable |
| br-srv | eth1 | router (eth2) | |
| br-srv | eth2 | dhcp | |

Routeur : eth1 = VLAN 10 (2001:db8:10:10::1, fe80::1), eth2 = VLAN 20 (2001:db8:10:20::1).
Dans chaque conteneur pont, le pont Linux s'appelle `br0` (les règles nftables s'y appliquent).

## Choix de configuration
- RA (radvd) : M=1, O=1, A=1 (adresse SLAAC et adresse DHCPv6).
- IPv6 est désactivé sur eth0 (réseau de gestion Docker) dans tous les nœuds : la seule route par défaut IPv6 du LAN vient des RA du routeur (fe80::1).
- Le routeur n'a que fe80::1 comme adresse link-local sur eth1.
- Relais DHCPv6 : eth1 -> 2001:db8:10:20::10 via eth2.

## Fichiers
- Commutateurs : `lab/configs/switch/bridge.sh`
- Routeur (adresses, forwarding, radvd, relais) : `lab/configs/router/router.sh`
- RA : `lab/configs/router/radvd.conf`

## Vérifications de l'état normal (avant attaque)
Adresse SLAAC, route par défaut unique via fe80::1, ping du routeur, ping de 2001:db8:10:20::10, cache des voisins (routeur avec sa vraie MAC), RA visibles.

## À finaliser avec Ramin
Serveur Kea sur dhcp (adresse 2001:db8:10:20::10/64 et route vers le VLAN 10 via 2001:db8:10:20::1, à rendre permanentes dans la topologie), clients DHCPv6, adresse de l'attaquant.
