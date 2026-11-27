# Lab de base (réseau non protégé)

Réseau de base du projet 10, construit par le groupe Réseau & Services (Ons, Ramin). Il est volontairement **sans protection** : les attaques doivent réussir avant que les règles de filtrage soient posées.

## Commandes
- Construire l'image : `sh docker/build.sh`
- Démarrer le lab : `sh lab/scripts/deploy.sh`
- Détruire le lab : `sh lab/scripts/destroy.sh`
- Vérifier le réseau de base : `sh lab/scripts/check-base.sh`
- Déboguer le relais DHCPv6 : `sh lab/scripts/test-relay.sh` (lance un `dhclient` manuel sur victim1 ; à n'utiliser que pour le débogage)
- Entrer dans un nœud : `docker exec -it clab-ipv6lab-<nœud> bash`

## Nœuds
Conteneurs : `clab-ipv6lab-` + router, dhcp, victim1, victim2, attacker, br-hosts, br-srv.
Tous utilisent l'image `ipv6lab:1.0`. Sur chaque nœud, `eth1` est l'interface du lab ; `eth0` est le réseau de gestion Docker.

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
- Les ponts n'ont pas d'IPv6 propre, le spanning tree est désactivé et le snooping multicast aussi (le multicast IPv6 est inondé sur tous les ports).
- Relais DHCPv6 : eth1 -> 2001:db8:10:20::10 via eth2.

## DHCPv6 (Kea) et clients
- Kea (nœud dhcp) : `lab/configs/dhcp/kea-dhcp6.conf`, lancé par `lab/configs/dhcp/start.sh`. Ce script pose aussi l'adresse 2001:db8:10:20::10/64 et la route vers 2001:db8:10:10::/64 via 2001:db8:10:20::1 à chaque démarrage.
- Pool : 2001:db8:10:10::1000 à 2001:db8:10:10::1fff.
- Options légitimes : DNS 2001:db8:10:20::53, domaine `legit.lab.local`, identifiant du serveur (DUID) de type EN dont l'identifiant est « LEGIT ». Ces valeurs permettent de distinguer le vrai serveur d'un faux.
- Clients (victim1, victim2, attacker) : `lab/configs/hosts/start.sh` (SLAAC, puis `dhclient -6 -N`). Chaque nœud a donc deux adresses globales : une SLAAC (/64) et une DHCPv6 (/128).
- L'adresse fixe 2001:db8:10:10::66 de l'attaquant n'est pas appliquée : la ligne est commentée dans `hosts/start.sh` en attendant la décision de Feriel (le CONTRAT dit « SLAAC + DHCPv6 »).

## Fichiers
- Commutateurs : `lab/configs/switch/bridge.sh`
- Routeur (adresses, forwarding, radvd, relais) : `lab/configs/router/router.sh`
- RA : `lab/configs/router/radvd.conf`
- Serveur DHCPv6 : `lab/configs/dhcp/` (`start.sh`, `kea-dhcp6.conf`)
- Clients et attaquant : `lab/configs/hosts/start.sh`
- Topologie : `lab/topology.clab.yml`
- Scripts : `lab/scripts/` (deploy, destroy, check-base, test-relay)

## État normal vérifié (avant attaque)
- victim1, victim2 et attacker : une adresse SLAAC en 2001:db8:10:10::/64, une adresse DHCPv6 du pool de Kea, et une seule route par défaut : `default via fe80::1 dev eth1 proto ra`.
- Baux Kea : le fichier `/var/lib/kea/kea-leases6.csv` du nœud dhcp contient un bail par client.
- Ping du routeur et ping de 2001:db8:10:20::10 à travers le routeur (ttl=63) : OK.
- Cache des voisins des victimes : l'adresse du routeur (fe80::1 et 2001:db8:10:10::1) pointe vers la vraie MAC du routeur.
- Les RA du routeur (source fe80::1, M=1, O=1) sont visibles sur les hôtes.
- Relais DHCPv6 : le journal du relais (`/var/log/dhcrelay.log`) montre Solicit, Advertise, Request et Reply relayés pour chaque client.
- Après un déploiement propre, aucune manipulation manuelle n'est nécessaire.

## Limites connues
- La MAC du routeur change à chaque redéploiement : la relire avec `docker exec clab-ipv6lab-router ip link show eth1` avant de la comparer.
- Le DNS légitime 2001:db8:10:20::53 n'appartient à aucun nœud du lab : c'est seulement une valeur d'option DHCPv6.
- Le dossier `lab/clab-ipv6lab/` est généré par Containerlab à chaque déploiement : il est ignoré par Git et ne doit pas être commité.

## Règles de sécurité (CONTRAT §8)
1. Les attaques se lancent seulement dans les conteneurs du lab, jamais depuis le terminal de la VM.
2. Toujours préciser l'interface dans les scripts (`iface="eth1"`).
3. La VM reste en mode NAT.
4. Jamais de test sur le réseau de l'école ou de la maison.