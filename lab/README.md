# Lab de base (réseau non protégé)

Réseau de base du projet 10, construit par le groupe Réseau & Services. Il est volontairement **sans protection** : les attaques doivent réussir avant que les Emna posent leurs règles.

## Commandes
- Construire l'image : `sh docker/build.sh`
- Démarrer le lab : `sh lab/scripts/deploy.sh`
- Détruire le lab : `sh lab/scripts/destroy.sh`
- Vérifier le réseau de base : `sh lab/scripts/check-base.sh`
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
- Les ponts n'ont pas d'IPv6 propre, le spanning tree est désactivé et le snooping multicast aussi (le multicast IPv6 est inondé sur tous les ports).
- Relais DHCPv6 : eth1 -> 2001:db8:10:20::10 via eth2.

## Fichiers
- Commutateurs : `lab/configs/switch/bridge.sh`
- Routeur (adresses, forwarding, radvd, relais) : `lab/configs/router/router.sh`
- RA : `lab/configs/router/radvd.conf`
- Scripts : `lab/scripts/` (deploy, destroy, check-base, test-relay)

## État normal vérifié (avant attaque)
- victim1 et victim2 : adresse SLAAC en 2001:db8:10:10::/64 et une seule route par défaut, `default via fe80::1 dev eth1 proto ra`.
- Ping du routeur et ping de 2001:db8:10:20::10 (à travers le routeur, ttl=63) : OK.
- Cache des voisins des victimes : l'adresse du routeur (fe80::1 et 2001:db8:10:10::1) pointe vers la vraie MAC du routeur.
- Les RA du routeur (source fe80::1, M=1, O=1) sont visibles sur les hôtes.
- Relais DHCPv6 vérifié par capture : Solicit sur eth1 (ff02::1:2), relay-fwd sur eth2 vers 2001:db8:10:20::10.

## Limites connues
- Le serveur Kea n'est pas encore configuré : les victimes n'ont pas d'adresse DHCPv6.
- L'adresse et la route du nœud `dhcp` (2001:db8:10:20::10/64, route vers le VLAN 10 via 2001:db8:10:20::1) sont posées à la main et disparaissent à chaque redéploiement.
- La MAC du routeur change à chaque redéploiement : la relire avec `docker exec clab-ipv6lab-router ip link show eth1`.

---

# Messages pour l'équipe

## À Feriel (cheffe de projet, CONTRAT.md)
1. Le lab de base est prêt sur la branche `origin main` (déploiement : `sh lab/scripts/deploy.sh`).
2. Merci d'ajouter au contrat la numérotation des ports du routeur : `router:eth1` = VLAN 10 (pont br-hosts, port eth1) et `router:eth2` = VLAN 20 (pont br-srv, port eth1).
3. Merci d'ajouter au contrat les drapeaux RA décidés avec Ramin : M=1, O=1, A=1.
4. Merci de noter dans le contrat que les conteneurs s'appellent `clab-ipv6lab-<nœud>` et que le pont Linux de chaque commutateur s'appelle `br0`.
5. IPv6 est désactivé sur eth0 (réseau de gestion Docker) dans tous les nœuds, pour que la seule route par défaut IPv6 vienne des RA : la condition de réussite du faux RA reste donc non ambiguë.
6. Question à trancher : l'attaquant est en « SLAAC + DHCPv6 » dans le contrat, mais le schéma indique l'adresse fixe 2001:db8:10:10::66. Proposition : adresse fixe en plus de l'adresse dynamique.
7. Rappels : confirmer que le dépôt est bien celui du projet 10 (le nom `sample-to-detection-pipeline` ne le laisse pas penser), la version exacte d'Ubuntu (le PDF dit 24.04.1, le contrat 24.04.x), et la fin tronquée de la remarque du PDF « prévoir par Feriel dans le schéma et par Ramin et Ons dans la config ».
8. Merci de me donner accès au dépôt (collaborateur) si ce n'est pas déjà fait.

## À Ranim (DHCPv6, clients, vérifications)
1. Le réseau de base est prêt : routeur, RA (M=1, O=1, A=1), relais DHCPv6, ponts. Les images, la topologie et les scripts sont dans `docker/` et `lab/`.
2. Kea sur `dhcp` : sous-réseau `2001:db8:10:10::/64` (le relais renseigne ce sous-réseau avec l'adresse 2001:db8:10:10::1), avec un pool d'adresses puisque M=1. Choisis une plage qui évite le routeur (::1) et l'attaquant (::66), par exemple ::100 à ::1ff.
3. Le nœud `dhcp` doit avoir en permanence l'adresse `2001:db8:10:20::10/64` et une route vers 2001:db8:10:10::/64 via `2001:db8:10:20::1`. Pour l'instant, je les pose à la main et elles disparaissent à chaque déploiement : à toi de les ajouter dans la section `exec` du nœud `dhcp` de `lab/topology.clab.yml` (et de monter ta configuration Kea avec `binds`).
4. Les clients (victim1, victim2, attacker) doivent lancer un client DHCPv6 (`dhclient -6 -v eth1`) : recevoir M=1 ne le démarre pas tout seul dans un conteneur nu. Chaque victime doit avoir à terme une adresse SLAAC et une adresse DHCPv6.
5. Le relais est vérifié : `sh lab/scripts/test-relay.sh` montre les Solicit sur eth1 et les relay-fwd vers le serveur sur eth2. Il manque seulement la réponse de Kea.
6. Ne change pas un nom ou une adresse sans passer par Feriel. Si tu as besoin d'un paquet dans l'image, ajoute-le dans `docker/Dockerfile`, reconstruis, et préviens tout le monde.
7. Vérifications et mesures de départ : `sh lab/scripts/check-base.sh` donne l'état normal. Les mesures « avant » vont dans `mesures/resultats.csv` avec les scripts et le format de Dora.

## À Emna Siala et Emna Salah (filtrage du premier saut)
1. Le pont à protéger est dans le conteneur `clab-ipv6lab-br-hosts`, et le pont Linux s'y appelle `br0`. Vos règles nftables s'appliquent sur ce pont.
2. Ports de `br-hosts` (ordre imposé par le contrat) : eth1 = router (de confiance, seul émetteur de RA légitime), eth2 = victim1, eth3 = victim2, eth4 = attacker (non fiables).
3. Les RA légitimes sont émis depuis `fe80::1` (MAC du routeur), avec M=1, O=1, A=1 et le préfixe 2001:db8:10:10::/64. Le serveur DHCPv6 légitime est `2001:db8:10:20::10` et il est joint à travers le routeur, donc ses réponses arrivent sur eth1.
4. Le pont est transparent : pas d'IPv6 propre, STP désactivé, snooping multicast désactivé. nftables est installé dans l'image commune.
5. Votre dossier est `filtrage/`. Ne modifiez pas `lab/` ou `docker/` sans prévenir Ons : un changement de nom de port ou de pont casse tout le monde. Si vos règles doivent être appliquées au déploiement, dites-moi comment vous voulez les brancher (ligne `exec` du nœud `br-hosts`, ou script séparé).
6. Après vos règles, il faut vérifier que le fonctionnement normal marche encore : les vrais RA passent, un client reçoit son adresse SLAAC et sa route par défaut via fe80::1, le DHCPv6 relayé marche. Le script `lab/scripts/check-base.sh` le vérifie.

## À Lina et Feriel (attaques)
1. L'attaquant est le conteneur `clab-ipv6lab-attacker`, branché sur `br-hosts:eth4`. Dans ses conteneurs, l'interface LAN est toujours `eth1` : précisez-la dans vos scripts (`iface="eth1"`). `eth0` est le réseau de gestion Docker, sans IPv6 : ne l'utilisez pas.
2. scapy, tshark, tcpdump et ndisc6 sont installés dans l'image. Lancez les attaques uniquement depuis les conteneurs du lab, jamais depuis le terminal de la VM.
3. État normal avant attaque : chaque victime a une seule route par défaut, `default via fe80::1 dev eth1 proto ra`, et le routeur dans son cache des voisins avec sa vraie MAC. Les critères de réussite du contrat se mesurent donc sans ambiguïté.
4. La MAC du routeur change à chaque déploiement : relisez-la avec `docker exec clab-ipv6lab-router ip link show eth1` avant de comparer.
5. Les RA légitimes sont envoyés toutes les 3 à 10 secondes avec M=1, O=1, A=1, depuis `fe80::1`. Pour être utile, un faux RA doit se distinguer ou l'emporter sur celui-ci.
6. Le relais DHCPv6 est en place : un faux serveur DHCPv6 sur le VLAN 10 doit répondre avant le vrai serveur (VLAN 20, 2001:db8:10:20::10). Les victimes n'ont pas encore d'adresse DHCPv6, car Ramin finalise Kea.
7. Le réseau est sans protection pour l'instant : c'est voulu, pour mesurer les attaques réussies. Ne commencez la campagne officielle que quand Ramin et moi confirmons que le réseau est prêt.
8. L'adresse de l'attaquant (fixe ::66 ou SLAAC) reste à trancher avec Feriel.

## À Dora (Wireshark et mesures)
1. Les captures se font dans les conteneurs. `tshark` est installé dans l'image. Filtre des RA : `icmpv6.type==134`. Exemple : `docker exec clab-ipv6lab-victim1 tshark -i eth1 -a duration:15 -Y "icmpv6.type==134"`.
2. État de départ vérifié : adresse SLAAC en 2001:db8:10:10::/64, route par défaut unique via fe80::1, ping du routeur, ping de 2001:db8:10:20::10 à travers le routeur, cache des voisins avec la vraie MAC du routeur. `sh lab/scripts/check-base.sh` produit tout cela d'un coup.
3. La MAC du routeur change à chaque redéploiement : relis-la dans chaque série de mesures.
4. Quand Kea sera configuré, chaque victime aura deux adresses globales (SLAAC et DHCPv6), puisque M=1 et A=1. Tiens-en compte dans les chiffres de `cache_voisins`.
5. `eth0` (gestion Docker) n'a pas d'IPv6 et ne doit pas apparaître dans tes mesures ; seule `eth1` compte.
6. Les mesures « avant » doivent être faites sur le réseau sans protection : dis-moi quand tu veux que je fige une version du lab (étiquette Git `v0.1-lab-base`) pour que « avant » et « après » partent de la même base.
7. Le CSV `mesures/resultats.csv` est à toi : je ne touche pas à ce dossier.

## À toute l'équipe
- Branche de travail : `origin main`. Un seul dépôt, un dossier par groupe.
- Pour démarrer : `sh docker/build.sh`, puis `sh lab/scripts/deploy.sh`. Pour tout remettre à zéro : `sh lab/scripts/destroy.sh`.
- Tout changement de nom, d'adresse ou de port passe d'abord par Feriel et le CONTRAT.md.
- Règles de sécurité : attaques seulement dans les conteneurs, interface toujours précisée, VM en NAT, jamais de test sur un réseau réel.
