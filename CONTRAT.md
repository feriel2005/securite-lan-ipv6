# CONTRAT – Projet 10 : sécurité IPv6 du lien local
Version 1.1. Toute modification passe par Feriel, qui prévient l'équipe.

## 1. Environnement
- Ubuntu 24.04.1 Desktop (même version pour tous), dans une VM, pas WSL
- Docker, Containerlab, nftables, Git, scapy, tshark

## 2. Topologie
Machines : router, dhcp, victim1, victim2, attacker
- VLAN 10 (hôtes) : pont br-hosts, avec router, victim1, victim2, attacker
- VLAN 20 (serveur) : pont br-srv, avec router et dhcp
- Le routeur relaie le DHCPv6 du VLAN 10 vers le serveur du VLAN 20
- Interfaces du routeur : eth1 côté VLAN 10, eth2 côté VLAN 20
Schéma : docs/schemas/topologie.png

## 3. Adressage (préfixe de documentation, non routé sur Internet)
| Élément | Valeur |
|---|---|
| Site /48 | 2001:db8:10::/48 |
| VLAN 10 /64 | 2001:db8:10:10::/64 |
| VLAN 20 /64 | 2001:db8:10:20::/64 |
| router (VLAN 10) | 2001:db8:10:10::1 (link-local fe80::1) |
| router (VLAN 20) | 2001:db8:10:20::1 |
| dhcp | 2001:db8:10:20::10 |
| victim1, victim2 | SLAAC + DHCPv6 |
| attacker | 2001:db8:10:10::66 (fixée par start-attacker.sh) |

## 4. Ports de confiance (pont br-hosts)
Numéros des ports du pont, à ne pas confondre avec les interfaces du routeur (§2).
| Port du pont | Branché sur | Statut |
|---|---|---|
| eth1 | router | de confiance (seul à émettre des RA) |
| eth2 | victim1 | non fiable |
| eth3 | victim2 | non fiable |
| eth4 | attacker | non fiable |
Un RA est légitime s'il arrive par le port de confiance.

## 5. Configuration d'adressage
SLAAC et DHCPv6 ensemble.

## 6. Attaque réussie, c'est quand...
| Attaque | Critère |
|---|---|
| Faux RA | une victime a une route par défaut vers l'attaquant |
| Usurpation de voisins | le cache d'une victime associe l'IP du routeur à la MAC de l'attaquant |
| Faux DHCPv6 | une victime reçoit la configuration du faux serveur |
| Saturation du cache | le cache du routeur est plein ou le ping échoue |

## 7. Format des mesures (mesures/resultats.csv)
phase,attaque,essai,succes,cache_voisins,latence_ms,faux_positif,commentaire
- phase : avant ou apres

## 8. Règles de sécurité
1. Les attaques se lancent seulement dans les conteneurs du lab, jamais depuis le terminal normal de la VM
2. Toujours préciser l'interface dans les scripts (iface="eth1")
3. La VM reste en mode NAT
4. Jamais de test sur le réseau de l'école ou de la maison

## 9. Qui fait quoi
| Qui | Rôle | Dossier |
|---|---|---|
| Feriel | Cheffe de projet, attaques | docs/, attaques/ |
| Ramin, Ons | Réseau et services | docker/, lab/ |
| Emna Siala, Emna Salah | Filtrage du premier saut | filtrage/ |
| Lina | Attaques | attaques/ |
| Dora | Wireshark, détection, mesures | detection/, mesures/ |

## 10. Échéances
- Lundi 16/11/2026 : rapport de conception (PDF)
- Lundi 30/11/2026 : remise finale (code, lab YAML, CSV avant/après, démo)
