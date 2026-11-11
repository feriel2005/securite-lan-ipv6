# Projet 10 : sécurité IPv6 du lien local

Dans un LAN IPv6, les machines font confiance à tout ce qu'elles reçoivent : n'importe qui peut se faire passer pour le routeur (RA), pour le serveur DHCPv6, ou empoisonner la table des voisins (ND).

Ce projet :

1. monte un LAN IPv6 **sans protection**,
2. l'**attaque en labo** et mesure les dégâts,
3. ajoute les **protections** (RA Guard, DHCPv6 Guard, filtrage ND, limitation de débit),
4. **rejoue les mêmes attaques** et compare avant/après.

> **Usage strictement pédagogique.** Toutes les attaques se lancent uniquement dans les conteneurs du lab (voir [Règles de sécurité](#règles-de-sécurité)).

---

## État d'avancement (11/11/2026)

| Élément | État |
|---|---|
| Réseau de base (Containerlab : radvd, Kea, victimes, attaquant) | Livré par Ramin et Ons, étiquette `v0.1-lab-base` |
| Adressage, préfixes /64, VLAN | Validés |
| Adresse fixe de l'attaquant (`::66`) via `start-attacker.sh` | En cours (Ramin, Ons) |
| Rapport de conception (PDF) | En cours, **échéance lundi 16/11** |
| Scripts d'attaque, `apply.sh`, scripts de mesure | À livrer le 20/11 |
| Campagnes « avant » puis « après », CSV, démo | 21 → 26/11 |
| Remise finale | **Échéance lundi 30/11** |

Le détail jour par jour est dans [`docs/Planning_Projet10_IPv6.docx`](docs/Planning_Projet10_IPv6.docx).

---

## Équipe

| Qui | Rôle | Dossier |
|---|---|---|
| Feriel | Cheffe de projet, attaques | `docs/`, `attaques/` |
| Ramin, Ons | Réseau et services | `docker/`, `lab/` |
| Emna Siala, Emna Salah | Filtrage du premier saut | `filtrage/` |
| Lina | Attaques | `attaques/` |
| Dora | Wireshark, détection, mesures | `detection/`, `mesures/` |

---

## Structure du dépôt

```
.
├── CONTRAT.md        # noms, adresses, ports : fait foi (modifié uniquement par Feriel)
├── README.md
├── docs/             # rapport, schémas (docs/schemas/topologie.png), planning
│   └── rapport/      # un sous-dossier par auteur pour le rapport de conception
├── docker/           # Dockerfile et image commune (radvd, Kea, FRR, scapy, tshark...)
├── lab/              # fichier YAML Containerlab, start-attacker.sh, scripts de remise à zéro
├── attaques/         # un script par attaque (Lina, Feriel)
├── filtrage/         # apply.sh : règles nftables appliquées sur le pont (les Emna)
├── detection/        # scripts de capture et de détection (Dora)
└── mesures/          # resultats.csv
```

Règle : **un dossier par groupe, on ne touche pas au dossier d'un autre sans le prévenir.**

---

## Prérequis

- **Ubuntu 24.04.1 Desktop** (ISO) dans une VM ou sur une machine, **pas WSL**. Même version pour tout le monde pour que Docker, Containerlab et nftables se comportent pareil.
- VM en **mode NAT**.
- Docker, Containerlab, nftables, Git, scapy, tshark.

---

## Démarrage rapide

> Les noms entre `<...>` sont à remplacer par les noms réels du dépôt (Ramin et Ons, à compléter).

```bash
# 1. Récupérer la base commune
git clone <url-du-depot>
cd <depot>
git checkout v0.1-lab-base

# 2. Construire l'image commune
docker build -t <nom-image> docker/

# 3. Lancer le lab (un conteneur par machine, câbles virtuels inclus)
sudo containerlab deploy -t lab/<topologie>.clab.yml

# 4. Entrer dans un conteneur (Containerlab préfixe les noms : clab-<lab>-<noeud>)
docker exec -it clab-<lab>-victim1 bash

# 5. Tout détruire
sudo containerlab destroy -t lab/<topologie>.clab.yml --cleanup
```

Pour fixer l'adresse de l'attaquant sans toucher aux victimes : `lab/start-attacker.sh` (en cours de correction).

---

## Topologie

Machines : `router`, `dhcp`, `victim1`, `victim2`, `attacker`.

- **VLAN 10 (hôtes)** : pont `br-hosts`, avec router, victim1, victim2, attacker.
- **VLAN 20 (serveur)** : pont `br-srv`, avec router et dhcp.
- Le routeur **relaie le DHCPv6** du VLAN 10 vers le serveur du VLAN 20 (les requêtes des clients ne traversent pas le routeur sans relais).

Schéma : `docs/schemas/topologie.png`

### Adressage (préfixe de documentation, non routé sur Internet)

| Élément | Valeur |
|---|---|
| Site /48 | `2001:db8:10::/48` |
| VLAN 10 /64 | `2001:db8:10:10::/64` |
| VLAN 20 /64 | `2001:db8:10:20::/64` |
| router (VLAN 10) | `2001:db8:10:10::1` (link-local `fe80::1`) |
| router (VLAN 20) | `2001:db8:10:20::1` |
| dhcp | `2001:db8:10:20::10` |
| victim1, victim2 | SLAAC + DHCPv6 |
| attacker | SLAAC + DHCPv6 ; adresse fixe `::66` posée par `start-attacker.sh` (à confirmer dans le CONTRAT) |

Configuration d'adressage : **SLAAC et DHCPv6 ensemble.**

### Ports de confiance (pont `br-hosts`)

| Port | Branché sur | Statut |
|---|---|---|
| eth1 | router | **de confiance** (seul à émettre des RA) |
| eth2 | victim1 | non fiable |
| eth3 | victim2 | non fiable |
| eth4 | attacker | non fiable |

Un RA est légitime s'il arrive par le port de confiance.

---

## Attaques et critères de réussite

| Attaque | Une attaque est réussie quand... |
|---|---|
| Faux RA | une victime a une route par défaut vers l'attaquant |
| Usurpation de voisins | le cache d'une victime associe l'IP du routeur à la MAC de l'attaquant |
| Faux DHCPv6 | une victime reçoit la configuration du faux serveur |
| Saturation du cache | le cache du routeur est plein ou le ping échoue |

Les attaques originales sont bienvenues, à condition de les annoncer à l'équipe.

## Protections

Règles `nftables` appliquées sur le pont Linux, regroupées dans `filtrage/apply.sh` (script externe, appliqué par-dessus le lab) :

- RA Guard : seuls les RA venant du port de confiance passent
- DHCPv6 Guard : pas de réponses de serveur DHCPv6 depuis les ports non fiables
- Filtrage des messages ND (voisins)
- Limitation de débit

---

## Mesures

Un seul fichier : `mesures/resultats.csv`, avec l'en-tête :

```
phase,attaque,essai,succes,cache_voisins,latence_ms,faux_positif,commentaire
```

- `phase` : `avant` ou `apres`
- `succes` : selon les critères du tableau ci-dessus
- Les mêmes attaques sont rejouées dans les deux phases pour que la comparaison soit valable.

Indicateurs du rapport : attaques réussies, taux de blocage, faux positifs, cache voisins, latence.

---

## Règles de sécurité

1. Les attaques se lancent **seulement dans les conteneurs du lab**, jamais depuis le terminal normal de la VM.
2. **Toujours préciser l'interface** dans les scripts (`iface="eth1"`).
3. La VM reste en **mode NAT**.
4. **Jamais** de test sur le réseau de l'école ou de la maison.

## Règles de travail

- **Le contrat prime** : si un nom ou une adresse change, Feriel le modifie d'abord dans `CONTRAT.md` et prévient tout le monde.
- **Personne ne modifie le réseau de base** de Ramin et Ons : les filtres vivent dans `filtrage/apply.sh`, les attaques dans `attaques/`, et Dora écoute sans rien modifier.
- Pousser à la fin de chaque séance ; un point rapide de 10 minutes par jour.
- Étiquettes Git : `v0.1-lab-base` (11/11), `v0.2-scripts` (20/11), `v0.3-avant` (22/11), `v0.4-apres` (26/11), `v1.0` (29/11).

---

## Livrables

- Le fichier de topologie (lab reproductible)
- Les chiffres avant/après
- L'analyse et la conception (rapport d'audit)
- Une démo d'une attaque neutralisée

---

## Glossaire

- **Conteneur** : « mini-machine Linux » légère avec ses outils déjà installés.
- **Image** : le modèle de cette machine ; même image pour tous, mêmes outils (radvd, Kea, FRR, scapy...).
- **Dockerfile** : fichier texte qui décrit comment construire l'image (`docker build`).
- **Containerlab** : monte tout le réseau à partir d'un fichier YAML (un conteneur par machine, câbles virtuels entre eux) ; une commande pour tout lancer ou tout détruire.
- **Pont Linux + nftables** : le switch du lab est un pont Linux ; les protections (RA Guard, etc.) sont des règles nftables appliquées sur ce pont.
