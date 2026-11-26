#!/usr/bin/env python3
"""
mesurer_cache_routeur.py — Relevé du cache de voisins du ROUTEUR, via docker exec.
Projet 10 — Sécurité du lien local IPv6

Ce n'est PAS un script d'attaque : il ne lance rien sur le routeur, il lit
juste son état (`ip -6 neigh`) et complète le CSV commun avec le nombre
d'entrées de cache, ce que ns_flood.py ne peut pas faire depuis le
conteneur attacker (CONTRAT.md §8 : les attaques restent dans leur conteneur,
mais une simple lecture de mesure, depuis l'hôte, n'est pas une attaque).

À lancer DEPUIS L'HÔTE (pas dans un conteneur), typiquement juste après
avoir lancé ns_flood.py dans le conteneur attacker :

  python3 mesures/mesurer_cache_routeur.py \
      --conteneur router --iface-routeur eth1 \
      --phase avant --essai 1 --attaque ns_flood \
      --ping-depuis router --ping-cible 2001:db8:10:10::10
"""

import argparse
import os
import re
import subprocess
import sys

# attaques/common.py est le dossier voisin de mesures/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attaques"))
from common import log_resultat  # noqa: E402


def compter_cache(conteneur, iface_routeur):
    """Exécute `ip -6 neigh show dev <iface>` DANS le conteneur du routeur
    via `docker exec`, et compte les lignes (= nombre d'entrées de cache).
    """
    try:
        resultat = subprocess.run(
            ["docker", "exec", conteneur, "ip", "-6", "neigh", "show", "dev", iface_routeur],
            capture_output=True, text=True, timeout=10, check=True,
        )
        lignes = [l for l in resultat.stdout.splitlines() if l.strip()]
        return len(lignes), resultat.stdout
    except subprocess.CalledProcessError as e:
        print(f"[ERREUR] docker exec a échoué : {e.stderr}")
    except FileNotFoundError:
        print("[ERREUR] la commande 'docker' n'est pas trouvée sur cette machine.")
    return None, ""


def ping_depuis_conteneur(conteneur, dest_ip, count=4):
    """Mesure la latence en pinguant DEPUIS un conteneur du lab (ex: le
    routeur, ou une victime) vers dest_ip, via docker exec.
    """
    try:
        resultat = subprocess.run(
            ["docker", "exec", conteneur, "ping", "-6", "-c", str(count), dest_ip],
            capture_output=True, text=True, timeout=count * 3 + 5,
        )
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", resultat.stdout)
        if m:
            return float(m.group(1))
    except Exception as e:
        print(f"[WARN] ping depuis {conteneur} impossible : {e}")
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conteneur", default="router", help="Nom du conteneur à interroger (défaut: router).")
    parser.add_argument("--iface-routeur", required=True, help="Interface du routeur à inspecter (ex: eth1).")
    parser.add_argument("--phase", choices=["avant", "apres"], required=True)
    parser.add_argument("--essai", type=int, required=True)
    parser.add_argument("--attaque", required=True, help="Nom de l'attaque mesurée (ex: ns_flood).")
    parser.add_argument("--ping-depuis", default=None, help="Conteneur depuis lequel pinguer (optionnel).")
    parser.add_argument("--ping-cible", default=None, help="Adresse à pinguer depuis --ping-depuis.")
    parser.add_argument("--commentaire", default="")
    args = parser.parse_args()

    nb_entrees, brut = compter_cache(args.conteneur, args.iface_routeur)
    print(f"[*] Cache de voisins de {args.conteneur}/{args.iface_routeur} : {nb_entrees} entrée(s)")
    if brut:
        print(brut)

    latence_ms = None
    if args.ping_depuis and args.ping_cible:
        latence_ms = ping_depuis_conteneur(args.ping_depuis, args.ping_cible)
        print(f"[*] Latence {args.ping_depuis} -> {args.ping_cible} : {latence_ms} ms")

    # Heuristique simple de "succès" pour la saturation : au-delà d'un seuil
    # arbitraire (à ajuster selon ce que vous observez réellement en 'avant'),
    # ou ping perdu. À affiner une fois les vraies valeurs connues (planning
    # étape 6 : "ajuster le volume ou la taille du cache si l'effet est invisible").
    SEUIL_SATURATION = 512
    ping_perdu = args.ping_cible is not None and latence_ms is None
    succes = (nb_entrees is not None and nb_entrees >= SEUIL_SATURATION) or ping_perdu

    log_resultat(
        attaque=args.attaque,
        phase=args.phase,
        essai=args.essai,
        succes=succes,
        cache_voisins=nb_entrees,
        latence_ms=latence_ms,
        faux_positif=False,
        commentaire=f"relevé via docker exec sur {args.conteneur}. {args.commentaire}".strip(),
    )


if __name__ == "__main__":
    main()
