"""
Utilitaires partagés pour les scripts d'attaque IPv6

Respecte le CONTRAT.md :
  - §2 règle "l'interface réseau est toujours un paramètre (--iface), jamais codée en dur"
  - §7 format des mesures : mesures/resultats.csv
        phase,attaque,essai,succes,cache_voisins,latence_ms,faux_positif,commentaire
  - §8 règle "les attaques se lancent seulement dans les conteneurs du lab"
        => ce module ne lance rien lui-même, il est juste importé par les scripts d'attaque
"""

import argparse
import csv
import os
import re
import subprocess
import time
from datetime import datetime

# mesures/resultats.csv est au même niveau que attaques/, donc on remonte
# d'un dossier depuis ce fichier (attaques/common.py -> racine du projet -> mesures/)
RACINE_PROJET = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(RACINE_PROJET, "mesures", "resultats.csv")

# Colonnes imposées par le CONTRAT.md (§7). On ajoute juste un horodatage
# à la fin, purement informatif, qui ne casse pas le format imposé par les 7
# premières colonnes puisqu'il est après "commentaire".
CSV_HEADER = [
    "phase", "attaque", "essai", "succes",
    "cache_voisins", "latence_ms", "faux_positif", "commentaire",
    "horodatage",
]


def base_arg_parser(description):
    """Parser d'arguments commun à na_spoof.py et ns_flood.py.
    Chaque script ajoute ensuite ses propres options spécifiques.
    """
    p = argparse.ArgumentParser(description=description)
    p.add_argument(
        "--iface", required=True,
        help="Interface réseau à utiliser dans le conteneur attacker (ex: eth1). "
             "Jamais codée en dur, cf. CONTRAT.md §2/§8.",
    )
    p.add_argument(
        "--phase", choices=["avant", "apres"], required=True,
        help="Phase de la campagne de mesure : 'avant' (sans protection) ou 'apres' (avec protection).",
    )
    p.add_argument(
        "--essai", type=int, required=True,
        help="Numéro de l'essai (pour répéter la même attaque plusieurs fois et comparer).",
    )
    p.add_argument(
        "--duree", type=float, default=30.0,
        help="Durée de l'attaque en secondes (défaut : 30).",
    )
    p.add_argument(
        "--commentaire", default="",
        help="Commentaire libre à inscrire dans la colonne 'commentaire' du CSV.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="N'envoie aucun paquet, affiche seulement ce qui serait fait (pour tester le script hors lab).",
    )
    return p


def log_resultat(attaque, phase, essai, succes, cache_voisins=None,
                  latence_ms=None, faux_positif=False, commentaire=""):
    """Ajoute une ligne au CSV commun mesures/resultats.csv.
    Crée le fichier et l'en-tête s'ils n'existent pas encore (premier appel
    de la campagne, par n'importe lequel des scripts).
    """
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    fichier_neuf = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        if fichier_neuf:
            writer.writerow(CSV_HEADER)
        writer.writerow([
            phase,
            attaque,
            essai,
            int(bool(succes)),
            "" if cache_voisins is None else cache_voisins,
            "" if latence_ms is None else f"{latence_ms:.2f}",
            int(bool(faux_positif)),
            commentaire,
            datetime.now().isoformat(timespec="seconds"),
        ])
    print(f"[CSV] Ligne ajoutée -> {CSV_PATH} "
          f"(phase={phase}, attaque={attaque}, essai={essai}, succes={int(bool(succes))})")


def mesurer_latence_ping(dest_ip, iface, count=4, timeout_s=2):
    """Mesure la latence moyenne (ms) vers dest_ip avec `ping -6`, en forçant
    la sortie sur `iface`. Retourne None si la mesure échoue (victime injoignable,
    ping absent, etc.) plutôt que de planter le script d'attaque.
    """
    try:
        resultat = subprocess.run(
            ["ping", "-6", "-c", str(count), "-W", str(timeout_s), "-I", iface, dest_ip],
            capture_output=True, text=True, timeout=count * timeout_s + 5,
        )
        # Ligne typique : rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", resultat.stdout)
        if m:
            return float(m.group(1))
        print(f"[WARN] ping vers {dest_ip} n'a pas abouti (0% reçu ?) : \n{resultat.stdout.strip()}")
    except FileNotFoundError:
        print("[WARN] commande 'ping' introuvable dans le conteneur.")
    except Exception as e:
        print(f"[WARN] mesure de latence impossible : {e}")
    return None


def attendre_ou_interrompre(duree_s, pas_s=0.5, condition_arret=None):
    """Attend duree_s secondes par petits pas, en s'arrêtant plus tôt si
    condition_arret() devient vraie (ex: Ctrl+C intercepté, ou objectif atteint).
    Permet un arrêt propre (cf. planning : "prévoir l'arrêt propre").
    """
    fin = time.time() + duree_s
    while time.time() < fin:
        if condition_arret is not None and condition_arret():
            return
        time.sleep(min(pas_s, max(0, fin - time.time())))
