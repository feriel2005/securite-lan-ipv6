import argparse
import csv
import os
import re
import subprocess
import sys
import time

# réutilise la lecture du cache déjà écrite par Lina/Feriel, sans dupliquer
# le code ni leur fichier (attaques/mesurer_cache_routeur.py n'est pas modifié)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attaques"))
from mesurer_cache_routeur import compter_cache  # noqa: E402

LAB = "clab-ipv6lab"
RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(RACINE, "mesures", "resultats.csv")
CAPTURES = os.path.join(RACINE, "mesures", "captures")
CIBLE_PING = "2001:db8:10:20::10"          # serveur dhcp, hors VLAN 10
ROUTEUR_IP = "2001:db8:10:10::1"
VICTIME_IP = "2001:db8:10:10::10"

ATTAQUES = ["fake_ra", "na_spoof", "ns_flood", "fake_dhcpv6"]


def sh(*args, timeout=None, check=False):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def docker_exec(conteneur, *cmd, timeout=None):
    return sh("docker", "exec", f"{LAB}-{conteneur}", *cmd, timeout=timeout)


def mac_routeur():
    r = docker_exec("router", "cat", "/sys/class/net/eth1/address", timeout=10)
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("[ERREUR] impossible de lire la MAC du routeur : le lab est-il déployé ?")
    return r.stdout.strip()


def remise_a_zero():
    for v in ("victim1", "victim2"):
        docker_exec(v, "ip", "-6", "route", "del", "default", "via", "fe80::2", "dev", "eth1", timeout=10)
        docker_exec(v, "ip", "-6", "neigh", "flush", "dev", "eth1", timeout=10)


def route_vers_attaquant(victime):
    r = docker_exec(victime, "ip", "-6", "route", "show", "default", timeout=10)
    return "via fe80::2 " in r.stdout or r.stdout.strip().endswith("via fe80::2")


def cache_usurpe(victime):
    """§6 : le cache de la victime associe l'IP du routeur à la MAC de l'attaquant."""
    r = docker_exec(victime, "ip", "-6", "neigh", "show", ROUTEUR_IP, timeout=10)
    return "FAILED" not in r.stdout and r.stdout.strip() != "" and "lladdr" in r.stdout


def demarrer_detecteur(phase, attaque, essai, duree, mac):
    os.makedirs(CAPTURES, exist_ok=True)
    chemin_log = os.path.join(CAPTURES, f"detection_{phase}_{attaque}_{essai}.log")
    script = os.path.join(RACINE, "detection", "detecteur.py")
    log_f = open(chemin_log, "w")
    proc = subprocess.Popen(
        ["docker", "exec", "-i", f"{LAB}-br-hosts", "python3", "-",
         "--phase", phase, "--essai", str(essai), "--duree", str(duree + 8),
         "--routeur-mac", mac],
        stdin=open(script), stdout=log_f, stderr=subprocess.STDOUT, text=True,
    )
    return proc, chemin_log


def derniere_ligne_csv(phase, attaque, essai):
    if not os.path.exists(CSV_PATH):
        return None, None
    with open(CSV_PATH, newline="") as f:
        lignes = list(csv.reader(f))
    for i in range(len(lignes) - 1, 0, -1):
        l = lignes[i]
        if len(l) >= 3 and l[0] == phase and l[1] == attaque and l[2] == str(essai):
            return i, lignes
    return None, lignes


def remplir_cache_latence(phase, attaque, essai, cache_voisins, latence_ms):
    """Complète cache_voisins et/ou latence_ms dans la ligne (phase, attaque,
    essai) déjà écrite par le script d'attaque, au lieu d'ajouter une ligne
    séparée comme le fait mesurer_cache_routeur.py en ligne de commande."""
    idx, lignes = derniere_ligne_csv(phase, attaque, essai)
    if idx is None:
        print(f"    [ATTENTION] aucune ligne {phase},{attaque},{essai} à compléter.")
        return
    if cache_voisins is not None and not lignes[idx][4]:
        lignes[idx][4] = str(cache_voisins)
    if latence_ms is not None and not lignes[idx][5]:
        lignes[idx][5] = f"{latence_ms:.2f}"
    with open(CSV_PATH, "w", newline="") as f:
        csv.writer(f).writerows(lignes)
    print(f"    [COMPLETE] ligne {idx + 1} : cache_voisins={cache_voisins}, latence_ms={latence_ms}")


def corriger_succes(phase, attaque, essai, preuve_ok):
    """Met succes=1 dans la dernière ligne (phase, attaque, essai) si la preuve
    côté victime dit que l'attaque a réussi mais que le script a écrit 0."""
    if not preuve_ok:
        return False
    idx, lignes = derniere_ligne_csv(phase, attaque, essai)
    if idx is None:
        print(f"    [ATTENTION] aucune ligne {phase},{attaque},{essai} trouvée dans le CSV.")
        return False
    if lignes[idx][3] == "1":
        return False
    lignes[idx][3] = "1"
    with open(CSV_PATH, "w", newline="") as f:
        csv.writer(f).writerows(lignes)
    print(f"    [CORRIGE] ligne {idx + 1} du CSV : succes 0 -> 1 (preuve côté victime)")
    return True


def lancer_attaque(nom, phase, essai, duree, mac):
    if nom == "fake_ra":
        return subprocess.Popen(
            ["docker", "exec", f"{LAB}-attacker", "python3", "/project/attaques/fake_ra.py",
             "--iface", "eth1", "--phase", phase, "--essai", str(essai),
             "--mode", "mitm", "--duree", str(duree)])
    if nom == "na_spoof":
        return subprocess.Popen(
            ["docker", "exec", f"{LAB}-attacker", "python3", "/project/attaques/na_spoof.py",
             "--iface", "eth1", "--phase", phase, "--essai", str(essai),
             "--routeur-ip", ROUTEUR_IP, "--victime-ip", VICTIME_IP,
             "--mode", "mitm", "--routeur-mac", mac, "--duree", str(duree), "--silencieux"])
    if nom == "ns_flood":
        return subprocess.Popen(
            ["docker", "exec", f"{LAB}-attacker", "python3", "/project/attaques/ns_flood.py",
             "--iface", "eth1", "--phase", phase, "--essai", str(essai),
             "--prefixe", "2001:db8:10:10::/64", "--nb-adresses", "2000",
             "--debit", "200", "--duree", str(duree), "--ping-cible", ROUTEUR_IP, "--silencieux"])
    if nom == "fake_dhcpv6":
        return subprocess.Popen(
            ["docker", "exec", f"{LAB}-attacker", "python3", "/project/attaques/fake_dhcpv6.py",
             "--iface", "eth1", "--phase", phase, "--essai", str(essai), "--duree", str(duree)])
    raise ValueError(nom)


def un_essai(nom, phase, essai, duree, mac):
    print(f"\n=== {nom} | {phase} | essai {essai} ===")
    remise_a_zero()
    proc_det, chemin_log = demarrer_detecteur(phase, nom, essai, duree, mac)
    time.sleep(2)

    proc_ping = None
    if nom == "fake_ra":
        time.sleep(1)
        proc_ping = subprocess.Popen(
            ["docker", "exec", f"{LAB}-victim1", "ping", "-6", "-c", str(max(duree - 4, 3)),
             "-i", "1", CIBLE_PING], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    proc_att = lancer_attaque(nom, phase, essai, duree, mac)
    proc_att.wait(timeout=duree + 15)
    if proc_ping:
        proc_ping.wait(timeout=10)

    preuve = False
    if nom in ("fake_ra",):
        preuve = route_vers_attaquant("victim1") or route_vers_attaquant("victim2")
    elif nom == "na_spoof":
        preuve = cache_usurpe("victim1") or cache_usurpe("victim2")
    if preuve:
        corriger_succes(phase, nom, essai, True)
    elif nom == "ns_flood":
        nb_entrees, _ = compter_cache(f"{LAB}-router", "eth1")
        print(f"    cache de voisins du routeur : {nb_entrees} entrée(s)")
        remplir_cache_latence(phase, nom, essai, nb_entrees, None)
    else:
        print("    (pas de correction automatique : vérifie quand même la ligne pour fake_dhcpv6)")

    proc_det.wait(timeout=15)
    remise_a_zero()
    print(f"    log détecteur : {chemin_log}")
    idx, lignes = derniere_ligne_csv(phase, nom, essai)
    if idx is not None:
        print("    ligne CSV      :", ",".join(lignes[idx]))
    else:
        print("    [ATTENTION] toujours aucune ligne dans le CSV pour cet essai.")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phase", choices=["avant", "apres"], required=True)
    p.add_argument("--essais", type=int, default=3, help="nombre d'essais par attaque")
    p.add_argument("--attaques", nargs="+", choices=ATTAQUES, default=ATTAQUES)
    p.add_argument("--duree", type=int, default=15, help="durée d'un essai, en secondes")
    args = p.parse_args()

    mac = mac_routeur()
    print(f"[*] MAC du routeur : {mac}  |  phase={args.phase}  "
          f"attaques={args.attaques}  essais={args.essais}  duree={args.duree}s")

    for nom in args.attaques:
        for n in range(1, args.essais + 1):
            try:
                un_essai(nom, args.phase, n, args.duree, mac)
            except subprocess.TimeoutExpired:
                print(f"    [ERREUR] {nom} essai {n} a dépassé le délai, on passe au suivant.")
                remise_a_zero()

    print("\n[OK] campagne terminée. Vérifie mesures/resultats.csv et mesures/captures/.")
    print("     Puis : python3 mesures/analyser.py")


if __name__ == "__main__":
    main()
