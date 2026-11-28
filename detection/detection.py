import argparse
import collections
import json
import subprocess
import sys
import time
from datetime import datetime

try:
    from scapy.all import (
        Ether, IPv6, UDP, ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS,
        ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, sniff, Raw,
    )
except ImportError:
    sys.exit("[ERREUR] scapy n'est pas installé dans ce conteneur.")

# Valeurs du CONTRAT.md / lab/README.md
IP_ROUTEUR = "2001:db8:10:10::1"
LL_ROUTEUR = "fe80::1"
PORT_CONFIANCE = "eth1"
PORT_ATTAQUANT = "eth4"
PORTS_VICTIMES = ("eth2", "eth3")
PORTS_PAR_DEFAUT = ["eth1", "eth2", "eth3", "eth4"]
DUID_LEGIT = b"LEGIT"          # identifiant EN du serveur Kea légitime
SEUIL_NS_NA_PAR_S = 100        # au-dessus : saturation du cache (à ajuster)


def lire_mac_routeur(pont="br0", port=PORT_CONFIANCE):
    """Lit dans la table du pont la MAC apprise sur le port de confiance.
    Il vaut mieux la donner avec --routeur-mac (elle change à chaque
    redéploiement : docker exec clab-ipv6lab-router ip link show eth1)."""
    try:
        sortie = subprocess.run(
            ["bridge", "fdb", "show", "br", pont],
            capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    for ligne in sortie.splitlines():
        champs = ligne.split()
        if len(champs) > 2 and "dev" in champs and champs[champs.index("dev") + 1] == port:
            if "permanent" in ligne or champs[0].startswith("33:33") or champs[0].startswith("01:00"):
                continue
            return champs[0].lower()
    return None


class Detecteur:
    def __init__(self, mac_routeur, sortie=sys.stdout):
        self.mac_routeur = mac_routeur.lower() if mac_routeur else None
        self.sortie = sortie
        self.alertes = collections.Counter()
        # trames de l'attaquant : vues à l'entrée (eth4) et revues ailleurs
        self.vues_entree = collections.Counter()   # clé : type de message
        self.vues_sortie = collections.Counter()
        self.legit_vus = collections.Counter()     # RA légitimes vus (ports)
        self.mac_attaquant = None
        self.ns_na_fenetre = collections.deque()   # horodatages pour le débit
        self.max_debit = 0

    # --- utilitaires -------------------------------------------------------
    def _alerte(self, genre, port, detail):
        self.alertes[genre] += 1
        ligne = {"t": datetime.now().isoformat(timespec="milliseconds"),
                 "alerte": genre, "port": port, "detail": detail}
        print(json.dumps(ligne, ensure_ascii=False), file=self.sortie, flush=True)

    def _compter_attaquant(self, port, mac_src, type_msg):
        """Compte une trame de l'attaquant à l'entrée ou à la sortie du pont."""
        if port == PORT_ATTAQUANT and mac_src != self.mac_routeur:
            self.mac_attaquant = mac_src
            self.vues_entree[type_msg] += 1
        elif mac_src == self.mac_attaquant and port != PORT_ATTAQUANT:
            self.vues_sortie[type_msg] += 1

    # --- traitement d'une trame --------------------------------------------
    def traiter(self, pkt, port):
        if Ether not in pkt:
            return
        mac_src = pkt[Ether].src.lower()
        if IPv6 not in pkt:
            return

        if ICMPv6ND_RA in pkt:
            self._traiter_ra(pkt, port, mac_src)
        elif ICMPv6ND_NA in pkt:
            self._traiter_na(pkt, port, mac_src)
        elif ICMPv6ND_NS in pkt:
            if port == PORT_ATTAQUANT:          # une seule fois par trame
                self._debit(time.time())
        elif UDP in pkt and pkt[UDP].sport == 547:
            self._traiter_dhcpv6(pkt, port, mac_src)

    def _traiter_ra(self, pkt, port, mac_src):
        if self.mac_routeur and mac_src == self.mac_routeur:
            self.legit_vus[port] += 1          # RA du vrai routeur
            return
        self._compter_attaquant(port, mac_src, "RA")
        if port == PORT_ATTAQUANT:              # alerte une fois, à l'entrée
            self._alerte("faux_RA", port,
                         {"mac_src": mac_src, "ip_src": pkt[IPv6].src,
                          "preference": getattr(pkt[ICMPv6ND_RA], "prf", None),
                          "lifetime": pkt[ICMPv6ND_RA].routerlifetime})

    def _traiter_na(self, pkt, port, mac_src):
        if port == PORT_ATTAQUANT:              # une seule fois par trame
            self._debit(time.time())
        na = pkt[ICMPv6ND_NA]
        mac_annoncee = mac_src
        if ICMPv6NDOptDstLLAddr in pkt:
            mac_annoncee = pkt[ICMPv6NDOptDstLLAddr].lladdr.lower()
        usurpe = na.tgt in (IP_ROUTEUR, LL_ROUTEUR) and \
            self.mac_routeur and mac_annoncee != self.mac_routeur
        if usurpe:
            self._compter_attaquant(port, mac_src, "NA")
            if port == PORT_ATTAQUANT:
                self._alerte("usurpation_NA", port,
                             {"cible": na.tgt, "mac_annoncee": mac_annoncee,
                              "mac_vraie_routeur": self.mac_routeur})

    def _traiter_dhcpv6(self, pkt, port, mac_src):
        brut = bytes(pkt[UDP].payload)
        if not brut:
            return
        type_msg = brut[0]
        if type_msg not in (2, 7):              # Advertise, Reply
            return
        legit = DUID_LEGIT in brut
        if self.mac_routeur and mac_src == self.mac_routeur:
            legit = True                        # relayé par le routeur
        if legit:
            return
        self._compter_attaquant(port, mac_src, "DHCPV6")
        if port == PORT_ATTAQUANT:
            self._alerte("faux_DHCPv6", port,
                         {"mac_src": mac_src, "ip_src": pkt[IPv6].src,
                          "type": {2: "ADVERTISE", 7: "REPLY"}[type_msg]})

    def _debit(self, t):
        self.ns_na_fenetre.append(t)
        while self.ns_na_fenetre and t - self.ns_na_fenetre[0] > 1.0:
            self.ns_na_fenetre.popleft()
        debit = len(self.ns_na_fenetre)
        self.max_debit = max(self.max_debit, debit)
        if debit == SEUIL_NS_NA_PAR_S + 1:
            self._alerte("saturation_cache", None, {"debit_par_s": debit})

    # --- bilan -------------------------------------------------------------
    def bilan(self):
        res = {}
        for genre, vu in self.vues_entree.items():
            passe = self.vues_sortie.get(genre, 0)
            # passe = nombre de copies revues sur eth1/eth2/eth3 (le pont
            # inonde chaque trame multicast sur les 3 autres ports)
            res[genre] = {"vues_entree_eth4": vu,
                          "revues_sur_autres_ports": passe,
                          "verdict": "passee" if passe > 0 else "bloquee"}
        # faux positif : un RA du vrai routeur entre par eth1 mais n'est pas
        # retransmis vers les victimes (eth2/eth3)
        entres = self.legit_vus.get(PORT_CONFIANCE, 0)
        sortis = min(self.legit_vus.get(p, 0) for p in PORTS_VICTIMES)
        return {"alertes": dict(self.alertes), "attaquant_mac": self.mac_attaquant,
                "ra_legitimes_vus": dict(self.legit_vus),
                "ra_legitimes_bloques": max(entres - sortis, 0),
                "debit_max_ns_na_par_s": self.max_debit, "par_type": res}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phase", choices=["avant", "apres"], required=True)
    p.add_argument("--essai", type=int, required=True)
    p.add_argument("--duree", type=float, default=30.0)
    p.add_argument("--ifaces", nargs="+", default=PORTS_PAR_DEFAUT,
                   help="ports du pont à écouter (défaut : eth1 à eth4)")
    p.add_argument("--routeur-mac", default=None,
                   help="MAC réelle du routeur (docker exec clab-ipv6lab-router "
                        "ip link show eth1)")
    args = p.parse_args()

    mac = args.routeur_mac or lire_mac_routeur()
    if not mac:
        sys.exit("[ERREUR] MAC du routeur inconnue : donne --routeur-mac.")
    print(f"# detection phase={args.phase} essai={args.essai} "
          f"mac_routeur={mac} ports={args.ifaces}", flush=True)

    det = Detecteur(mac)
    sniff(iface=args.ifaces, store=False, timeout=args.duree,
          prn=lambda pkt: det.traiter(pkt, getattr(pkt, "sniffed_on", None)))
    print("# bilan " + json.dumps(det.bilan(), ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
