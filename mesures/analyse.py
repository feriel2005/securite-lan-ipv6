import argparse
import os
import sys

import pandas as pd

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(RACINE, "mesures", "resultats.csv")


def calculer(df):
    df = df.copy()
    for c in ("succes", "faux_positif", "cache_voisins", "latence_ms"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    g = df.groupby(["attaque", "phase"])
    res = g.agg(essais=("succes", "size"),
                reussies=("succes", "sum"),
                faux_positifs=("faux_positif", "sum"),
                cache_voisins_moy=("cache_voisins", "mean"),
                latence_moy_ms=("latence_ms", "mean")).reset_index()
    res["taux_reussite_pct"] = (100 * res["reussies"] / res["essais"]).round(1)
    res["taux_blocage_pct"] = (100 - res["taux_reussite_pct"]).round(1)
    return res[["attaque", "phase", "essais", "reussies", "taux_reussite_pct",
                "taux_blocage_pct", "faux_positifs", "cache_voisins_moy",
                "latence_moy_ms"]].round(2)


def verifier(df):
    """Signale les lignes qui risquent de fausser les chiffres."""
    alertes = []
    doublons = df[df.duplicated(["phase", "attaque", "essai"], keep=False)]
    if len(doublons):
        alertes.append(f"{len(doublons)} lignes partagent le même (phase, attaque, essai) : "
                       "numéros d'essai en double, à renuméroter avant la campagne officielle.")
    if df["cache_voisins"].isna().all():
        alertes.append("colonne cache_voisins vide partout : relever le cache avec "
                       "attaques/mesurer_cache_routeur.py.")
    if df["latence_ms"].isna().any():
        alertes.append(f"{int(df['latence_ms'].isna().sum())} lignes sans latence.")
    return alertes


def graphes(res, dossier):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(dossier, exist_ok=True)
    for col, titre, fichier in (("taux_reussite_pct", "Attaques réussies (%)", "reussite.png"),
                                ("latence_moy_ms", "Latence moyenne (ms)", "latence.png")):
        p = res.pivot(index="attaque", columns="phase", values=col)
        ax = p.plot(kind="bar", figsize=(7, 4), rot=20)
        ax.set_title(titre); ax.set_xlabel(""); ax.set_ylabel(titre)
        plt.tight_layout(); plt.savefig(os.path.join(dossier, fichier), dpi=150); plt.close()
        print("[graphe]", os.path.join(dossier, fichier))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default=CSV)
    p.add_argument("--graphes", action="store_true")
    a = p.parse_args()
    df = pd.read_csv(a.csv)
    res = calculer(df)
    pd.set_option("display.width", 200)
    print(res.to_string(index=False))
    for m in verifier(df):
        print("[ATTENTION]", m)
    out = os.path.join(os.path.dirname(a.csv), "synthese.csv")
    res.to_csv(out, index=False)
    print("[OK] écrit :", out)
    if a.graphes:
        graphes(res, os.path.join(os.path.dirname(a.csv), "graphes"))


if __name__ == "__main__":
    sys.exit(main())
