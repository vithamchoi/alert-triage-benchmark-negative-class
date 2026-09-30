#!/usr/bin/env python3
"""Generate the paper's data figures from the evaluation result files.

    python3 make_figures.py <results_dir> <out_dir>

Every plotted value is read from disk. Vector PDF sized for the Elsevier
two-column layout. Palette: Okabe-Ito subset, validated colourblind-safe.
"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import figstyle as F

RES = Path(sys.argv[1] if len(sys.argv) > 1 else "../results")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "figures")
OUT.mkdir(parents=True, exist_ok=True)

C = ["#0072B2", "#D55E00", "#009E73", "#E69F00"]
INK, MUTED, GRID = "#1a1a1a", "#6b6b6b", "#dcdcdc"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"],
    "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8.5,
    "legend.fontsize": 7.2, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
    "axes.edgecolor": MUTED, "axes.linewidth": 0.6, "axes.labelcolor": INK,
    "text.color": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "figure.dpi": 200,
    "savefig.bbox": "tight", "savefig.pad_inches": 0.02, "pdf.fonttype": 42,
})


def tidy(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.tick_params(length=2.5, width=0.6)


def load(rel):
    with open(RES / rel, encoding="utf-8") as f:
        return json.load(f)


def save(fig, name):
    fig.savefig(OUT / name)
    plt.close(fig)
    print(f"wrote {OUT / name}")


R = load("real_eval/real_eval_results.json")

LABEL = {"accept_all": "Accept-all", "heuristic": "Heuristic regex",
         "tfidf_rf": "TF-IDF + RF", "tfidf_msgonly": "TF-IDF, msg only"}
ORDER = ["accept_all", "heuristic", "tfidf_rf", "tfidf_msgonly"]


def rows(setname):
    by = {r["triager"]: r for r in R[setname]}
    return [by[k] for k in ORDER]


# --- Fig 1: MCC with bootstrap CI, both prevalence regimes -------------------
fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.5), sharey=True)
for ax, sn, title in zip(axes, ("balanced", "imbalanced"),
                         (f"Balanced ({R['config']['n_balanced']} alerts, 1:1)",
                          f"Imbalanced ({R['config']['n_imbalanced']} alerts, "
                          f"1:{R['config']['imb_ratio']:.2f})")):
    rs = rows(sn)
    y = np.arange(len(rs))[::-1]
    mcc = [r["mcc"] for r in rs]
    lo = [r["mcc"] - r["mcc_ci_lo"] for r in rs]
    hi = [r["mcc_ci_hi"] - r["mcc"] for r in rs]
    ax.barh(y, mcc, height=0.55, color=C[:len(rs)], edgecolor="none")
    ax.errorbar(mcc, y, xerr=[lo, hi], fmt="none", ecolor=INK,
                elinewidth=0.8, capsize=2.5, capthick=0.8)
    ax.axvline(0.0, color=MUTED, lw=0.7, ls="--")
    ax.set_yticks(y)
    ax.set_yticklabels([LABEL[r["triager"]] for r in rs])
    ax.set_xlabel("Matthews correlation coefficient")
    ax.set_title(title)
    ax.set_xlim(-0.25, 0.75)
    tidy(ax)
save(fig, "fig_mcc.pdf")

# --- Fig 2: recall against developer burden ---------------------------------
fig, ax = plt.subplots(figsize=(3.4, 2.6))
for sn, mk, ls in (("balanced", "o", "-"), ("imbalanced", "s", "--")):
    rs = rows(sn)
    rec = [r["tp"] / (r["tp"] + r["fn"]) for r in rs]
    bur = [r["burden_fp_plus_50fn"] for r in rs]
    ax.plot(rec, bur, ls, color=MUTED, lw=0.6, zorder=1)
    for r, x, yv, c in zip(rs, rec, bur, C):
        ax.scatter([x], [yv], s=26, marker=mk, color=c, zorder=2,
                   label=LABEL[r["triager"]] if sn == "balanced" else None)
ax.set_yscale("log")
ax.set_xlabel("Recall on true positives")
ax.set_ylabel(r"Developer burden $\mathrm{FP}+50\,\mathrm{FN}$")
ax.set_xlim(0.0, 1.05)
ax.legend(frameon=False, loc="lower left", handletextpad=0.3)
tidy(ax)
save(fig, "fig_burden.pdf")

print("\nAll figures generated from:", RES)
