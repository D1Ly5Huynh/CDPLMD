"""Grouped bars: published IF-MalEvade tables next to the locked Dike lab run.

Numbers match IF-MalEvade-so-sanh-lab-va-paper.md. Means only.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "lab-vs-paper.png"

PAPER = "#0072B2"
LAB = "#E69F00"
INK = "#1A1A1A"
MUTED = "#5C6570"
GRID = "#E6E8EB"

PANELS = [
    {
        "title": "Table 4  ·  ADR",
        "labels": ["RF", "GB", "MLP", "DT"],
        "paper": [9.1, 13.56, 7.69, 8.1],
        "lab": [98, 94, 100, 100],
        "paper_text": ["9,1", "13,6", "7,7", "8,1"],
        "lab_text": ["98", "94", "100", "100"],
    },
    {
        "title": "Table 6  ·  detection VirusTotal",
        "labels": ["Gốc", "MAB", "MalFox", "IF-MalEvade"],
        "paper": [61.8, 42.9, 30.2, 21.8],
        "lab": [82.3, 65.8, 64.4, 74.1],
        "paper_text": ["61,8", "42,9", "30,2", "21,8"],
        "lab_text": ["82,3", "65,8", "64,4", "74,1"],
    },
    {
        "title": "Table 7  ·  evasion VirusTotal",
        "labels": ["MAB", "MalFox", "IF-MalEvade"],
        "paper": [19.2, 38.2, 57.8],
        "lab": [21.2, 22.6, 11.5],
        "paper_text": ["19,2", "38,2", "57,8"],
        "lab_text": ["21,2", "22,6", "11,5"],
    },
]


def _annotate(ax, xs, heights, texts, color):
    for x, height, text in zip(xs, heights, texts):
        ax.text(
            x,
            height + 1.6,
            text,
            ha="center",
            va="bottom",
            fontsize=8,
            color=color,
            fontweight="medium",
        )


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": "Segoe UI",
            "axes.unicode_minus": False,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "text.color": INK,
            "axes.labelcolor": INK,
            "xtick.color": INK,
            "ytick.color": MUTED,
        }
    )
    fig, axes = plt.subplots(1, 3, figsize=(12.8, 4.55), layout="constrained")
    fig.suptitle(
        "Lab Dike và paper VirusShare",
        fontsize=15,
        fontweight="semibold",
        color=INK,
        x=0.0,
        ha="left",
    )

    for ax, panel in zip(axes, PANELS):
        labels = panel["labels"]
        x = np.arange(len(labels))
        width = 0.36
        paper_x = x - width / 2
        lab_x = x + width / 2
        ax.bar(
            paper_x,
            panel["paper"],
            width,
            color=PAPER,
            edgecolor=PAPER,
            zorder=3,
        )
        ax.bar(
            lab_x,
            panel["lab"],
            width,
            color=LAB,
            edgecolor="#8A5A00",
            hatch="///",
            linewidth=0.6,
            zorder=3,
        )
        _annotate(ax, paper_x, panel["paper"], panel["paper_text"], PAPER)
        _annotate(ax, lab_x, panel["lab"], panel["lab_text"], "#6B4A00")
        ax.set_title(panel["title"], loc="left", fontsize=11, pad=8, color=INK)
        ax.set_xticks(x, labels, fontsize=9)
        ax.set_ylim(0, 118)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_ylabel("Phần trăm" if ax is axes[0] else "")
        ax.yaxis.grid(True, color=GRID, linewidth=0.8, zorder=0)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color("#D5D8DE")
        ax.spines["bottom"].set_color("#D5D8DE")
        ax.tick_params(length=0)

    legend = [
        Patch(facecolor=PAPER, edgecolor=PAPER, label="Paper  ·  500 cặp, 61 engine"),
        Patch(
            facecolor=LAB,
            edgecolor="#8A5A00",
            hatch="///",
            label="Lab  ·  50 cặp, 75 engine",
        ),
    ]
    fig.legend(
        handles=legend,
        loc="upper right",
        frameon=False,
        ncol=2,
        fontsize=9,
        bbox_to_anchor=(1.0, 1.02),
    )
    fig.text(
        0.0,
        -0.045,
        "Trung bình. Min–max và điều kiện thí nghiệm nằm trong IF-MalEvade-so-sanh-lab-va-paper.md.",
        fontsize=8,
        color=MUTED,
        ha="left",
    )
    fig.savefig(OUT, dpi=160, bbox_inches="tight", pad_inches=0.28)
    plt.close(fig)
    print(OUT)


if __name__ == "__main__":
    main()
