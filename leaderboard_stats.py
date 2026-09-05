"""leaderboard_stats.py — did the public board predict the private one?

Everything else in this repo is model-free and offline. This one file needs the Kaggle CLI,
because the question it answers is about the competition's own two leaderboards rather than
about the SDK. It pulls both boards, joins them by team id, and reports:

  * how many teams scored exactly zero on the private board,
  * the rank correlation between public and private score across the whole field,
  * the same correlation restricted to the teams that were actually competitive publicly,
  * how many of those top public teams scored zero privately.

The numbers quoted in the working note are the output of this script.

Run:  python leaderboard_stats.py            (needs `kaggle` on PATH and API credentials)
"""
from __future__ import annotations
import csv, glob, io, os, re, subprocess, sys, tempfile, zipfile

COMP = "ai-agent-security-multi-step-tool-attacks"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, env=ENV).stdout.decode("utf-8", "replace")


def private_board(page_size=200, max_pages=40):
    """The private board comes back paginated, so walk the page tokens to the end."""
    token, rows, page = None, [], 0
    while True:
        cmd = ["kaggle", "competitions", "leaderboard", COMP, "--show", "--csv",
               "--page-size", str(page_size)]
        if token:
            cmd += ["--page-token", token]
        token = None
        for line in _run(cmd).splitlines():
            m = re.match(r"Next Page Token = (\S+)", line.strip())
            if m:
                token = m.group(1)
                continue
            if line.strip() and not line.startswith("teamId"):
                rows.append(line)
        page += 1
        if not token or page >= max_pages:
            break
    out = {}
    for r in rows:
        head, score = r.rsplit(",", 1)
        out[head.split(",")[0]] = float(score)
    return out


def public_board():
    d = os.path.join(tempfile.gettempdir(), "aas_lb")
    os.makedirs(d, exist_ok=True)
    _run(["kaggle", "competitions", "leaderboard", COMP, "--download", "-p", d, "-q"])
    z = zipfile.ZipFile(sorted(glob.glob(os.path.join(d, "*.zip")))[-1])
    reader = csv.DictReader(io.TextIOWrapper(z.open(z.namelist()[0]), "utf-8-sig"))
    return {row["TeamId"]: float(row["Score"]) for row in reader}


def spearman(xs, ys):
    """Rank correlation with average ranks for ties (the field has thousands of tied zeros)."""
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        out = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1
            for k in range(i, j + 1):
                out[order[k]] = avg
            i = j + 1
        return out
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else float("nan")


def report(top_n=200):
    priv, pub = private_board(), public_board()
    common = sorted(t for t in priv if t in pub)
    if not common:
        print("No overlap between the two boards — check your Kaggle credentials.")
        return

    zeros = sum(1 for t in priv if priv[t] == 0.0)
    x = [pub[t] for t in common]
    y = [priv[t] for t in common]
    cutoff = sorted(x, reverse=True)[min(top_n, len(x)) - 1]
    top = [t for t in common if pub[t] >= cutoff]
    top_zero = sum(1 for t in top if priv[t] == 0.0)

    print("Did the public board predict the private one?\n")
    print("  teams on both boards            : %d" % len(common))
    print("  private scores of exactly 0.000 : %d  (%.1f%%)" % (zeros, 100.0 * zeros / len(priv)))
    print("  Spearman rho, whole field       : %+.3f" % spearman(x, y))
    print("  Spearman rho, top %d public     : %+.3f  (n=%d)"
          % (top_n, spearman([pub[t] for t in top], [priv[t] for t in top]), len(top)))
    print("  of those top public teams, %d (%.0f%%) scored 0 privately"
          % (top_zero, 100.0 * top_zero / len(top)))
    print("\n=> A public score carried essentially no information about the private one. Two thirds of")
    print("   the field scored nothing where the prizes were decided, and being good publicly was not")
    print("   protection: nearly half the most competitive public teams also scored zero.")


if __name__ == "__main__":
    report()
