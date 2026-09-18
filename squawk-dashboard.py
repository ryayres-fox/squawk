#!/usr/bin/env python3
"""
squawk-dashboard.py — a static HTML renderer for one Squawk run.

Writes <run-dir>/dashboard.html: a single self-contained page you can archive
or attach somewhere, showing the run's ledger, severity picture, and the same
per-scanner fingerprint the GitHub-issue baselines use — so you can eyeball a
dashboard against a posted baseline table and see immediately whether the
identity set changed.

This file deliberately imports its counting logic FROM the squawk package, which
must sit in the same directory. The identity keys, the contamination filter,
the severity model, and the fingerprint are defined once; if the two files
could disagree, the diffs and the issue baselines would stop matching and
nothing would announce it.

Usage:
  python3 squawk-dashboard.py                    # newest run in the evidence root
  python3 squawk-dashboard.py <run-dir> [--open]
  SQUAWK_EVIDENCE=... python3 squawk-dashboard.py

Python 3.9+, standard library only. No X | Y annotations (3.9 kills them).
"""

import argparse
import json
import os
import sys
import webbrowser
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))


def load_tower():
    """Import the squawk package that sits beside this file. The identity keys,
    contamination filter, severity model and fingerprint are defined once, there,
    so this dashboard can never disagree with the app."""
    if not os.path.isdir(os.path.join(HERE, "squawk")):
        sys.stderr.write(
            "squawk-dashboard.py needs the squawk package beside it (looked in %s).\n"
            "The identity keys, contamination filter, and fingerprint are defined\n"
            "once, in that package, so the dashboard can never disagree with the app.\n"
            % HERE)
        raise SystemExit(2)
    sys.path.insert(0, HERE)
    import squawk
    return squawk


def pick_run(tower, evidence_root: str, explicit: Optional[str]) -> str:
    if explicit:
        run_dir = os.path.abspath(explicit)
        if not os.path.isfile(os.path.join(run_dir, "manifest.json")):
            sys.stderr.write("%s has no manifest.json — not a run directory.\n"
                             % run_dir)
            raise SystemExit(2)
        return run_dir
    runs = tower.list_runs(evidence_root)
    if not runs:
        sys.stderr.write("No runs under %s. Run a scan first.\n" % evidence_root)
        raise SystemExit(1)
    return runs[0]["_dir"]


def render(tower, run_dir: str) -> str:
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    identities = tower.load_identities(run_dir)
    findings = tower.load_findings(run_dir)
    E = tower.E

    sev_counts = man.get("severities", {})
    fingerprints = {t: tower.fingerprint(ids) for t, ids in identities.items()}

    ledger_rows = "".join(
        "<tr><td class='mono'>%s</td><td class='mono'>%s</td>"
        "<td><span class='st %s'>%s</span></td><td class='muted'>%s</td></tr>"
        % (E(r["tool"]), E(r["mode"]), E(r["status"]), E(r["status"]),
           E(r["detail"]))
        for r in man.get("ledger", []))

    fp_rows = "".join(
        "<tr><td class='mono'>%s</td><td>%d</td><td class='mono'>%s</td></tr>"
        % (E(t), len(identities[t]), fingerprints[t])
        for t in sorted(identities))

    finding_rows = "".join(
        "<tr><td>%s</td><td><b>%s</b><div class='mono muted'>%s</div></td>"
        "<td class='mono muted'>%s</td><td class='mono muted'>%s</td></tr>"
        % (tower.sev_pill(f["severity"]), E(f["title"]), E(f["path"]),
           E(f["scanner"]), E(f["identity"]))
        for f in sorted(findings, key=lambda x: tower.SEVERITY_ORDER.index(
            x["severity"]) if x["severity"] in tower.SEVERITY_ORDER else 9))

    sev_chips = " ".join(tower.sev_pill(s, sev_counts[s])
                         for s in tower.SEVERITY_ORDER if sev_counts.get(s))

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s · Squawk run</title><style>%s"
        ".st{font-weight:600}.st.ok{color:var(--ok)}.st.skipped{color:var(--faint)}"
        ".st.error{color:var(--crit)}.st.gap{color:var(--gap)}"
        "body{display:block;padding:2.2rem 2rem 4rem;max-width:1000px;margin:0 auto}"
        ".rpthead{display:flex;align-items:center;justify-content:space-between;"
        "gap:1rem;margin-bottom:1.2rem}"
        ".rpthead .mk{display:flex;align-items:center;gap:.55rem;font-weight:700;"
        "letter-spacing:.12em;font-size:.95rem}"
        ".rpthead .mk svg{width:24px;height:24px}"
        "</style></head><body>"
        "<div class='rpthead'><div class='mk'>"
        "<svg viewBox='0 0 30 30' fill='none'>"
        "<circle cx='15' cy='15' r='13' stroke='#7aa0a0' stroke-width='1.4'/>"
        "<circle cx='15' cy='15' r='7.5' stroke='#7aa0a0' stroke-width='1.2'/>"
        "<circle cx='15' cy='15' r='2' fill='var(--accent)'/>"
        "<path d='M15 15 L26 8' stroke='var(--accent)' stroke-width='1.6' "
        "stroke-linecap='round'/></svg>SQUAWK REPORT</div>"
        "<div class='themetoggle' style='margin:0;background:var(--inset)'>"
        "<button id='t-light' type='button' onclick=\"sqTheme('light')\" "
        "style='color:var(--faint)'>Light</button>"
        "<button id='t-dark' type='button' onclick=\"sqTheme('dark')\" "
        "style='color:var(--faint)'>Dark</button></div></div>"
        "<h1>Run %s</h1>"
        "<p class='sub'>%s · scope <b>%s</b> · target <span class='mono'>%s</span>"
        "<br>not covered: %s</p>"
        "<div class='card' style='margin-bottom:1rem'>%s"
        "<p class='muted' style='font-size:.8rem;margin:.6rem 0 0'>%d finding(s), "
        "%d excluded as working-tree contamination</p></div>"
        "<h2>Stage ledger</h2><div class='card tight'><table>"
        "<thead><tr><th>Tool</th><th>Mode</th><th>Status</th><th>Detail</th></tr>"
        "</thead><tbody>%s</tbody></table></div>"
        "<h2>Identity fingerprints — comparable to a posted baseline table</h2>"
        "<div class='card tight'><table><thead><tr><th>Scanner</th>"
        "<th>Identities</th><th>sha256[:16]</th></tr></thead><tbody>%s</tbody>"
        "</table></div>"
        "<h2>Findings</h2><div class='card tight'><table><thead><tr>"
        "<th>Severity</th><th>Finding</th><th>Scanner</th><th>Identity</th></tr>"
        "</thead><tbody>%s</tbody></table></div>"
        "<script>function sqTheme(t){document.documentElement.setAttribute("
        "'data-theme',t);var l=document.getElementById('t-light'),"
        "d=document.getElementById('t-dark');if(l)l.classList.toggle('sel',t==='light');"
        "if(d)d.classList.toggle('sel',t==='dark');try{localStorage.setItem("
        "'squawk-theme',t)}catch(e){}}(function(){var v;try{v=localStorage.getItem("
        "'squawk-theme')}catch(e){}var t=v||(matchMedia('(prefers-color-scheme:dark)')"
        ".matches?'dark':'light');sqTheme(t)})();</script>"
        "</body></html>"
        % (E(man.get("run_id", "")), tower.PAGE_CSS, E(man.get("run_id", "")),
           E(man.get("service_label", "")), E(man.get("scope", "")),
           E(man.get("target", "")), E(man.get("not_covered", "")),
           sev_chips or "<span class='muted'>no findings</span>",
           man.get("counts", {}).get("total", 0),
           man.get("counts", {}).get("excluded", 0),
           ledger_rows, fp_rows,
           finding_rows or "<tr><td colspan='4' class='muted'>none</td></tr>"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Static HTML for one Squawk run.")
    ap.add_argument("run_dir", nargs="?", help="a run directory (default: newest)")
    ap.add_argument("--evidence", help="evidence root (default ~/scan-evidence)")
    ap.add_argument("--open", action="store_true", help="open the result")
    args = ap.parse_args()

    tower = load_tower()
    root = args.evidence or os.environ.get("SQUAWK_EVIDENCE") \
        or tower.DEFAULT_EVIDENCE
    run_dir = pick_run(tower, root, args.run_dir)

    html_text = render(tower, run_dir)
    out = os.path.join(run_dir, "dashboard.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    print("wrote %s" % out)
    if args.open:
        webbrowser.open("file://%s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
