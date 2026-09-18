"""The loopback web UI: every page, and the request handler."""

import calendar
import datetime
import html
import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

from squawk.analysis import (
    CLOUD_DRILL,
    DRILL_SUMS,
    ESTATE_SORTS,
    ESTATE_STATUSES,
    OUTSIDE_REACH,
    READING_STALE_HOURS,
    SQUAWK_CODES,
    _run_incomplete,
    _run_score,
    analyzer_agreement,
    analyzer_caveats,
    analyzer_findings,
    analyzer_summary,
    apply_estate_query,
    cloud_drill,
    compare_readings,
    container_findings,
    container_summary,
    dataservice_caveats,
    dataservice_findings,
    dataservice_summary,
    edge_findings,
    edge_gaps,
    edge_summary,
    enablement_summary,
    estate_rows,
    frontdoor_caveats,
    frontdoor_findings,
    frontdoor_summary,
    headline_facts,
    iam_caveats,
    iam_summary,
    interface_owners,
    inventory_caveats,
    inventory_notes,
    inventory_summary,
    org_summary,
    partial_caveat,
    reach_words,
    reading_age,
    split_regions,
    squawk_check,
    storage_caveats,
    storage_findings,
    storage_summary,
    verify_state,
    watching_gaps,
)
from squawk.baselines import (
    baseline_identity_set,
    generate_baseline_comments,
    load_baselines,
    resolve_gh_repo,
    sync_baselines,
)
from squawk.core import (
    BASE_TITLE,
    LOG,
    PROFILE_REFUSED_NOTE,
    SCANNERS,
    SEVERITY_ORDER,
    STALE_SCAN_DAYS,
    ProfileError,
    __version__,
    _rows,
    as_text,
    env,
    host_is_loopback,
    human_seconds,
    is_test_code,
    mask_account,
    redact_identifiers,
    resolve_repo,
    show_setting,
    tool_path,
)
from squawk.decisions import current_decisions, record_decision, summarize
from squawk.engine import profile_for
from squawk.evidence import (
    count_runs,
    diff_runs,
    estate_runs,
    finding_history,
    history_counts,
    history_entries,
    iso_week,
    list_runs,
    load_findings,
    target_key,
)
from squawk.feeds import (
    EPSS_HOT,
    FEED_STALE_DAYS,
    PRIORITY_TIERS,
    cve_of,
    cvss_words,
    epss_top,
    estate_cves,
    feed_ages,
    intel_provenance,
    kev_by_vendor,
    kev_ransomware,
    kev_recent,
    load_feeds,
    load_intel,
    rank_run,
)
from squawk.retention import prune_record
from squawk.runtime import (
    JOBS,
    Job,
    read_pid_file,
    running_job_for_scope,
    start_job,
)
from squawk.scanners import _real_evidence, rule_of
from squawk.stages import (
    SERVICES,
    STAGES,
    aws_identity,
    aws_identity_readonly,
    cloud_target_ok,
    dast_target_live,
    dast_target_ok,
    probes_a_named_port,
)

# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #

E = html.escape
# Lightness descends with severity so the ramp survives grayscale; the letter
# marker (C/H/M/L/I) is the primary signal, color is reinforcement (WCAG 1.4.1).
SEV_COLORS = {"critical": "var(--crit)", "high": "var(--high)",
              "medium": "var(--med)", "low": "var(--low)",
              "info": "var(--info)", "unknown": "var(--unknown)"}
SEV_MARKS = {"critical": "C", "high": "H", "medium": "M",
             "low": "L", "info": "I", "unknown": "?"}

# Small stroke icons keep the shell reading like a product, not a script.
ICONS = {
    "overview": "<path d='M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z'/>",
    "scan": "<circle cx='12' cy='12' r='3'/><path d='M12 2v3M12 19v3M2 12h3M19 12h3"
            "M20 12a8 8 0 1 1-8-8'/>",
    "findings": "<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>",
    "history": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "shield": "<path d='M12 2l8 3v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V5z'/>",
    "triage": "<path d='M9 11l3 3 8-8M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5"
              "a2 2 0 0 1 2-2h11'/>",
    "baselines": "<path d='M12 3v18M3 12h18M7.5 7.5l9 9M16.5 7.5l-9 9'/>",
    "rescan": ("<path d='M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5'/>"
               "<path d='M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5'/>"),
    "compare": ("<path d='M12 3v18'/><path d='M7 8l-4 4 4 4'/>"
                "<path d='M17 8l4 4-4 4'/>"),
    "priority": "<path d='M5 21V4h11l-2 4 2 4H5'/>",
    "cloud": "<path d='M7 18a4 4 0 0 1-.6-8 6 6 0 0 1 11.3-1.5A4 4 0 0 1 17 18z'/>",
}

PAGE_CSS = """
:root{
 /* The two sticky strips at the top of every page, named once. The offset
    a third sticky element needs is the sum of them, and it was written as
    the literal `73px` in one place and nowhere else — so the clock strip,
    added later, scrolled away under the topbar and the sticky column
    underneath it cleared only one of the two. */
 /* The clock strip wraps, so its height is not one number. Two rows is the
    common case on an ordinary window; a sticky element below it clears that
    rather than the one-row height, because too much gap is a smaller fault
    than a column sitting under the clocks. */
 --topbar-h:73px;--clocks-h:88px;
 --bg:#f3f6f6;--panel:#ffffff;--panel-2:#f8fbfb;--inset:#edf3f3;
 --line:#e0e9e9;--line-2:#eef4f4;
 --ink:#15242b;--soft:#556772;--faint:#667278;
 --accent:#0b847d;--accent-2:#086f69;--accent-ink:#ffffff;--accent-soft:#e0f3f1;
 --crit:#d42d3d;--high:#bd5730;--med:#a16c08;--low:#3d78bf;--info:#6b7a81;
 --ok:#108655;--gap:#a16c08;--unknown:#6b7783;
 --mark-ink:#ffffff;
 --rail:#0f2a2e;--rail-ink:#c4d6d5;--rail-ink-2:#7e9b9a;--rail-line:#1c3c3f;
 --shadow:0 1px 2px rgba(21,36,43,.05),0 4px 16px rgba(21,36,43,.05);
}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){
 --bg:#0e181b;--panel:#152329;--panel-2:#111d22;--inset:#1a2830;
 --line:#243239;--line-2:#1a262b;
 --ink:#e6edee;--soft:#93a5aa;--faint:#8593a8;
 --accent:#22c7bd;--accent-2:#4bd8cf;--accent-ink:#05221f;--accent-soft:#0c2b29;
 --crit:#ff4d5e;--high:#ff7a4d;--med:#f0a83a;--low:#5fa0e8;--info:#8593a8;
 --ok:#2ec98a;--gap:#f0a83a;--unknown:#8b97a1;
 --mark-ink:#0e181b;
 --rail:#091518;--rail-ink:#c4d6d5;--rail-ink-2:#7a9291;--rail-line:#152a2d;
 --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 22px rgba(0,0,0,.34);
}}
:root[data-theme="dark"]{
 --bg:#0e181b;--panel:#152329;--panel-2:#111d22;--inset:#1a2830;
 --line:#243239;--line-2:#1a262b;
 --ink:#e6edee;--soft:#93a5aa;--faint:#8593a8;
 --accent:#22c7bd;--accent-2:#4bd8cf;--accent-ink:#05221f;--accent-soft:#0c2b29;
 --crit:#ff4d5e;--high:#ff7a4d;--med:#f0a83a;--low:#5fa0e8;--info:#8593a8;
 --ok:#2ec98a;--gap:#f0a83a;--unknown:#8b97a1;
 --mark-ink:#0e181b;
 --rail:#091518;--rail-ink:#c4d6d5;--rail-ink-2:#7a9291;--rail-line:#152a2d;
 --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 22px rgba(0,0,0,.34);
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);
 font:14px/1.55 "IBM Plex Sans",system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
 -webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
 font-size:.82rem;font-variant-numeric:tabular-nums}
.muted{color:var(--faint)}.soft{color:var(--soft)}
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,
[tabindex]:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}

/* shell + rail */
.shell{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.side{background:var(--rail);color:var(--rail-ink);border-right:1px solid var(--rail-line);
 display:flex;flex-direction:column;padding:0;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:.6rem;padding:1.25rem 1.25rem 1.1rem;
 font-weight:700;letter-spacing:.12em;font-size:1rem;color:#fff}
.brand svg{width:26px;height:26px;fill:none}
.brand .tagline{font-size:9.5px;letter-spacing:.16em;color:var(--rail-ink-2);
 text-transform:uppercase;margin-top:2px;font-weight:600;letter-spacing:.14em}
.side nav{display:flex;flex-direction:column;gap:1px;padding:.5rem .75rem;flex:1}
.side nav a{display:flex;align-items:center;gap:.7rem;padding:.55rem .75rem;
 border-radius:8px;color:var(--rail-ink);font-weight:500;font-size:13.5px;
 transition:background .12s}
.side nav a svg{width:17px;height:17px;stroke:currentColor;fill:none;
 stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round;opacity:.72}
.side nav a:hover{background:rgba(255,255,255,.05);color:#fff;text-decoration:none}
.side nav a.on{background:rgba(34,199,189,.16);color:#fff}
.side nav a.on svg{opacity:1;color:#3fd6cc;stroke:#3fd6cc}
.themetoggle{display:flex;background:rgba(255,255,255,.06);border-radius:8px;
 padding:3px;margin:.5rem 1rem}
.themetoggle button{flex:1;border:0;background:transparent;color:var(--rail-ink-2);
 font:inherit;font-size:12px;font-weight:600;padding:.4rem;border-radius:6px;cursor:pointer;
 display:flex;align-items:center;justify-content:center;gap:6px}
.themetoggle button.sel{background:rgba(255,255,255,.13);color:#fff}
.themetoggle button svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:1.6}
.side .legend{padding:.85rem 1rem;border-top:1px solid var(--rail-line);
 font-size:.72rem;color:var(--rail-ink-2)}
.side .legend div{display:flex;align-items:center;gap:.45rem;margin:.28rem 0}
.side .legend .loop{color:#39c78e}
.side .legend .loop .dot{background:#39c78e;box-shadow:0 0 0 3px rgba(57,199,142,.22)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:0 0 auto}

/* three-state marks — ok / gap / unknown by SHAPE, not colour alone */
.st-ok{width:9px;height:9px;border-radius:50%;background:var(--ok);
 display:inline-block;flex:0 0 auto}
.st-gap{width:0;height:0;display:inline-block;flex:0 0 auto;border-left:5px solid transparent;
 border-right:5px solid transparent;border-bottom:9px solid var(--gap)}
.st-unknown{width:9px;height:9px;border-radius:50%;border:1.6px dashed var(--unknown);
 background:transparent;display:inline-block;flex:0 0 auto}

/* topbar + content */
.content{display:flex;flex-direction:column;min-width:0}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;
 padding:1rem 1.75rem;border-bottom:1px solid var(--line);background:var(--panel);
 position:sticky;top:0;z-index:5}
.topbar .ctx{font-size:.8rem;color:var(--faint);display:flex;align-items:center;
 gap:.5rem;min-width:0}
.topbar .ctx b{color:var(--soft);font-weight:500}
.topbar .ctx .lbl{text-transform:uppercase;letter-spacing:.07em;font-size:.64rem;
 color:var(--faint)}
.topbar .ctx .path{color:var(--soft);overflow:hidden;text-overflow:ellipsis;
 white-space:nowrap;max-width:34ch}
.topbar .ctx .sep{opacity:.45}
.topbar .ctx .badge{display:inline-flex;align-items:center;gap:.35rem;flex:none;
 padding:.12rem .55rem;border:1px solid var(--line-2);border-radius:999px;
 font-size:.72rem;color:var(--ok)}
.topbar .ctx .badge::before{content:'';width:6px;height:6px;border-radius:50%;
 background:var(--ok)}
/* The clock wall, the way an operations room hangs it: UTC first because that
   is what the evidence is stamped in, then the desks west to east. Two of them
   are also facts about this run — one is the machine that scanned, one is the
   browser reading — and where either is already on the wall it is badged
   rather than drawn twice. Its own row, and it scrolls inside itself, so ten
   clocks can never push a page sideways. */
/* A GRID, not a wrapping flex row. Fifteen cells never fit one row on a
   laptop, and wrapped flex cells size themselves independently: eight on the
   first row and seven on the second, none of them lining up, every cell a
   different width. On a small laptop screen that reads as noise rather than as a wall
   of clocks (the operator, 2026-09-15).
   `auto-fit` puts as many columns as fit and shares the rest, so the rows are
   columns and the cell count follows the window without a breakpoint. */
/* A FIXED number per row, chosen at breakpoints, with the remainder centred.
   Neither of the first two attempts balanced. A wrapping flex row sized every
   cell to its own content, so the rows did not line up. `auto-fit` lined them
   up and then picked the column count from the window width alone — which is
   the real fault, because with fifteen clocks the count decides everything:

       8 columns -> 8 + 7        7 columns -> 7 + 7 + 1
       5 columns -> 5 + 5 + 5    4 columns -> 4 + 4 + 4 + 3

   A window a little narrower than the operator's lands on seven and puts one
   clock alone on a row. So the count is chosen here, from the values that
   divide well, and never by the width on its own.

   8, 6 and 4 are the three that strand nobody at FIFTEEN or at SIXTEEN — the
   script adds a sixteenth clock when the reader's own zone is not already on
   the wall, so both counts have to work:

       8 -> 8+7  or 8+8        6 -> 6+6+3    or 6+6+4
       4 -> 4+4+4+3 or 4+4+4+4

   2, 3, 5 and 7 are all excluded, each of them leaving one clock alone on a
   row at one count or the other. 4 is the floor for that reason and not
   because of the width.

   Fifteen is odd, so no two-row split is even and no amount of arithmetic
   makes one. `justify-content:center` is the answer to that: the short row
   sits centred under the full one, which reads as deliberate rather than as a
   hole at the end. */
.clocks{display:flex;flex-wrap:wrap;justify-content:center;
 gap:.5rem .25rem;align-items:stretch;
 padding:.5rem 1.75rem;border-bottom:1px solid var(--line);
 background:var(--panel-2);
 /* Slides with the page. The topbar above it has been sticky since it was
    written; this was not, so the wall a reader is meant to check a timestamp
    against left the screen the moment they scrolled to the timestamp. */
 position:sticky;top:var(--topbar-h);z-index:4}
/* A percentage basis forces the count: eight per row whatever the width, so
   the rows cannot line up differently from one another. `0 0` because a cell
   that grows would fill the short row and undo the centring. */
.clocks .clk{display:flex;flex-direction:column;gap:.02rem;
 padding:.1rem .5rem;min-width:0;flex:0 0 calc(12.5% - .25rem)}
@media(max-width:1180px){.clocks .clk{flex-basis:calc(16.666% - .25rem)}}
@media(max-width:820px){.clocks .clk{flex-basis:calc(25% - .25rem)}}

.clocks .zone{text-transform:uppercase;letter-spacing:.07em;font-size:.6rem;
 color:var(--faint);line-height:1.25}
.clocks .now{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
 font-size:.95rem;font-weight:600;color:var(--ink);line-height:1.2;
 font-variant-numeric:tabular-nums}
.clocks .day{font-size:.62rem;color:var(--faint);line-height:1.25}
/* A clock that is one of *these* machines — the host that scanned, the browser
   reading — is marked by the whole cell. On a wall of ten a chip in the corner
   is easy to miss, which is what the operator found. */
.clocks .clk.here{background:var(--accent-soft);border-radius:5px;
 box-shadow:inset 0 2px 0 var(--accent)}
.clocks .clk.here .now{color:var(--accent-2)}
.clocks .clk.here .zone,.clocks .clk.here .day{color:var(--accent-2);opacity:.85}
.clocks .who{font-size:.55rem;letter-spacing:.06em;padding:.02rem .3rem;
 border-radius:3px;background:var(--accent);color:var(--accent-ink);
 display:inline-block;margin-left:.35rem;white-space:nowrap;vertical-align:1px}
.clocks .who.skew{background:var(--high);color:#fff}
/* The "N not shown" note is a cell of the grid like any clock, so it keeps its
   own track rather than sitting against a rule that no longer exists. */
.clocks .miss{align-self:center;padding:.1rem .5rem;font-size:.62rem;
 color:var(--gap)}
@media(max-width:820px){.clocks{padding:.45rem 1rem}}
/* A wide window should be used. At 1200px the content left 568px empty on a
   2000px screen and 1128px on a 2560px one, while the clock strip spanned the
   whole width — measured 2026-09-08, and the mismatch is what made it read as
   broken. Tables and grids take the room; prose is held to a readable measure
   by the rule below rather than by starving the whole page. */
/* No hard cap. The comment above says tables and grids take the room and
   prose is held to a readable measure by the rule below -- and then a 1680px
   cap starved the whole page anyway, so a wide monitor got a column of
   content and six hundred pixels of nothing beside it. The 82ch rule is the
   control; this was not. */
main{padding:1.6rem 1.75rem 3.5rem;width:100%}
/* Running text stays readable however wide the window: a line of 200
   characters is worse than a narrow page. Tables, grids and cards are exempt
   — they are scanned, not read. */
main > p,.sub,.card > p:not(.mono){max-width:82ch}
h1{font-size:1.3rem;margin:0 0 .3rem;font-weight:700;letter-spacing:-.01em}
.sub{color:var(--faint);margin:0 0 1.4rem;font-size:.9rem}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);
 margin:1.8rem 0 .7rem;font-weight:600}

/* cards + grid */
.grid{display:grid;gap:1rem}
.grid>*{min-width:0}
/* a path in a table cell may break anywhere: a 40-character mono path was the
   widest fixed thing in the Overview's target column, and the column could not
   shrink below it */
td .mono,.card .mono.muted{overflow-wrap:anywhere}
.cols-2{grid-template-columns:2fr 1fr;align-items:start}
/* The estate summary is short and the targets table is long, so the right
   column was mostly empty on a wide screen. It follows the table instead —
   the totals stay readable beside whichever row you are on. 73px is the
   sticky top bar; below 1280 the columns stack and this does nothing. */
.cols-2 > :nth-child(2){position:sticky;
 top:calc(var(--topbar-h) + var(--clocks-h) + .8rem)}
@media(max-width:1280px){.cols-2 > :nth-child(2){position:static}}
/* the two-column Overview needs ~780px for its targets table; below this the
   two columns stack rather than a card scrolling its table out of view. After
   the rule above on purpose: equal specificity, so the later one wins. */
@media(max-width:1280px){.cols-2{grid-template-columns:1fr}}
/* Tile rows FOLLOW the window instead of being pinned to a column count.
   Three columns at any width meant a row of six tiles was always 3+3 with
   each number stretched across a third of the screen, and below 900px the
   row collapsed to one tile per line -- which is why a printed page put one
   tile on each third of a sheet and the Cloud page ran to sixteen of them.
   auto-fit does both ends: as many columns as fit, one when only one fits. */
.cols-3{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}
.cols-4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.cols-auto{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{position:static;
 height:auto;flex-direction:row;flex-wrap:wrap;align-items:center}
 .side nav{flex-direction:row;flex-wrap:wrap;flex:1 1 100%;order:3}
 .cols-2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:1.1rem 1.2rem;box-shadow:var(--shadow);min-width:0;overflow-x:auto}
.card.tight{padding:.9rem 1rem}
.card h3{margin:0 0 .2rem;font-size:.95rem;font-weight:600}
.stat{display:flex;flex-direction:column;gap:.15rem}
.stat .n{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:1.9rem;font-weight:600;
 line-height:1;font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.stat .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--faint)}
.attn{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.8rem}
.attn-i{display:inline-flex;align-items:center;gap:.35rem;padding:.3rem .7rem;
 border-radius:999px;border:1px solid var(--line-2);background:var(--panel-2);
 font-size:.78rem;color:var(--soft);text-decoration:none}
.attn-i.gap{color:var(--gap);border-color:color-mix(in srgb,var(--gap) 40%,transparent)}
.attn-i.stale{color:var(--med)}
.spark{display:block}.sparkcell{width:104px}
.stale{color:var(--gap);font-size:.64rem;text-transform:uppercase;letter-spacing:.06em}

/* severity system */
.dchips{display:flex;flex-wrap:wrap;gap:.35rem}
.dchip{display:inline-block;padding:.12rem .55rem;border-radius:20px;
.dchip.dec{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.dchip.regress,.regress{color:var(--crit);font-weight:600}
.dchip.regress{border-color:color-mix(in srgb,var(--crit) 45%,transparent)}
 border:1px solid var(--line-2);color:var(--soft);font-size:.72rem;
 font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace;white-space:nowrap;
 background:var(--panel-2)}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.12rem .55rem .12rem .18rem;
 border-radius:20px;font-size:.74rem;font-weight:600;border:1px solid transparent}
.mark{display:inline-grid;place-items:center;width:15px;height:15px;border-radius:50%;
 font-size:.62rem;font-weight:800;font-family:"IBM Plex Mono",Menlo,monospace;color:var(--mark-ink)}
.sevbar{display:flex;height:9px;border-radius:6px;overflow:hidden;
 background:var(--inset);margin:.3rem 0}
.sevbar span{display:block;height:100%}
.sevrow{display:flex;align-items:center;justify-content:space-between;
 padding:.28rem 0;font-size:.85rem}
.sevrow .lbl{display:flex;align-items:center;gap:.5rem;text-transform:capitalize}
a.sevrow:hover{color:var(--accent) !important}
.sevrow b{font-family:"IBM Plex Mono",monospace;font-variant-numeric:tabular-nums}
.donut{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;flex:none}
.donut .hole{width:92px;height:92px;border-radius:50%;background:var(--panel);
 display:grid;place-items:center;text-align:center}
.donut .hole .big{font-family:"IBM Plex Mono",monospace;font-size:1.6rem;
 font-weight:600;line-height:1}
.donut .hole .lab{font-size:.62rem;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}

/* transponder readout (overview hero) */
.xpndr{position:relative;overflow:hidden;display:flex;flex-direction:column;
 justify-content:space-between;min-height:150px}
.xpndr .code{font-family:"IBM Plex Mono",monospace;font-size:3.2rem;font-weight:700;
 letter-spacing:.03em;line-height:1;font-variant-numeric:tabular-nums}
.xpndr .code.c7700,.xpndr .code.c7500{color:var(--crit)}
.xpndr .code.c7600{color:var(--gap)}
.xpndr .code.c1200{color:var(--ok)}
.xpndr .rlabel{margin-top:.5rem;font-size:.85rem;font-weight:600}
.xpndr .rdesc{color:var(--soft);font-size:.8rem;margin-top:.15rem}

/* tables */
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th{text-align:left;color:var(--faint);font-weight:600;text-transform:uppercase;
 font-size:.66rem;letter-spacing:.06em;padding:.7rem .8rem;
 border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:.65rem .8rem;border-bottom:1px solid var(--line-2);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--panel-2)}
td .idline{display:block;font-family:"IBM Plex Mono",monospace;font-size:.72rem;
 color:var(--faint);margin-top:2px}

/* controls */
button,input,select{font:inherit}
.btn{display:inline-flex;align-items:center;gap:.45rem;background:var(--accent);
 color:var(--accent-ink);border:0;border-radius:9px;padding:.55rem .95rem;font-weight:600;
 font-size:.9rem;white-space:nowrap;cursor:pointer}
.btn svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.9;flex:none}
.btn:hover{background:var(--accent-2);text-decoration:none}
.btn.ghost{background:transparent;color:var(--soft);border:1px solid var(--line-2)}
.btn.ghost:hover{background:var(--panel-2);color:var(--ink)}
input[type=text],select{background:var(--panel-2);border:1px solid var(--line-2);
 color:var(--ink);border-radius:9px;padding:.5rem .7rem;min-width:220px}
input[type=text]:focus,select:focus{outline:2px solid var(--accent);border-color:var(--accent)}

/* service launcher */
.svc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.1rem;
 display:flex;flex-direction:column;gap:.5rem;box-shadow:var(--shadow)}
.svc:hover{border-color:var(--accent);box-shadow:var(--shadow)}
.svc .row{display:flex;align-items:center;justify-content:space-between;gap:.5rem}
.svc .name{font-weight:650;font-size:1rem}
.svc .meta{font-size:.75rem;color:var(--faint)}
.svc .tools{display:flex;flex-wrap:wrap;gap:.3rem}
.tag{font-size:.7rem;padding:.12rem .5rem;border-radius:6px;background:var(--inset);
 border:1px solid var(--line-2);color:var(--soft);font-family:"IBM Plex Mono",monospace}
.tag.gap{color:var(--gap);border-color:color-mix(in srgb,var(--gap) 40%,transparent)}
a.stat{display:flex;color:inherit}
a.stat:hover{border-color:var(--accent);text-decoration:none}
a.stat .k{color:var(--accent)}
.svc form{display:flex;gap:.4rem;margin-top:auto;padding-top:.5rem;flex-wrap:wrap;
 align-items:center}
.svc .meta.nc{flex:1}
.svc form select,.svc form input[type=text],.svc .fixed{flex:1;min-width:0}
.svc .fixed{background:var(--panel-2);border:1px solid var(--line-2);border-radius:9px;
 padding:.5rem .7rem;font-size:.85rem;color:var(--soft);white-space:nowrap;overflow:hidden;
 text-overflow:ellipsis}
.picker{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:1rem 1.1rem;margin-bottom:1.1rem;box-shadow:var(--shadow)}
.picker h3{margin:0 0 .4rem}
.picker .lbl{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;
 color:var(--faint);margin:.75rem 0 .35rem}
.chip{display:inline-flex;align-items:center;gap:.4rem;padding:.25rem .6rem;
 border-radius:8px;border:1px solid var(--line-2);background:var(--panel-2);color:var(--ink);
 font-family:"IBM Plex Mono",monospace;font-size:.74rem;cursor:pointer;margin:.15rem .3rem .15rem 0}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.chip.gone{opacity:.5;cursor:not-allowed;text-decoration:line-through}
.chip .sc{font-size:.6rem;color:var(--faint);text-transform:uppercase;letter-spacing:.06em}
.browse{font-family:"IBM Plex Mono",monospace;font-size:.76rem}
.browse .brow{display:flex;gap:.5rem;align-items:center;padding:.12rem 0}
.browse .repo{color:var(--ok);font-size:.6rem;text-transform:uppercase;letter-spacing:.06em}
.browse .list{max-height:15rem;overflow:auto}
.picker summary{cursor:pointer;font-weight:600;color:var(--soft);
 list-style:disclosure-closed inside;color:var(--soft)}
.picker[open] summary{list-style:disclosure-open inside}
.picker summary:hover{color:var(--accent)}
.svc select{flex:1;min-width:0}
.svc input[type=text][name=target_other]{flex:1;min-width:0}

/* diff + misc */
.added{color:var(--crit);font-weight:600}.removed{color:var(--ok);font-weight:600}
.silent{color:var(--faint);font-style:italic}
.week{display:inline-block;width:15px;height:15px;border-radius:4px;margin:1.5px;background:var(--inset)}
.week.has{background:var(--accent)}
.week.none{background:var(--inset);border:1px dashed var(--line-2)}
.banner{background:var(--accent-soft);
 border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);
 border-radius:10px;padding:.75rem 1rem;font-size:.88rem;margin-bottom:1.2rem}
.banner.warn{background:color-mix(in srgb,var(--gap) 12%,transparent);
 border-color:color-mix(in srgb,var(--gap) 40%,transparent)}
.banner.alarm{background:color-mix(in srgb,var(--crit) 10%,transparent);
 border-color:color-mix(in srgb,var(--crit) 38%,transparent)}
.empty{text-align:center;padding:3.5rem 1rem;color:var(--faint)}
.empty svg{width:44px;height:44px;stroke:var(--line-2);fill:none;
 stroke-width:1.4;margin-bottom:.8rem}
.empty h3{color:var(--soft);margin:.2rem 0 .4rem;font-size:1.05rem}
.bar{height:5px;border-radius:3px;background:var(--inset);overflow:hidden;
 margin:.4rem 0 .25rem;max-width:340px}
.bar i{display:block;height:100%;background:var(--accent);border-radius:3px;
 transition:width .4s linear}
.spin{width:16px;height:16px;border:2px solid var(--line-2);border-top-color:var(--accent);
 border-radius:50%;display:inline-block;animation:sp .8s linear infinite;vertical-align:-3px}
@keyframes sp{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}

/* print — the page is handed on as a PDF, and paper does not scroll.
   Every `overflow-x:auto` container that fits on screen by scrolling was
   CLIPPED at the page edge: the region table lost its right-hand columns and
   the clock strip lost its last two cities. A scroll bar is a promise the
   reader can see more, and print cannot keep it, so on paper the content
   wraps or shrinks instead. */
@media print{
 .clocks{overflow:visible;flex-wrap:wrap;row-gap:.35rem}
 .clocks .clk{min-width:0}
 .clocks .clk:first-child{padding-left:.85rem;border-left:1px solid var(--line-2)}
 .tablewrap,.card,[style*="overflow-x:auto"]{overflow:visible!important}
 table{font-size:.72rem;table-layout:fixed;width:100%}
 th,td{padding:.35rem .4rem;white-space:normal!important;word-break:break-word}
 .card{break-inside:avoid;page-break-inside:avoid;box-shadow:none}
 .btn,form,.spin{display:none!important}
 /* Sticky is a screen idea. On paper it either repeats on every sheet or
    prints over the content under it, and neither is the clock wall. */
 .topbar,.clocks,.side,.cols-2 > :nth-child(2){position:static!important}
}
"""


def icon(name: str, cls: str = "") -> str:
    return ("<svg viewBox='0 0 24 24' class='%s' stroke-linecap='round' "
            "stroke-linejoin='round'>%s</svg>" % (cls, ICONS.get(name, "")))


def sev_pill(sev: str, count: Optional[int] = None) -> str:
    c = SEV_COLORS.get(sev, "var(--info)")
    mark = SEV_MARKS.get(sev, "?")
    label = E(sev) if count is None else "%s %d" % (E(sev), count)
    return ("<span class='pill' style='color:%s;"
            "background:color-mix(in srgb,%s 13%%,transparent);"
            "border-color:color-mix(in srgb,%s 42%%,transparent)'>"
            "<span class='mark' style='background:%s'>%s</span>%s</span>"
            % (c, c, c, c, mark, label))


def sev_donut(counts: Dict[str, int]) -> str:
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    if not total:
        return ("<div class='donut' style='background:conic-gradient(var(--low) 0 100%%)'>"
                "<div class='hole'><span class='big'>0</span>"
                "<span class='lab'>findings</span></div></div>")
    stops, acc = [], 0.0
    for s in SEVERITY_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        frac = n / total * 100.0
        stops.append("%s %.2f%% %.2f%%" % (SEV_COLORS[s], acc, acc + frac))
        acc += frac
    grad = "conic-gradient(%s)" % ", ".join(stops)
    label = ", ".join("%d %s" % (counts.get(sv, 0), sv)
                      for sv in SEVERITY_ORDER if counts.get(sv, 0))
    return ("<div class='donut' role='img' aria-label='%s' title='%s' "
            "style='background:%s'><div class='hole'>"
            "<span class='big'>%d</span><span class='lab'>findings</span></div></div>"
            % (E(label), E(label), grad, total))


def sev_breakdown(counts: Dict[str, int]) -> str:
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER) or 1
    bar = "".join(
        "<span style='width:%.2f%%;background:%s' title='%s: %d'></span>"
        % (counts.get(s, 0) / total * 100.0, SEV_COLORS[s], s, counts.get(s, 0))
        for s in SEVERITY_ORDER if counts.get(s, 0))
    # Each count links to exactly the findings behind it. A number that
    # references data and cannot be opened is a number the reader has to take
    # on trust, which is the thing this tool exists not to ask for.
    rows = "".join(
        "<a class='sevrow' href='/estate?sev=%s' style='text-decoration:none;"
        "color:inherit' title='Every %s finding across the estate'>"
        "<span class='lbl'><span class='mark' style='background:%s'>%s</span>%s"
        "</span><b>%d</b></a>"
        % (s, s, SEV_COLORS[s], SEV_MARKS[s], s, counts.get(s, 0))
        for s in SEVERITY_ORDER if s != "unknown")
    return "<div class='sevbar'>%s</div>%s" % (bar, rows)


def empty_state(icon_name: str, title: str, msg: str, cta: str = "") -> str:
    return ("<div class='empty'>%s<h3>%s</h3><p>%s</p>%s</div>"
            % (icon(icon_name), E(title), E(msg), cta))


def rescan_form(service_key: str, target: str,
                label: str = "Rescan", cls: str = "btn ghost") -> str:
    """A one-click rescan of a target already scanned: re-runs the same service
    against the same target rather than making the operator re-type it. It POSTs
    to the same /run endpoint the scan form uses, so it inherits the origin
    check, the scope resolution and the DAST private-target rail for free."""
    return ("<form method='post' action='/run' style='display:inline'>"
            "<input type='hidden' name='service' value='%s'>"
            "<input type='hidden' name='target' value='%s'>"
            "<button class='%s' type='submit' title='Re-run this scan and "
            "compare against this run'>%s %s</button></form>"
            % (E(service_key), E(target), cls, icon("rescan"), E(label)))


def page(title: str, body: str, active: str = "",
         ctx: str = "", head_extra: str = "") -> bytes:
    nav_items = [("", "overview", "Overview"), ("scan", "scan", "Scan"),
                 ("findings", "findings", "Findings"),
                 ("estate", "findings", "Estate"),
                 ("priority", "priority", "Priority"),
                 ("intel", "priority", "Intel"), ("triage", "triage", "Triage"),
                 ("history", "history", "History"),
                 ("cloud", "cloud", "Cloud"),
                 ("baselines", "baselines", "Baselines")]
    nav = "".join(
        "<a href='/%s' class='%s'>%s<span>%s</span></a>"
        % (route, "on" if key == active else "", icon(key), label)
        for route, key, label in nav_items)
    legend = "".join(
        "<div><span class='mark' style='background:%s'>%s</span>%s</div>"
        % (SEV_COLORS[s], SEV_MARKS[s], s)
        for s in ("critical", "high", "medium", "low"))
    scope = (
        "<svg width='26' height='26' viewBox='0 0 30 30' fill='none'>"
        "<circle cx='15' cy='15' r='13' stroke='#2f5a5c' stroke-width='1.4'/>"
        "<circle cx='15' cy='15' r='7.5' stroke='#2f5a5c' stroke-width='1.2'/>"
        "<circle cx='15' cy='15' r='2' fill='#3fd6cc'/>"
        "<path d='M15 15 L26 8' stroke='#3fd6cc' stroke-width='1.6' stroke-linecap='round'/>"
        "<path d='M15 2 v3 M15 25 v3 M2 15 h3 M25 15 h3' stroke='#2f5a5c' "
        "stroke-width='1.4' stroke-linecap='round'/></svg>")
    toggle = (
        "<div class='themetoggle' role='group' aria-label='Theme'>"
        "<button id='t-light' type='button' onclick=\"sqTheme('light')\">"
        "<svg viewBox='0 0 20 20'><circle cx='10' cy='10' r='4'/>"
        "<path d='M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2M4 4l1.4 1.4M14.6 14.6L16 16"
        "M16 4l-1.4 1.4M5.4 14.6L4 16' stroke-linecap='round'/></svg>Light</button>"
        "<button id='t-dark' type='button' onclick=\"sqTheme('dark')\">"
        "<svg viewBox='0 0 20 20'><path d='M16 11a6.5 6.5 0 11-7-7 5 5 0 007 7z' "
        "stroke-linejoin='round'/></svg>Dark</button></div>")
    theme_js = (
        "<script>function sqTheme(t){document.documentElement.setAttribute("
        "'data-theme',t);var l=document.getElementById('t-light'),"
        "d=document.getElementById('t-dark');if(l)l.classList.toggle('sel',t==='light');"
        "if(d)d.classList.toggle('sel',t==='dark');try{localStorage.setItem("
        "'squawk-theme',t)}catch(e){}}(function(){var v;try{v=localStorage.getItem("
        "'squawk-theme')}catch(e){}var t=v||(matchMedia('(prefers-color-scheme:dark)')"
        ".matches?'dark':'light');sqTheme(t)})();</script>")
    doc = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s · Squawk</title><style>%s</style>%s</head><body>"
        "<div class='shell'>"
        "<aside class='side'><div class='brand'>%s<div>SQUAWK"
        "<div class='tagline'>covering your six</div></div></div><nav>%s</nav>%s"
        "<div class='legend'>Severity%s"
        "<div class='loop'><span class='dot'></span>loopback only · read-only</div>"
        "</div></aside>"
        "<div class='content'><div class='topbar'><div class='ctx'>%s</div>"
        "<a class='btn' href='/scan'>%s Run scan</a></div>%s"
        "<main>%s</main></div></div>%s%s</body></html>"
        % (E(title), PAGE_CSS, head_extra, scope, nav, toggle, legend,
           ctx or "", icon("scan"), clock_wall(), body, theme_js, CLOCK_JS))
    return doc.encode("utf-8")


# The wall an operations room hangs: UTC first, because that is what the
# evidence is stamped in, then the desks the work moves between, west to east.
# Canonical IANA names only — `Europe/Frankfurt` is a link that is absent from
# some tz databases, and a clock that silently vanished would be worse than
# one that was never offered.
WORLD_ZONES = (
    ("UTC", "UTC"),
    # The four US offsets, not two. Honolulu and Denver were missing, so a
    # wall meant to answer "what time is it where that ran" skipped two of
    # the zones a US estate actually runs in.
    ("Pacific/Honolulu", "Honolulu"),
    ("America/Los_Angeles", "Los Angeles"),
    ("America/Denver", "Denver"),
    ("America/Chicago", "Chicago"),
    ("America/New_York", "New York"),
    ("America/Sao_Paulo", "Sao Paulo"),
    ("Europe/London", "London"),
    ("Europe/Berlin", "Berlin"),
    ("Asia/Dubai", "Dubai"),
    # Half-hour offsets exist and a wall that only shows whole hours quietly
    # teaches that they do not.
    ("Asia/Kolkata", "Mumbai"),
    ("Asia/Singapore", "Singapore"),
    ("Asia/Tokyo", "Tokyo"),
    ("Australia/Sydney", "Sydney"),
    ("Pacific/Auckland", "Auckland"),
)


# Every spelling of "no offset" the tz database carries. A container whose
# /etc/localtime points at Etc/UTC would otherwise have added an eleventh
# clock beside UTC showing the same time — the duplicate the wall exists to
# avoid, wearing a different name. Seen on python:3.9, 2026-09-07.
UTC_ALIASES = frozenset({
    "UTC", "Etc/UTC", "Etc/GMT", "GMT", "GMT0", "GMT+0", "GMT-0", "Etc/GMT0",
    "Etc/GMT+0", "Etc/GMT-0", "Greenwich", "Etc/Greenwich", "Universal",
    "Etc/Universal", "Zulu", "Etc/Zulu", "UCT", "Etc/UCT",
})


def canonical_zone(zone: str) -> str:
    """The name this wall hangs a zone under. Only the UTC family is folded:
    two zones that merely share an offset today are still two zones and will
    part company at the next daylight-saving change."""
    return "UTC" if zone in UTC_ALIASES else zone


def _zone_now(zone: str, when: float) -> Optional[Tuple[str, str, str, str]]:
    """(HH:MM:SS, `Tue 08 Sep`, abbreviation, `UTC+9`) in a zone, or None when this
    machine's time-zone database does not have it. None is the honest answer:
    the clock is left off the wall and the wall says how many are missing."""
    try:
        from zoneinfo import ZoneInfo
        moment = datetime.datetime.fromtimestamp(when, ZoneInfo(zone))
    except Exception:
        return None
    # The offset comes with it: an operator reading a UTC run id off the page
    # can convert it against any clock on the wall without knowing which zones
    # are on daylight saving today.
    off = moment.strftime("%z")            # +0900
    off = "UTC%s%s" % (off[0], off[1:3].lstrip("0") or "0") + (
        ":%s" % off[3:] if off[3:] != "00" else "")
    return (moment.strftime("%H:%M:%S"), moment.strftime("%a %d %b"),
            moment.tzname() or zone, off)


def clock_wall() -> str:
    """The wall, the way an operations room hangs it — the operator's own
    request, and their correction to the first version: not two clocks on the
    same zone, but the three main American zones plus UTC, the major European
    and Asian ones, and any other standard zone, each once.

    Two of the clocks are also facts about this run: one is badged **server**,
    the machine the scans run on, and one **you**, the browser reading. In
    this tool's lab those are two machines — a Kali VM and a laptop through a
    tunnel — and the evidence is stamped in a third zone, UTC. A run id read
    as local time is an hour's confusion at the wrong moment. Where the server
    or the reader is already on the wall, that clock is badged rather than
    drawn twice; where it is not, it is added.

    Server time is sent once as an epoch and ticked forward by the time spent
    on the page rather than re-read from the browser: a browser whose clock is
    wrong must not make the server's look wrong too."""
    now = time.time()
    local = time.localtime(now)
    offset = -(time.altzone if local.tm_isdst > 0 else time.timezone)
    server_zone = canonical_zone(_server_zone())
    zones = list(WORLD_ZONES)
    if server_zone and server_zone not in [z for z, _l in zones]:
        zones.append((server_zone, server_zone.rsplit("/", 1)[-1].replace("_", " ")))
    cells, missing = [], []
    for zone, label in zones:
        shown = _zone_now(zone, now)
        if shown is None:
            missing.append(zone)
            continue
        hhmmss, day, abbr, off = shown
        # Some zones have no name of their own — the tz database answers `+04`
        # for Dubai — and printing "+04 · UTC+4" says one thing twice.
        tail = off if (abbr == "UTC" or abbr[:1] in "+-") else "%s · %s" % (abbr, off)
        here = zone == server_zone
        # The zone's abbreviation is rendered once, by this machine's own tz
        # database (BST, JST, PDT) — the browser's `timeZoneName:'short'`
        # answers `GMT+1` for some of the same zones, and an operations wall
        # is read by those labels. It only changes at a DST boundary, so the
        # script updates the time and the date beside it and leaves it alone.
        #
        # A clock that is one of *these* machines is marked by the whole cell,
        # not by a chip in the corner: on a wall of ten identical clocks a
        # small badge is easy to miss, which is what the operator found.
        cells.append(
            "<div class='clk%s' data-zone='%s' title='%s · %s'>"
            "<span class='zone'>%s%s</span>"
            "<span class='now'>%s</span>"
            "<span class='day'><span class='dt'>%s</span> %s</span></div>"
            % (" here" if here else "", E(zone), E(zone), E(off),
               E(label if zone != "UTC" else "UTC · evidence"),
               "<span class='who'>server</span>" if here else "",
               E(hhmmss), E(day), E(tail)))
    note = ("<div class='clk miss' title='%s'>%d zone(s) missing from this "
            "machine&#39;s time-zone database</div>"
            % (E(", ".join(missing)), len(missing))) if missing else ""
    return ("<div class='clocks' id='sq-clocks' data-epoch='%.3f' "
            "data-offset='%d' data-server='%s'>%s%s</div>"
            % (now, offset, E(server_zone or ""), "".join(cells), note))


def _server_zone() -> str:
    """This machine's IANA zone name, or "" when it cannot be read as one.
    `time.tzname` gives an abbreviation (`CDT`), which is not a zone and is
    ambiguous across hemispheres, so the zone itself is what the wall needs."""
    try:
        import zoneinfo
        key = getattr(time, "tzname", ("",))[0]
        link = os.path.realpath("/etc/localtime")
        if "/zoneinfo/" in link:
            cand = link.split("/zoneinfo/", 1)[1]
            zoneinfo.ZoneInfo(cand)
            return cand
        env_tz = os.environ.get("TZ", "")
        if env_tz:
            zoneinfo.ZoneInfo(env_tz)
            return env_tz
        del key
    except Exception:
        return ""
    return ""


CLOCK_JS = (
    "<script>(function(){var w=document.getElementById('sq-clocks');if(!w)return;"
    "var base=parseFloat(w.dataset.epoch)*1000,t0=Date.now(),"
    "srvZone=w.dataset.server||'',you='';"
    "try{you=Intl.DateTimeFormat().resolvedOptions().timeZone||''}catch(e){}"
    # The same folding as the server does, so a browser reporting Etc/UTC
    # badges the UTC clock rather than adding a second one beside it.
    "if(/^(Etc\\/)?(UTC|GMT|UCT|Universal|Zulu|Greenwich|GMT[+-]?0)$/.test(you))"
    "you='UTC';"
    "var cells=[].slice.call(w.querySelectorAll('.clk[data-zone]')),fmt={};"
    # One formatter shape, so the browser's rendering matches the server's:
    # en-US short month (Sep, not Sept) and the zone abbreviation, which is
    # what makes a wall of clocks readable at a glance.
    "function mk(z){return new Intl.DateTimeFormat('en-US',{timeZone:z,"
    "hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false,"
    "weekday:'short',day:'2-digit',month:'short',timeZoneName:'short'})}"
    "cells.forEach(function(c){var z=c.dataset.zone;try{"
    "fmt[z]=mk(z)}catch(e){}});"
    # The reader's own zone: badge the clock that already shows it, or add one.
    # Two clocks reading the same time is what the first version got wrong.
    "if(you){var mine=cells.filter(function(c){return c.dataset.zone===you})[0];"
    "if(!mine&&fmtZone(you)){mine=document.createElement('div');"
    "mine.className='clk';mine.dataset.zone=you;mine.title=you;"
    "mine.innerHTML=\"<span class='zone'></span><span class='now'></span>\"+"
    # No `.dt` inside it: this clock was added by the script, so the script
    # fills the whole line, abbreviation included.
    "\"<span class='day'></span>\";"
    "mine.querySelector('.zone').textContent=you.split('/').pop()"
    ".replace(/_/g,' ');w.insertBefore(mine,w.firstChild.nextSibling);"
    "cells.push(mine)}"
    # One mark, not two chips: where the server is also the machine reading —
    # the common case on a laptop — the wall says "server · you" once.
    "if(mine){mine.classList.add('here');var z=mine.querySelector('.zone'),"
    "b=z.querySelector('.who');"
    "if(b){if(b.textContent.indexOf('you')<0)b.textContent=b.textContent+' · you'}else{"
    "b=document.createElement('span');b.className='who';b.textContent='you';"
    "z.appendChild(b)}b.classList.add('you')}}"
    "function fmtZone(z){try{fmt[z]=fmt[z]||mk(z);return true}catch(e){return false}}"
    "function tick(){"
    # The server's clock, carried forward by the time spent on the page and
    # never re-read from the browser — whose clock may be the wrong one.
    "var srv=new Date(base+(Date.now()-t0));"
    "cells.forEach(function(c){var f=fmt[c.dataset.zone];if(!f)return;"
    "var parts={};f.formatToParts(srv).forEach(function(p){parts[p.type]=p.value});"
    "var n=c.querySelector('.now'),d=c.querySelector('.dt');"
    "if(n)n.textContent=parts.hour+':'+parts.minute+':'+parts.second;"
    "if(d)d.textContent=parts.weekday+' '+parts.day+' '+parts.month;"
    "if(!d&&c.querySelector('.day'))c.querySelector('.day').textContent="
    "parts.weekday+' '+parts.day+' '+parts.month+' '+(parts.timeZoneName||'')});"
    "var skew=Math.abs(Date.now()-srv.getTime()),yc=w.querySelector('.who.you');"
    "if(yc){yc.classList.toggle('skew',skew>120000);"
    "yc.title=skew>120000?('your browser and the server disagree by '"
    "+Math.round(skew/60000)+' min — every timestamp in the evidence comes from "
    "the server'):'in step with the server'}"
    "}tick();setInterval(tick,1000);})();</script>")


def _fmt_run_time(run_id_str: str) -> str:
    try:
        t = time.strptime(run_id_str[:16], "%Y%m%dT%H%M%SZ")
        return time.strftime("%b %d, %H:%M", t) + " UTC"
    except ValueError:
        return run_id_str


def _short_target(target: object) -> str:
    """What a target is called on screen. Every list, heading and picker goes
    through here, which is why the account mask lives here too -- and why it
    coerces first: this is fed straight from manifests on disk, and one run
    whose target was a JSON null raised out of here and took the entire
    Findings page down with it."""
    text = as_text(target)
    if "/" in text and not text.startswith(("image:",)):
        return os.path.basename(text.rstrip("/")) or text
    return mask_account(text)


def rel_time(run_id_str: str, now: Optional[float] = None) -> Tuple[str, bool]:
    """A run's age in words, and whether it is past STALE_SCAN_DAYS. Run ids
    are UTC stamps, so the arithmetic is done in UTC."""
    try:
        t = calendar.timegm(time.strptime(run_id_str[:15], "%Y%m%dT%H%M%S"))
    except (ValueError, OverflowError):
        return "", False
    secs = max(0.0, (now if now is not None else time.time()) - t)
    if secs < 90:
        txt = "just now"
    elif secs < 3600:
        txt = "%d min ago" % (secs // 60)
    elif secs < 86400:
        txt = "%d h ago" % (secs // 3600)
    else:
        txt = "%d d ago" % (secs // 86400)
    return txt, secs > STALE_SCAN_DAYS * 86400


def sparkline(runs: List[dict]) -> str:
    """A target's severity-weighted score across its runs, oldest to newest,
    as a small inline line. Up is cleaner, matching the compare trend. A run
    that could not fully look ends the line with a hollow point. Fewer than two
    runs has no trend to draw."""
    pts = sorted(runs, key=lambda m: m["run_id"])
    if len(pts) < 2:
        return "<span class='muted'>&mdash;</span>"
    scores = [_run_score(m) for m in pts]
    lo, hi = min(scores), max(scores)
    w, h, pad = 96, 24, 3

    def xat(i):
        return pad + (w - 2 * pad) * i / (len(pts) - 1)

    def yat(sc):
        frac = (sc - lo) / (hi - lo) if hi > lo else 0.5
        return pad + frac * (h - 2 * pad)

    poly = " ".join("%.1f,%.1f" % (xat(i), yat(sc)) for i, sc in enumerate(scores))
    last = ("fill='var(--panel)' stroke='var(--gap)' stroke-width='1.6'"
            if _run_incomplete(pts[-1]) else "fill='var(--accent)'")
    return ("<svg class='spark' viewBox='0 0 %d %d' width='%d' height='%d' role='img' "
            "aria-label='%d runs, score trend'><title>%d runs, oldest to newest; up "
            "is cleaner</title><polyline points='%s' fill='none' stroke='var(--accent)' "
            "stroke-width='1.5' stroke-linejoin='round'/><circle cx='%.1f' cy='%.1f' "
            "r='2.6' %s/></svg>"
            % (w, h, w, h, len(pts), len(pts), poly, xat(len(pts) - 1),
               yat(scores[-1]), last))


def integrity_block(root: str) -> Tuple[str, str]:
    """The evidence-integrity card and, if it needs saying, the attention-strip
    line that points at it. Never verified is shown as never verified: a store
    nobody has checked is not a store that checked out."""
    st = verify_state(root)
    status = st["status"]
    look = {"ok": ("var(--ok)", "verified"),
            "failed": (SEV_COLORS["critical"], "does not verify"),
            "unverifiable": ("var(--gap)", "partly unverifiable"),
            "never": ("var(--gap)", "never verified")}
    color, word = look.get(status, ("var(--gap)", status))
    when = ("checked %s" % _fmt_verify_time(st["at"])) if st["at"] else \
        "no verification has ever been run against this evidence root"
    body = ("Run the command below and this card will say what it found."
            if status == "never" else E(st["summary"]))
    card_html = (
        "<h2 id='integrity'>Evidence integrity</h2>"
        "<div class='card'><p style='margin:0 0 .5rem'>"
        "<b style='color:%s'>Evidence %s</b> <span class='muted'>&middot; %s</span></p>"
        "<p class='muted' style='margin:.2rem 0 .6rem'>%s</p>"
        "<p class='mono' style='font-size:.78rem;margin:0'>squawk verify</p>"
        "<p class='muted' style='font-size:.75rem;margin:.5rem 0 0'>Every run "
        "hashes its own files and the run before it, so a file edited after the "
        "fact is named. This proves the evidence was not changed; it does not "
        "prove who wrote it, because there are no signatures here.</p></div>"
        % (color, E(word), E(when), body))
    attn = ""
    if status == "failed":
        attn = ("<a class='attn-i gap' href='#integrity'>&#9650; the evidence "
                "does not verify</a>")
    elif status == "never":
        attn = ("<a class='attn-i stale' href='#integrity'>evidence never "
                "verified</a>")
    elif status == "unverifiable":
        attn = ("<a class='attn-i stale' href='#integrity'>some evidence cannot "
                "be verified</a>")
    return card_html, attn


def _fmt_verify_time(stamp: str) -> str:
    """20260906T204421Z as something a person reads. The raw stamp if it is not
    the shape this writes, rather than a guess."""
    try:
        t = time.strptime(stamp, "%Y%m%dT%H%M%SZ")
    except (ValueError, TypeError):
        return stamp or "an unrecorded time"
    return time.strftime("%d %b %Y %H:%M UTC", t)


def view_overview(root: str) -> str:
    """The landing page: estate posture at a glance — the summary before the detail."""
    runs = list_runs(root)
    if not runs:
        return (
            "<h1>Overview</h1><p class='sub'>Estate posture at a glance.</p>"
            + empty_state("scan", "No scans yet",
                          "Run your first scan to see posture, findings, and drift here.",
                          "<a class='btn' href='/scan'>Run a scan</a>"))

    # The split lives in evidence.estate_runs so every page that answers "what
    # do I look after" answers it the same way.
    live, vanished, by_target = estate_runs(root)

    sev_totals: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for m in live.values():
        for s, n in m.get("severities", {}).items():
            sev_totals[s] = sev_totals.get(s, 0) + n
    open_total = sum(sev_totals.values())
    excluded = sum(m.get("counts", {}).get("excluded", 0) for m in live.values())

    # 12-week activity strip
    weeks_present = {iso_week(m["run_id"]) for m in runs}
    strip = []
    now = time.gmtime()
    for i in range(11, -1, -1):
        wt = time.gmtime(time.mktime(now) - i * 7 * 86400)
        wk = "%s-W%s" % (time.strftime("%G", wt), time.strftime("%V", wt))
        strip.append("<span class='week %s' title='%s'></span>"
                     % ("has" if wk in weeks_present else "none", wk))

    # top targets by risk (critical+high first)
    def risk(m: dict) -> int:
        sv = m.get("severities", {})
        return sv.get("critical", 0) * 1000 + sv.get("high", 0) * 100 + \
            sv.get("medium", 0) * 10 + sv.get("low", 0)

    gap_pill = ("<span class='pill' style='color:var(--gap);background:color-mix("
                "in srgb,var(--gap) 13%,transparent);border-color:color-mix(in "
                "srgb,var(--gap) 42%,transparent)' title='A stage could not fully "
                "scan — this is a gap, not a clean result'>"
                "<span class='mark' style='background:var(--gap)'>&#9650;</span>"
                "gap</span>")
    target_rows = []
    for m in sorted(live.values(), key=risk, reverse=True):
        sv = m.get("severities", {})
        incomplete = _run_incomplete(m)
        links = " ".join(
            "<a href='/findings?run=%s&amp;sev=%s' style='text-decoration:none' "
            "title='Open %s findings for this target'>%s</a>"
            % (E(m["run_id"]), E(s), E(s), sev_pill(s, sv[s]))
            for s in SEVERITY_ORDER if sv.get(s))
        if links:
            # Findings present; if a stage also could not look, the counts are a
            # floor, so flag the gap alongside them.
            chips = links + (" " + gap_pill if incomplete else "")
        elif incomplete:
            # No findings AND a stage could not look is not clean — it is a gap.
            note = ("aborted: %s" % m.get("aborted_reason", "never finished")
                    if m.get("aborted") else "did not fully scan")
            chips = (gap_pill + " <span class='muted' style='font-size:.75rem'>%s</span>"
                     % E(note))
        else:
            chips = sev_pill("low", 0).replace("low 0", "clean")
        ago, stale = rel_time(m["run_id"])
        target_rows.append(
            "<tr><td><b>%s</b><div class='mono muted' style='font-size:.72rem'>%s</div>"
            "<div class='muted' style='font-size:.7rem'>%s</div></td>"
            "<td>%s</td><td class='sparkcell'>%s</td>"
            "<td class='muted' title='%s'>%s%s</td>"
            "<td>%s "
            "<a href='/findings?run=%s' style='margin-left:.4rem'>view &rarr;</a>"
            "</td></tr>"
            % (E(_short_target(m.get("target", ""))),
               E(mask_account(m.get("target", ""))),
               E(m.get("service_label", "")), chips,
               sparkline(by_target.get(target_key(m), [])),
               E(_fmt_run_time(m["run_id"])), E(ago),
               " <span class='stale'>stale</span>" if stale else "",
               rescan_form(m.get("service", ""), m.get("target", ""), "Rescan"),
               E(m["run_id"])))

    recent = "".join(
        "<tr><td class='muted' style='white-space:nowrap'>%s</td>"
        "<td><b>%s</b><div class='mono muted' style='font-size:.72rem'>%s</div>"
        "</td><td class='muted'>%s</td>"
        "<td><b>%d</b> <span class='muted'>findings</span></td>"
        "<td><a href='/findings?run=%s'>open &rarr;</a></td></tr>"
        % (E(_fmt_run_time(m["run_id"])),
           E(_short_target(m.get("target", ""))),
           E(mask_account(m.get("target", ""))),
           E(m.get("service_label", "")),
           m.get("counts", {}).get("total", 0), E(m["run_id"]))
        for m in runs[:6])

    crit_high = sev_totals.get("critical", 0) + sev_totals.get("high", 0)
    # Exploited now, across the newest run of every target. Honest when the
    # feeds are absent: a dash and the reason, never a zero that reads as none.
    feeds = load_feeds(root)
    if feeds.get("present"):
        kev_n = 0
        for m in live.values():
            for f in load_findings(m["_dir"]):
                c = cve_of(f)
                if c and c in feeds["kev"]:
                    kev_n += 1
        exploited_tile = ("<a class='card tight stat' href='/intel' "
                          "style='text-decoration:none' title='Every KEV finding "
                          "across the estate, with its evidence'><span class='n' "
                          "style='color:%s'>%d</span><span class='k'>exploited "
                          "now (KEV) &rarr;</span></a>"
                          % (SEV_COLORS["critical"] if kev_n else "var(--ok)", kev_n))
    else:
        exploited_tile = ("<a class='card tight stat' href='/intel' "
                          "style='text-decoration:none' title='Run squawk feeds "
                          "to fetch CISA KEV and EPSS'><span class='n muted'>"
                          "&mdash;</span><span class='k'>exploited now &middot; "
                          "feeds not fetched &rarr;</span></a>")
    gap_n = sum(1 for m in live.values() if _run_incomplete(m))
    stale_n = sum(1 for m in live.values() if rel_time(m["run_id"])[1])
    attn_items = []
    if gap_n:
        attn_items.append("<a class='attn-i gap' href='#targets'>&#9650; %d target%s "
                          "with a coverage gap</a>"
                          % (gap_n, "" if gap_n == 1 else "s"))
    if stale_n:
        attn_items.append("<a class='attn-i stale' href='#targets'>%d target%s not "
                          "scanned in %d+ days</a>"
                          % (stale_n, "" if stale_n == 1 else "s", STALE_SCAN_DAYS))
    if vanished:
        attn_items.append("<a class='attn-i' href='#vanished'>%d vanished target%s, not "
                          "counted</a>" % (len(vanished), "" if len(vanished) == 1 else "s"))
    integrity_card, integrity_attn = integrity_block(root)
    if integrity_attn:
        attn_items.append(integrity_attn)
    attn = "<div class='attn'>%s</div>" % "".join(attn_items) if attn_items else ""
    vanished_block = ""
    if vanished:
        vrows = "".join(
            "<tr><td><b>%s</b><div class='mono muted' style='font-size:.72rem'>%s</div>"
            "</td><td class='muted'>%s</td><td class='muted'>%s</td>"
            "<td><a href='/findings?run=%s'>view &rarr;</a></td></tr>"
            % (E(_short_target(m.get("target", ""))),
               E(mask_account(m.get("target", ""))),
               E(m.get("service_label", "")), E(_fmt_run_time(m["run_id"])),
               E(m["run_id"]))
            for m in sorted(vanished.values(), key=lambda m: m["run_id"], reverse=True))
        vanished_block = (
            "<details id='vanished' style='margin-top:.8rem'><summary class='muted' "
            "style='cursor:pointer'>%d vanished target%s: directory no longer on disk. "
            "Not counted above; kept as evidence.</summary><table style='margin-top:"
            ".5rem'><tbody>%s</tbody></table></details>"
            % (len(vanished), "" if len(vanished) == 1 else "s", vrows))
    return (
        "<h1>Overview</h1><p class='sub'>Newest run of every target — the estate "
        "as it stands. A week with no scan is a gap, not clean.</p>"

        "<div class='grid' style='grid-template-columns:repeat(auto-fit,minmax(170px,1fr))'>"
        "<a class='card tight stat' href='/estate?sev=critical,high' "
        "style='text-decoration:none' title='Every critical and high finding "
        "across the estate — the same count as this tile'>"
        "<span class='n' style='color:%s'>%d</span>"
        "<span class='k'>critical &amp; high &rarr;</span></a>"
        "<a class='card tight stat' href='/estate' style='text-decoration:none' "
        "title='Every open finding across every target'><span class='n'>%d</span>"
        "<span class='k'>open findings &rarr;</span></a>"
        "<a class='card tight stat' href='#targets' style='text-decoration:none'>"
        "<span class='n'>%d</span>"
        "<span class='k'>targets tracked &rarr;</span></a>%s</div>%s"

        "<div class='grid cols-2' style='margin-top:1rem'>"
        "<div class='card' id='targets'><h3>Targets by risk</h3>"
        "<table><thead><tr><th>Target</th><th>Open findings</th><th>Trend</th>"
        "<th>Last scan</th><th></th></tr></thead><tbody>%s</tbody></table>%s</div>"
        "<div class='card' style='display:flex;gap:1.2rem;align-items:center'>"
        "%s<div style='flex:1'>%s"
        "<p class='muted' style='font-size:.75rem;margin:.6rem 0 0'>%d finding(s) "
        "excluded as working-tree contamination</p></div></div></div>"

        "<h2>Scan activity — last 12 weeks</h2>"
        "<div class='card tight'>%s</div>"

        "<h2>Recent runs</h2>"
        "<div class='card tight'><table><tbody>%s</tbody></table></div>%s"
        % (SEV_COLORS["critical"] if crit_high else SEV_COLORS["low"], crit_high,
           open_total, len(live), exploited_tile, attn, "".join(target_rows),
           vanished_block,
           sev_donut(sev_totals), sev_breakdown(sev_totals), excluded,
           "".join(strip), recent, integrity_card))


_SKIP_DIRS = frozenset((".git", "node_modules", ".venv", "venv", "__pycache__",
                        "site-packages", "Library", ".Trash", ".cache", ".npm",
                        ".cargo", "dist", "build", ".tox", ".idea", "Applications"))


def scan_roots() -> List[str]:
    """Directories the target picker may list and search: SQUAWK_SCAN_ROOTS
    (colon-separated), defaulting to the home directory. The browser never
    leaves these, so the picker cannot be used to walk the rest of the disk."""
    raw = env("SCAN_ROOTS") or os.path.expanduser("~")
    out: List[str] = []
    for part in raw.split(":"):
        real = os.path.realpath(os.path.expanduser(part.strip()))
        if part.strip() and os.path.isdir(real) and real not in out:
            out.append(real)
    return out


def _under_roots(path: str, roots: List[str]) -> bool:
    real = os.path.realpath(path)
    return any(real == r or real.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def discover_repos(roots: List[str], max_depth: int = 3, budget: int = 4000) -> List[str]:
    """Git checkouts under the scan roots, a few levels deep, so a repo is
    picked rather than typed. Hidden and dependency directories are pruned, a
    checkout is not descended into, and a directory budget bounds the walk so a
    large home cannot stall the page."""
    found: List[str] = []
    seen = 0
    for root in roots:
        base_depth = root.rstrip(os.sep).count(os.sep)
        for cur, dirs, _files in os.walk(root):
            seen += 1
            if seen > budget:
                dirs[:] = []
                break
            if ".git" in dirs:
                found.append(cur)
                dirs[:] = []
                continue
            if cur.rstrip(os.sep).count(os.sep) - base_depth >= max_depth:
                dirs[:] = []
                continue
            dirs[:] = sorted(d for d in dirs
                             if not d.startswith(".") and d not in _SKIP_DIRS)
    return sorted(set(found))


def list_dir(path: str, roots: List[str]) -> Tuple[Optional[str], List[Tuple[str, bool]]]:
    """Subdirectories of one directory inside the scan roots, each flagged as a
    git checkout or not. Outside the roots, or unreadable, it returns the reason
    and nothing. Hidden entries are skipped and the listing is capped."""
    real = os.path.realpath(os.path.expanduser(path or ""))
    if not _under_roots(real, roots):
        return "outside the scan roots (set SQUAWK_SCAN_ROOTS)", []
    if not os.path.isdir(real):
        return "not a directory", []
    try:
        names = sorted(os.listdir(real))
    except OSError as exc:
        return str(exc), []
    out: List[Tuple[str, bool]] = []
    for name in names:
        if name.startswith(".") or name in _SKIP_DIRS:
            continue
        full = os.path.join(real, name)
        if os.path.isdir(full):
            out.append((full, os.path.isdir(os.path.join(full, ".git"))))
        if len(out) >= 300:
            break
    return None, out


def recent_targets(root: str) -> List[dict]:
    """Every target that has a run, newest first, once each, with whether it is
    still on disk. A vanished one is offered as gone, not as a choice that would
    launch a run against nothing."""
    out: List[dict] = []
    seen = set()
    for m in list_runs(root):
        key = target_key(m)
        if key in seen:
            continue
        seen.add(key)
        scope = m.get("scope", "")
        tgt = m.get("target", "")
        out.append({"service": m.get("service", ""), "scope": scope, "target": tgt,
                    "label": m.get("service_label", ""), "run_id": m["run_id"],
                    "gone": scope in ("repo", "dir") and not os.path.isdir(tgt)})
    return out


def _chip(scope: str, target: str, gone: bool = False) -> str:
    shown = _short_target(target) if scope in ("repo", "dir") else mask_account(target)
    return ("<button type='button' class='chip%s' data-scope='%s' data-target='%s'%s "
            "title='%s'><span class='sc'>%s</span>%s%s</button>"
            % (" gone" if gone else "", E(scope), E(target),
               " disabled" if gone else "", E(target), E(scope), E(shown),
               " <span class='sc'>gone</span>" if gone else ""))


def _rel_root(path: str, roots: List[str]) -> str:
    """A path as the picker labels it: relative to the scan root that holds it,
    with the home directory written as ~, so two checkouts that share a name
    still read as different choices."""
    real = os.path.realpath(path)
    home = os.path.realpath(os.path.expanduser("~"))
    for r in roots:
        base = r.rstrip(os.sep)
        if real == base or real.startswith(base + os.sep):
            head = "~" if base == home else (os.path.basename(base) or base)
            rel = real[len(base):].lstrip(os.sep)
            return head + ("/" + rel if rel else "")
    return path


def _target_options(scope: str, recent: List[dict], repos: List[str],
                    roots: List[str]) -> List[Tuple[str, List[Tuple[str, str, bool]]]]:
    """What a service tile offers for its scope, grouped: the targets it has run
    against (a vanished one shown as gone, never as a choice that would launch a
    run against nothing), then what the scan roots hold. A repo tile lists the
    git checkouts found; a directory tile lists the roots and the checkouts too,
    since a checkout is also a directory. Each entry is (value, label, gone)."""
    groups: List[Tuple[str, List[Tuple[str, str, bool]]]] = []
    seen = set()
    rec = []
    for r in recent:
        if r["scope"] != scope or r["target"] in seen:
            continue
        seen.add(r["target"])
        label = _rel_root(r["target"], roots) if scope in ("repo", "dir") else r["target"]
        rec.append((r["target"], label, r["gone"]))
    if rec:
        groups.append(("Recent", rec))
    if scope == "repo":
        found = [(p, _rel_root(p, roots), False) for p in repos if p not in seen]
        if found:
            groups.append(("Git checkouts found", found))
    elif scope == "dir":
        base = [(p, _rel_root(p, roots), False) for p in roots if p not in seen]
        if base:
            groups.append(("Scan roots", base))
        found = [(p, _rel_root(p, roots), False) for p in repos
                 if p not in seen and p not in roots]
        if found:
            groups.append(("Git checkouts found", found))
    return groups


def _target_select(scope: str, groups: List[Tuple[str, List[Tuple[str, str, bool]]]],
                   default: str, placeholder: str, label: str) -> str:
    """The tile's target control: a list of what it knows plus 'Other path',
    which reveals a typed field. With nothing to list (no image or URL has been
    run yet, say) it is the typed field alone, honestly, rather than an empty
    list. The posted field is always `target`; `_posted_target` reads it."""
    choices = [v for _t, es in groups for v, _l, gone in es if not gone]
    if not choices:
        return ("<input type='text' name='target' value='%s' placeholder='%s' "
                "data-scope='%s' aria-label='target for %s'>"
                % (E(default), E(placeholder), E(scope), E(label)))
    listed = default in choices
    opts = []
    for title, entries in groups:
        body = "".join(
            "<option value='%s' title='%s'%s%s>%s%s</option>"
            % (E(v), E(v), " disabled" if gone else "",
               " selected" if (v == default and not gone) else "",
               E(lbl), " (gone)" if gone else "")
            for v, lbl, gone in entries)
        opts.append("<optgroup label='%s'>%s</optgroup>" % (E(title), body))
    other = default and not listed
    return ("<select name='target' data-scope='%s' aria-label='target for %s'>%s"
            "<option value='__other__'%s>Other path&hellip;</option></select>"
            "<input type='text' name='target_other' value='%s' placeholder='%s' "
            "data-scope='%s' aria-label='other target for %s'>"
            % (E(scope), E(label), "".join(opts), " selected" if other else "",
               E(default if other else ""), E(placeholder), E(scope), E(label)))


def _posted_target(form: Dict[str, List[str]]) -> str:
    """The target a tile posted. A tile offers a list plus 'Other path'; when
    the list says other, the typed field is the answer."""
    picked = (form.get("target", [""])[0] or "").strip()
    if picked == "__other__":
        return (form.get("target_other", [""])[0] or "").strip()
    return picked


def view_scan(root: str, repo: Optional[str], browse: Optional[str] = None) -> str:
    """The scan launcher: each tile is the picker. A tile lists the targets it
    knows for its scope (recent runs, git checkouts under the scan roots, the
    roots themselves) and 'Other path' for one it does not; nothing has to be
    typed to run against something already known. A directory browser, kept
    folded, finds one none of the tiles lists. It never leaves the scan roots."""
    from urllib.parse import quote
    roots = scan_roots()
    recent = recent_targets(root)
    repos = discover_repos(roots)
    cur = browse or (roots[0] if roots else "")
    err, entries = list_dir(cur, roots) if cur else ("no scan roots", [])
    if err:
        brows = ("<div class='muted' style='font-size:.8rem'>%s: %s</div>"
                 % (E(cur), E(err)))
    else:
        real = os.path.realpath(cur)
        parent = os.path.dirname(real)
        up = ("<div class='brow'><a href='/scan?browse=%s'>&uarr; %s</a></div>"
              % (quote(parent), E(parent))
              if parent != real and _under_roots(parent, roots) else "")
        rows = "".join(
            "<div class='brow'><a href='/scan?browse=%s'>%s/</a>%s"
            "<button type='button' class='chip' data-scope='%s' data-target='%s'>"
            "use</button></div>"
            % (quote(p), E(os.path.basename(p)),
               " <span class='repo'>git</span>" if is_repo else "",
               "repo" if is_repo else "dir", E(p))
            for p, is_repo in entries)
        here_scope = "repo" if os.path.isdir(os.path.join(real, ".git")) else "dir"
        brows = ("<div class='mono muted' style='font-size:.74rem;margin-bottom:.3rem'>"
                 "%s <button type='button' class='chip' data-scope='%s' "
                 "data-target='%s'>use this directory</button></div>%s"
                 "<div class='list'>%s</div>"
                 % (E(real), here_scope, E(real), up,
                    rows or "<div class='muted' style='font-size:.8rem'>no "
                            "subdirectories</div>"))
    picker = (
        "<details class='picker'%s><summary>Browse for a directory no tile lists"
        "</summary><p class='muted' style='font-size:.82rem;margin:.4rem 0 .6rem'>"
        "Each tile below lists what it knows: targets already run, and the git "
        "checkouts under <span class='mono'>%s</span> (set <span class='mono'>"
        "SQUAWK_SCAN_ROOTS</span> to look elsewhere). This browser is for a "
        "directory none of them lists; <b>use</b> puts it in every matching "
        "tile. It never leaves the scan roots.</p>"
        "<div class='browse'>%s</div></details>"
        % (" open" if browse else "", E(", ".join(roots)), brows))

    placeholders = {"repo": "/path/to/git/checkout", "dir": "/path/to/directory",
                    "image": "registry/image:tag", "url": "http://192.168.56.x/"}
    cards = []
    for s in SERVICES.values():
        # A probe built into Squawk has no binary to be missing; listing it as
        # a gap told the reader the self-audit could not run when it always can.
        gaps = [STAGES[st].tool for st in s.stages
                if not SCANNERS[STAGES[st].tool].internal
                and not tool_path(SCANNERS[STAGES[st].tool].binary)]
        tools = "".join(
            "<span class='tag%s'>%s</span>"
            % (" gap" if STAGES[st].tool in gaps else "", E(STAGES[st].tool))
            for st in dict.fromkeys(s.stages))
        gap_note = ("<div class='meta' style='color:var(--high)'>missing: %s — "
                    "recorded as coverage gaps, never as a pass</div>"
                    % E(", ".join(gaps)) if gaps else "")
        subject = ""
        if s.scope == "host":
            # The subject is this machine, named the way the CLI names it.
            # Nothing typed could change that, so nothing is asked for. It sits
            # above the form rather than inside it: the form is a flex row, so
            # a subject line in it shared the row with the button and left Run
            # floating in the middle of the tile.
            # The subject sits IN the control row, in a box the same shape as
            # the other tiles' pickers, so twelve tiles share one geometry: a
            # bare Run button under a sentence was the one tile that did not.
            control = ("<input type='hidden' name='target' value='host' "
                       "data-scope='host'>"
                       "<div class='fixed' title='The subject is this machine; "
                       "nothing typed could change that.'>this machine &middot; "
                       "<span class='mono'>%s</span></div>" % E(socket.gethostname()))
        elif s.scope == "aws":
            control = ("<input type='hidden' name='target' value='credential-chain' "
                       "data-scope='aws'>"
                       "<div class='fixed' title='The AWS account the credential "
                       "chain resolves to. The identity is named before anything "
                       "is read.'>the account your AWS credential chain resolves "
                       "to</div>")
        else:
            default = (repo or "") if s.scope == "repo" else ""
            control = _target_select(
                s.scope, _target_options(s.scope, recent, repos, roots),
                default, placeholders.get(s.scope, ""), s.label)
        cards.append(
            "<div class='svc'><div class='row'><span class='name'>%s</span>"
            "<span class='meta'>%s · %s</span></div>"
            "<div class='tools'>%s</div>"
            "<div class='meta nc'>not covered: %s</div>%s%s"
            "<form method='post' action='/run'>"
            "<input type='hidden' name='service' value='%s'>%s"
            "<button class='btn'>Run</button></form></div>"
            % (E(s.label), E(s.scope), E(s.rough_time), tools, E(s.not_covered),
               gap_note, subject, E(s.key), control))
    js = ("<script>"
          "function syncOther(s){var o=s.parentNode.querySelector("
          "'input[name=target_other]');if(!o)return;"
          "var other=s.value==='__other__';o.hidden=!other;"
          "if(other&&document.activeElement===s)o.focus()}\n"
          "Array.prototype.forEach.call(document.querySelectorAll("
          "'select[name=target]'),syncOther);\n"
          "document.addEventListener('change',function(ev){var s=ev.target;"
          "if(s&&s.matches&&s.matches('select[name=target]'))syncOther(s)});\n"
          "document.addEventListener('click',function(ev){"
          "var b=ev.target.closest&&ev.target.closest('.chip');if(!b||b.disabled)return;"
          "var sc=b.getAttribute('data-scope'),t=b.getAttribute('data-target');"
          "var scopes=(sc==='repo'||sc==='dir')?['repo','dir']:[sc];"
          "Array.prototype.forEach.call(document.querySelectorAll("
          "'select[name=target],input[name=target]'),function(el){"
          "if(scopes.indexOf(el.getAttribute('data-scope'))<0)return;"
          "if(el.tagName==='SELECT'){var have=false;"
          "Array.prototype.forEach.call(el.options,function(op){"
          "if(op.value===t)have=true});"
          "if(!have){var op=document.createElement('option');op.value=t;"
          "op.textContent=t;el.insertBefore(op,el.querySelector("
          "'option[value=__other__]'))}el.value=t;syncOther(el)}"
          "else{el.value=t}"
          "el.style.outline='2px solid var(--accent)';"
          "setTimeout(function(){el.style.outline=''},900)})});"
          "</script>")
    return (
        "<h1>Run a scan</h1><p class='sub'>Each service states its scope, its "
        "tools, and what it does <i>not</i> cover — that text is part of the "
        "result, not decoration. Pick a target from the tile's list; type one "
        "only if it is not there yet.</p>%s"
        "<div class='grid cols-auto'>%s</div>%s" % (picker, "".join(cards), js))

def _run_stage_raw(man: dict, tool: str) -> Optional[dict]:
    """A stage's own raw output for a run, read back by the path its ledger row
    recorded. Used to show a self-audit's per-check results, which live in the
    raw output but not in the findings — an 'ok' check is not a finding."""
    for row in man.get("ledger", []):
        if row.get("tool") == tool and row.get("evidence"):
            path = os.path.join(man.get("_dir", ""), row["evidence"])
            try:
                with open(path, encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError, ValueError):
                return None
    return None


_STATUS_DOT = {"ok": "var(--ok)", "gap": "var(--gap)", "skipped": "var(--faint)",
               "error": "var(--crit)", "unknown": "var(--unknown)"}


def _pruned_note(man: dict) -> str:
    """Say that a run's raw output was removed by retention.

    A trimmed run and a run whose scanners never wrote anything show the same
    empty space, and that is this tool's cardinal sin doing the housekeeping.
    The ledger above still says what each stage found and examined; what is
    gone is the scanner's own output behind it."""
    rec = prune_record(man.get("_dir", ""))
    if not rec:
        return ""
    return ("<div class='banner' style='margin-top:.7rem'>"
            "<b>Raw scanner output was removed from this run</b> on %s by "
            "retention%s. The ledger above is intact and every count still "
            "comes from this run; what is gone is the scanner's own output "
            "behind it, so a finding here cannot be re-checked against what "
            "the tool printed. Removed: <span class='mono'>%s</span>.</div>"
            % (E(_fmt_run_time(str(rec.get("at", "")))),
               (" (%s)" % E(str(rec["by"]))) if rec.get("by") else "",
               E(", ".join(str(x) for x in rec.get("removed", [])))))


def profile_line(man: dict) -> str:
    """What the run ran under, on the run page (I12): the profile it used and
    every value that differed from the built-in, or that none did — and, for
    a run written before profiles existed, that this was not recorded."""
    prof = man.get("profile")
    if prof is None:
        body = ("<b>Profile:</b> <span class='muted'>not recorded &mdash; this run "
                "predates profiles, so it ran under the built-in budgets of its day</span>")
    elif not prof.get("path"):
        body = "<b>Profile:</b> none &mdash; built-in budgets"
    else:
        parts = ["%s %s = %s <span class='muted'>(built-in %s) %s</span>"
                 % (E(str(c.get("stage", ""))), E(str(c.get("key", ""))),
                    E(show_setting(c.get("value"))), E(show_setting(c.get("builtin"))),
                    E(str(c.get("section", ""))))
                 for c in (prof.get("changed") or [])]
        for tool, args in sorted((prof.get("extra_args") or {}).items()):
            parts.append("%s extra_args + <span class='mono'>%s</span>"
                         % (E(str(tool)), E(" ".join(str(a) for a in args))))
        body = ("<b>Profile:</b> <span class='mono'>%s</span> <span class='muted'>(%s)"
                "</span> &mdash; %s" % (E(str(prof.get("path", ""))),
                                        E(str(prof.get("source", ""))),
                                        "; ".join(parts) if parts
                                        else "no value differs from the built-in"))
        for note in (prof.get("notes") or []):
            body += "<br><b>Note:</b> %s" % E(str(note))
    return "<p style='font-size:.82rem'>%s</p>" % body


def coverage_panel(man: dict) -> str:
    """What the run actually ran and looked at — a clean verdict shown with its
    work. The tool's own rule, turned on itself: a pass that shows nothing is
    indistinguishable from a scan that never happened. Includes a self-audit's
    passing checks, which are dropped from the findings on purpose."""
    ledger = man.get("ledger", [])
    if not ledger:
        return ""
    rows = []
    for row in ledger:
        st = row.get("status", "")
        cov = row.get("coverage")
        if cov and cov.get("examined") is not None:
            looked = "examined %d %s" % (cov["examined"], E(cov.get("unit", "")))
            if cov.get("note"):
                # What the number does not include, beside the number.
                looked += ("<div class='muted' style='font-size:.72rem'>%s</div>"
                           % E(str(cov["note"])))
        elif cov:
            looked = "<span class='muted'>publishes no coverage</span>"
        else:
            looked = "<span class='muted'>&mdash;</span>"
        # The budget the stage ran under, with its source when a profile set
        # it, and the command itself on hover: what ran is the argv.
        ran = row.get("ran") or {}
        if ran.get("timeout"):
            # What it took, against what it was allowed. A stage that finished
            # well inside its budget and one that nearly hit it read the same
            # when only the budget is shown, and the second is the one worth
            # knowing about before the next run.
            # The same wording as the job page while it was running — that
            # said "6m 35s of the 40m 00s budget" and this said "6m 42s of
            # 2400 s", one number in two hands (the operator's screenshots,
            # 2026-09-08). The raw seconds are what a profile types; a page
            # that reports elapsed against it should read the same both times.
            took = ran.get("elapsed")
            budget = ("%s of %s" % (E(human_seconds(took)),
                                    E(human_seconds(ran["timeout"])))
                      if took is not None else E(human_seconds(ran["timeout"])))
            if ran.get("timeout_from") and ran["timeout_from"] != "built-in":
                budget += " <span class='muted'>%s</span>" % E(str(ran["timeout_from"]))
            budget_title = E(" ".join(str(a) for a in (ran.get("command") or [])))
        elif ran.get("internal") and ran.get("elapsed") is not None:
            # No subprocess, so no bound to show — but the time it took is
            # measured, and saying "—" for a stage that ran hides that.
            budget = ("%s <span class='muted'>in-process</span>"
                      % E(human_seconds(ran["elapsed"])))
            budget_title = "runs in-process; no stage timeout applies"
        else:
            budget, budget_title = "<span class='muted'>&mdash;</span>", ""
        rows.append(
            "<tr><td class='mono'>%s</td>"
            "<td><span class='dot' style='background:%s'></span> %s</td>"
            "<td>%s</td><td class='mono' style='font-size:.8rem' title='%s'>%s</td>"
            "<td class='muted' style='font-size:.8rem'>%s</td></tr>"
            % (E(row.get("tool", "")), _STATUS_DOT.get(st, "var(--faint)"),
               E(st), looked, budget_title, budget,
               # The CLI redacts this same string (`cli.py`, `_line`); this
               # rendered it raw, so a ledger detail built from a role name or
               # an ARN reached the page with the account in it. Found in
               # review, 2026-09-18.
               E(redact_identifiers(row.get("detail", "")))))
    panel = ("<div class='card'><h3>What ran</h3>"
             "<p class='muted' style='font-size:.82rem'>Every stage, its status, "
             "what it examined and the budget it ran under &mdash; a clean result "
             "shown with its work, not asserted.</p>%s"
             "<div style='overflow-x:auto'><table><thead><tr>"
             "<th>Stage</th><th>Status</th><th>Examined</th><th>Budget</th>"
             "<th>Detail</th></tr></thead><tbody>%s</tbody></table></div>%s</div>"
             % (profile_line(man), "".join(rows), _pruned_note(man)))
    audit = _run_stage_raw(man, "selfaudit")
    if isinstance(audit, dict) and audit.get("checks"):
        # The fix is computed for every check and was not rendered, so the
        # panel told you what was wrong and never what to do about it. Each
        # check carries one; a check that passed has nothing to recommend and
        # says so rather than showing an empty cell.
        crows = "".join(
            "<tr><td style='white-space:nowrap'>"
            "<span class='dot' style='background:%s'></span> %s</td>"
            "<td class='mono muted' style='font-size:.75rem'>%s</td>"
            "<td><b>%s</b></td><td class='muted' style='font-size:.8rem'>%s</td>"
            "<td style='font-size:.8rem'>%s</td></tr>"
            % (_STATUS_DOT.get(c.get("status", ""), "var(--faint)"),
               E(c.get("status", "")), E(c.get("area", "")),
               E(c.get("title", "")), E(c.get("detail", "")),
               ("<span class='mono'>%s</span>" % E(str(c.get("fix", ""))))
               if c.get("fix") else
               ("<span class='muted'>nothing to do</span>"
                if c.get("status") == "ok" else
                "<span class='silent'>no fix recorded</span>"))
            for c in audit["checks"])
        panel += ("<div class='card'><h3>Instrument checks</h3>"
                  "<p class='muted' style='font-size:.82rem'>Every host check, "
                  "including the ones that passed, and what to do about each "
                  "one that did not. A self-audit that hides its passes is the "
                  "exact failure it exists to catch; one that reports a gap "
                  "with no fix is a complaint.</p>"
                  "<div style='overflow-x:auto'><table><thead><tr><th>Status</th>"
                  "<th>Area</th><th>Check</th><th>Detail</th><th>Recommendation"
                  "</th></tr></thead><tbody>%s</tbody></table></div></div>" % crows)
    nc = (man.get("not_covered") or "").strip()
    if nc:
        panel += ("<div class='card'><div class='mono muted' style='font-size:"
                  ".66rem;letter-spacing:.09em;text-transform:uppercase'>"
                  "Not covered by this service</div>"
                  "<p class='muted' style='font-size:.85rem;margin:.35rem 0 0;"
                  "max-width:96ch'>%s</p></div>" % E(nc))
    return panel


def _budget_bar(job: Job, stage: dict) -> str:
    """Elapsed against the bound this stage actually runs under, labelled as
    time rather than as work. A scanner publishes no progress, so a bar that
    advanced on a guess would be a denominator nobody measured — the one
    substitution this tool refuses everywhere else. When the stage has not yet
    said what its budget is, there is no bar and the elapsed stands alone."""
    budget = stage.get("timeout")
    if not budget:
        return ""
    elapsed = job.stage_elapsed(stage)
    pct = min(100.0, 100.0 * elapsed / float(budget))
    where = stage.get("timeout_from") or "built-in"
    return ("<div class='bar' title='time against this stage&#39;s %ss budget "
            "(%s) — not work done'><i style='width:%.1f%%'></i></div>"
            "<div class='muted' style='font-size:.75rem'>%s of the %s budget"
            "%s</div>"
            % (E(str(budget)), E(where), pct,
               E(human_seconds(elapsed)), E(human_seconds(budget)),
               "" if where == "built-in" else " &middot; %s" % E(where)))


def view_job(job: Job, root: str) -> str:
    if job.status == "running":
        done_n = sum(1 for s in job.stages if s["status"] != "running")
        total = len(job.service.stages)
        planned = list(dict.fromkeys(STAGES[st].tool for st in job.service.stages))
        rows = []
        for i, tool in enumerate(planned):
            st = job.stages[i] if i < len(job.stages) else None
            if st is None:
                icon_html = "<span style='color:var(--faint)'>·</span>"
                cell = "<span class='muted'>queued</span>"
                took = ""
            elif st["status"] == "running":
                icon_html = "<span class='spin'></span>"
                # The bar's caption already carries the elapsed; repeating it
                # in the right-hand column says the same number twice.
                bar = _budget_bar(job, st)
                cell = "<span class='soft'>running…</span>" + bar
                took = "" if bar else human_seconds(job.stage_elapsed(st))
            else:
                dot = {"ok": "var(--low)", "skipped": "var(--faint)",
                       "gap": "var(--high)",
                       "error": "var(--crit)"}.get(st["status"], "var(--faint)")
                icon_html = "<span class='dot' style='background:%s'></span>" % dot
                cell = "%s <span class='muted'>%s</span>" % (
                    E(st["status"]), E(st["detail"]))
                took = (human_seconds(st["elapsed"]) if st.get("elapsed") is not None
                        else "")
            rows.append("<tr><td style='width:24px'>%s</td>"
                        "<td class='mono'>%s</td><td>%s</td>"
                        "<td class='mono muted' style='text-align:right;"
                        "white-space:nowrap;font-size:.8rem'>%s</td></tr>"
                        % (icon_html, E(tool), cell, E(took)))
        return (
            "<h1><span class='spin'></span>&nbsp; Scanning… "
            "<span class='muted' style='font-size:1rem'>%d/%d</span></h1>"
            "<p class='sub'>%s against <span class='mono'>%s</span> &middot; "
            "%s in total so far, usually %s</p>"
            "<div class='card tight'><table><tbody>%s</tbody></table></div>"
            "<p class='muted' style='font-size:.8rem'>Scanners run as local "
            "subprocesses and publish no progress of their own, so the bar is "
            "time against the budget the stage is running under &mdash; not "
            "work done. A first run can be slower while databases download. "
            "This page refreshes itself.</p>"
            % (done_n, total, E(job.service.label), E(job.target),
               E(human_seconds(job.elapsed())), E(job.service.rough_time),
               "".join(rows)))
    if job.status == "error":
        return ("<h1>Run failed</h1><div class='card'>"
                "<p class='added'>%s</p>"
                "<p><a class='btn ghost' href='/scan'>Back to scans</a></p></div>"
                % E(job.error or "unknown error"))
    # The alarm belongs here as well. It was wired into the CLI and the
    # Findings header, but this is the page an operator is looking at the moment
    # a scan ends — an alarm you have to navigate to is an alarm that did not
    # sound. Silence is stated rather than left blank, for the same reason.
    runs_all = list_runs(root)
    man = next((m for m in runs_all if m["run_id"] == job.run_id), None)
    raised = squawk_check(root, man) if man else []
    if raised:
        verdict = squawk_banner(raised)
    elif man:
        verdict = ("<div class='card tight' style='border-left:4px solid "
                   "var(--low)'><b>No squawk.</b> <span class='muted'>Nothing "
                   "critical, nothing under attack, and every source that "
                   "reported last time reported again.</span></div>")
    else:
        verdict = ("<div class='card tight' style='border-left:4px solid "
                   "var(--high)'><b>No squawk verdict.</b> <span class='muted'>"
                   "The run's evidence could not be read, so no check was made "
                   "— this is not the same as nothing being wrong.</span></div>")
    # A rescan lands here. If this target has an earlier run, the first thing
    # the operator wants is what moved, so offer that before the raw findings.
    priors = sum(1 for m in runs_all if man and target_key(m) == target_key(man))
    compare_btn = ("<a class='btn' href='/compare?run=%s'>What changed</a>"
                   % E(job.run_id or "")) if priors >= 2 else ""
    # Which scan, and against what. The page said only "Scan complete" and a
    # run id, so an operator who had walked away could not tell what had just
    # run without watching where the job page came from (the operator,
    # 2026-09-07). The running view says it; the finished one must too.
    took = human_seconds(job.elapsed())
    return (
        "<h1>Scan complete</h1>"
        "<p class='sub'>%s against <span class='mono'>%s</span> &middot; took %s</p>"
        "<div class='banner'>Evidence written for run "
        "<span class='mono'>%s</span>.</div>%s"
        "<div class='card'>"
        "<p style='display:flex;gap:.6rem;flex-wrap:wrap'>%s"
        "<a class='btn ghost' href='/findings?run=%s'>Review findings</a>"
        "<a class='btn ghost' href='/history'>See drift</a>"
        "<a class='btn ghost' href='/'>Overview</a></p></div>%s"
        % (E(job.service.label), E(job.target), E(took), E(job.run_id or ""), verdict,
           compare_btn, E(job.run_id or ""),
           coverage_panel(man) if man else ""))


def squawk_banner(raised: List[dict]) -> str:
    """The same alarm for the web view. Rendered at the top of a run, because a
    code that has to be scrolled to is a code that was not raised."""
    if not raised:
        return ""
    blocks = []
    for r in raised:
        name, meaning = SQUAWK_CODES[r["code"]]
        # A scope-specific strapline, when the alarm carried one. The page and
        # the CLI must not disagree about what an alarm means.
        meaning = r.get("meaning") or meaning
        colour = "var(--crit)" if r["code"] in ("7500", "7700") else "var(--high)"
        # Masked at the point of display, like the CLI: the record keeps the
        # real ARN so the operator can act on it, and the screen shows the
        # form that is safe to screenshot.
        # `_why`, not `mask_account`: an alarm line can carry a denial, and a
        # denial under SSO carries the operator's address as well as the
        # account id. Masking one of the two is masking neither, in practice.
        items = "".join("<li>%s</li>" % _why(d) for d in r["detail"])
        blocks.append(
            "<div class='card tight' style='border-left:4px solid %s;"
            "margin-bottom:.6rem'>"
            "<div style='display:flex;gap:.7rem;align-items:baseline'>"
            "<span class='mono' style='font-size:1.15rem;font-weight:700;"
            "color:%s'>SQUAWK %s</span>"
            "<b>%s</b><span class='muted' style='font-size:.8rem'>%s</span></div>"
            "<div style='margin-top:.35rem;font-size:.88rem'>%s</div>"
            "<ul class='muted' style='font-size:.8rem;margin:.35rem 0 0 1rem'>"
            "%s</ul></div>"
            % (colour, colour, E(r["code"]), E(name), E(meaning),
               _why(r["why"]), items))
    return "".join(blocks)


def _first_of(items: List[dict], keys: Tuple[str, ...], cap: int = 600) -> str:
    """The first non-empty value for any of these keys across a group's
    findings. Grouped rows share an advisory, so its description and its fix
    are the same for every member; the first one that has it speaks for all."""
    for f in items:
        det = f.get("detail") or {}
        for key in keys:
            val = str(det.get(key, "") or "").strip()
            if val:
                return val[:cap]
    return ""


def _detail_block(det: dict) -> str:
    """What a reader needs to decide: what it is, what proved it, what to do.
    A field the scanner did not supply is left out rather than rendered as an
    empty row that reads like an answer."""
    if not det:
        return ("<p class='muted' style='font-size:.82rem'>This scanner supplied "
                "no description or remediation for the finding.</p>")
    rows = []
    for label, keys in (("What it is", ("description", "what")),
                        ("Remediation", ("remediation",)),
                        ("Evidence", ("evidence", "attack", "other")),
                        ("Reference", ("reference",))):
        vals = [str(det.get(k, "")).strip() for k in keys]
        if label == "Evidence":
            vals = [_real_evidence(v) for v in vals]
        vals = [v for v in vals if v]
        if not vals:
            continue
        body = "<br>".join(E(v).replace(chr(10), "<br>") for v in vals)
        cls = "mono" if label == "Evidence" else ""
        rows.append("<div style='margin:.55rem 0'><div class='mono muted' "
                    "style='font-size:.66rem;letter-spacing:.09em;"
                    "text-transform:uppercase'>%s</div>"
                    "<div class='%s' style='font-size:.85rem;max-width:96ch'>%s"
                    "</div></div>" % (label, cls, body))
    chips = []
    for label, k in (("CWE", "cwe"), ("WASC", "wasc"),
                     ("confidence", "confidence"), ("risk", "risk"),
                     ("fixed in", "fixed_in"), ("package", "package"),
                     ("installed", "installed"), ("rule", "rule")):
        v = str(det.get(k, "")).strip()
        if v:
            chips.append("<span class='dchip'>%s %s</span>" % (E(label), E(v)))
    if chips:
        rows.append("<div class='dchips' style='margin-top:.5rem'>%s</div>"
                    % "".join(chips))
    return "".join(rows)


def resolved_block(timeline: Dict[Tuple[str, str], dict], persisted: bool) -> str:
    """What this target had fixed before this run, with the date each one went.

    It is built before the early returns on purpose. A run that found nothing
    because everything was fixed used to render as "this run recorded no
    findings", which is the same page a target with nothing to find shows, and
    it dropped the one thing the reader wanted: the list of what they fixed and
    when. Two different results must not print the same page."""
    resolved = sorted(((k, v) for k, v in timeline.items()
                       if v.get("status") == "resolved"),
                      key=lambda kv: (kv[1].get("resolved_on") or "", kv[0]),
                      reverse=True)
    if not resolved:
        return ""
    rows = "".join(
        "<tr><td class='mono' style='font-size:.75rem'>%s</td>"
        "<td class='mono' style='font-size:.72rem'>%s</td>"
        "<td style='white-space:nowrap'>%s</td>"
        "<td class='muted' style='font-size:.75rem;white-space:nowrap'>"
        "first %s &middot; last %s &middot; %d run%s</td></tr>"
        % (E(t), E(i), E(_fmt_run_time(v.get("resolved_on") or "")),
           E(_fmt_run_time(v.get("first_seen") or "")),
           E(_fmt_run_time(v.get("last_seen") or "")), v.get("runs", 0),
           "" if v.get("runs", 0) == 1 else "s")
        for (t, i), v in resolved[:200])
    return ("<details class='card tight' style='margin-top:.6rem' open><summary "
            "style='cursor:pointer'>Resolved before this run &mdash; %d, with dates"
            "%s</summary><p class='muted' style='font-size:.8rem;margin:.5rem 0'>"
            "Present in an earlier run of this target and absent from a later one "
            "in which the same scanner ran. A scanner that did not run resolves "
            "nothing. Dated to the first run it was missing from.%s</p>"
            "<div style='overflow-x:auto'><table><thead><tr><th>Scanner</th>"
            "<th>Identity</th><th>Resolved on</th><th>Seen</th></tr></thead>"
            "<tbody>%s</tbody></table></div></details>"
            % (len(resolved),
               "" if len(resolved) <= 200 else " (first 200 shown)",
               "" if persisted else " Reconstructed now: this run predates the "
                                    "history file.",
               rows))


def view_findings(root: str, run_id: Optional[str],
                  sev_filter: Optional[str] = None,
                  scanner_filter: Optional[str] = None,
                  where: Optional[str] = None) -> str:
    runs = list_runs(root)
    if not runs:
        return ("<h1>Findings</h1><p class='sub'>What a run found, grouped so one "
                "advisory is one row.</p>"
                + empty_state("findings", "No runs yet",
                              "Run a scan and its findings land here.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))
    # An unknown run id is a bad request, not a reason to show a different run.
    # Silently substituting one made the header assert a run nobody asked for.
    man = next((m for m in runs if m["run_id"] == run_id), None) if run_id else runs[0]
    if man is None:
        return ("<h1>No such run</h1>" + empty_state(
            "findings", "That run id is not on record",
            "The id in the address does not match any run in this evidence "
            "root. Nothing was substituted for it.",
            "<a class='btn' href='%s'>Newest run</a>" % '/findings'))
    findings = load_findings(man["_dir"])
    hist = finding_history(root, man)
    cur = current_decisions(root, man.get("target", ""))
    timeline, persisted = history_entries(root, man)
    fixed = resolved_block(timeline, persisted)
    n_resolved = sum(1 for v in timeline.values() if v.get("status") == "resolved")

    scanners = sorted({f["scanner"] for f in findings})
    matched = [f for f in findings
               if (not sev_filter or f["severity"] == sev_filter)
               and (not scanner_filter or f["scanner"] == scanner_filter)]
    # A finding about a test is not a finding about the product. Both are
    # recorded and both are counted; which set this page is showing is in the
    # address, so the number above expands to exactly these rows.
    #
    # Triage deliberately keeps both. Deciding once on a whole advisory is the
    # point of that page -- "skip bandit's assert rule in this target's tests"
    # is one decision, recorded once, and it follows the finding into every
    # later run. Splitting it there would make that decision twice.
    in_tests = [f for f in matched if is_test_code(f.get("path", ""))]
    in_product = [f for f in matched if not is_test_code(f.get("path", ""))]
    looking_at_tests = (where or "").lower() == "tests"
    shown = in_tests if looking_at_tests else in_product
    other = in_tests if not looking_at_tests else in_product

    def sel(name, current, options, label):
        opts = "".join("<option value='%s'%s>%s</option>"
                       % (E(o), " selected" if o == (current or "") else "",
                          E(o or label))
                       for o in ["", *list(options)])
        return ("<select name='%s' onchange='this.form.submit()'>%s</select>"
                % (name, opts))

    controls = (
        "<form method='get' action='/findings' class='card tight' "
        "style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;"
        "margin-bottom:1rem'>"
        "<select name='run' onchange='this.form.submit()'>%s</select>%s%s"
        "<span class='muted' style='margin-left:auto;font-size:.82rem'>"
        "%s%d shown%s &middot; %d excluded as contamination</span></form>"
        % ("".join("<option value='%s'%s>%s &middot; %s &middot; %s</option>"
                   % (E(m["run_id"]),
                      " selected" if m["run_id"] == man["run_id"] else "",
                      E(_short_target(m.get("target", ""))),
                      E(m.get("service_label", "")),
                      E(_fmt_run_time(m["run_id"])))
                   for m in runs),
           sel("sev", sev_filter, list(SEVERITY_ORDER), "All severities"),
           sel("scanner", scanner_filter, scanners, "All scanners"),
           ("<input type='hidden' name='where' value='tests'>"
            if looking_at_tests else ""),
           len(shown),
           # The other set's count beside this one's, so the two numbers a
           # reader sees on this page and on the Overview reconcile at a
           # glance (review 3, R-40).
           (" &middot; %d in %s" % (len(other), "test code"
                                     if not looking_at_tests else "product code")
            if other else ""),
           man.get("counts", {}).get("excluded", 0)))

    head = ("<div style='display:flex;align-items:flex-start;justify-content:"
            "space-between;gap:1rem'><div><h1>Findings</h1>"
            "<p class='sub'>Run of <span class='mono'>%s</span>"
            " &middot; %s &middot; not covered: %s</p></div>"
            "<div style='display:flex;gap:.4rem;flex-wrap:wrap'>"
            "<a class='btn' href='/priority?run=%s' title='What to act on first, "
            "and why'>%s Priority</a>"
            "<a class='btn ghost' href='/compare?run=%s' title='What changed "
            "since the last run of this target'>%s Compare</a>%s</div></div>%s"
            % (E(mask_account(man.get("target", ""))),
               E(man.get("service_label", "")),
               E(man.get("not_covered", "")), E(man["run_id"]), icon("priority"),
               E(man["run_id"]), icon("compare"),
               rescan_form(man.get("service", ""), man.get("target", ""),
                           "Rescan this target"),
               squawk_banner(squawk_check(root, man))))

    if not shown:
        if man.get("aborted"):
            return head + controls + (
                "<div class='card tight' style='border-left:4px solid var(--gap)'>"
                "<b>This run was aborted</b> <span class='muted'>(%s) and recorded "
                "nothing. It is kept so the gap is visible; rescan the target for a "
                "result.</span></div>" % E(str(man.get("aborted_reason", ""))))
        if not findings:
            # No findings is only a clean result if the run also looked. Show
            # what ran (and a self-audit's passing checks) rather than a blank,
            # and show what was fixed to get here: a target cleared by work and
            # a target that never had anything are different results.
            lede = ("This run recorded no findings. That is a clean result only "
                    "because it looked &mdash; here is what ran.")
            if n_resolved:
                lede = ("This run recorded no findings, and %d were resolved "
                        "before it. That is a clean result only because it "
                        "looked &mdash; what was fixed, and what ran, are both "
                        "below." % n_resolved)
            if _run_incomplete(man):
                # No findings and a stage that could not look is not clean.
                # This said "only because it looked" over a table in which
                # nothing had.
                ledger = man.get("ledger") or []
                bad = [r for r in ledger
                       if r.get("status") in ("gap", "error", "skipped")
                       or ((r.get("coverage") or {}).get("examined") == 0)]
                fixed_part = (" %d were resolved before it, and the fixes are real; "
                              "the clean result is not." % n_resolved) if n_resolved \
                    else " That is a gap, not a clean result."
                lede = ("This run recorded no findings, <b>and it did not fully "
                        "look</b>: %d of %d stage(s) could not run or examined "
                        "nothing.%s Here is what ran and what did not%s."
                        % (len(bad), len(ledger), fixed_part,
                           ", and what was fixed" if n_resolved else ""))
            return (head + controls + "<p class='sub'>%s</p>" % lede
                    + fixed + coverage_panel(man))
        other_set = in_tests if not looking_at_tests else in_product
        if other_set:
            side = ("test code" if not looking_at_tests else "product code")
            back = ("&amp;where=tests" if not looking_at_tests else "")
            # The count of THIS side before the filters, not `len(shown)`,
            # which is zero in this branch by construction and printed
            # "None of the 0 in product code" (review 3, R-45).
            mine = sum(1 for f in findings
                       if is_test_code(f.get("path", "")) == looking_at_tests)
            return head + controls + empty_state(
                "findings", "Nothing here matches these filters",
                "This run holds %d finding(s). None of the %d in %s matches "
                "these filters, and %d are in the %s."
                % (len(findings), mine,
                   "product code" if not looking_at_tests else "test code",
                   len(other_set), side),
                "<a class='btn' href='/findings?run=%s%s'>Show the %d in %s</a>"
                % (E(man["run_id"]), back, len(other_set), E(side))) + fixed
        return head + controls + empty_state(
            "findings", "Nothing matches these filters",
            "This run holds %d finding(s); the filters above exclude them all."
            % len(findings)) + fixed

    # Where the other set is, said with its exact count and a link that shows
    # it. A finding moved behind a number is not a finding dropped (I12), and
    # the sentence has to work in both directions: on the test page it points
    # back at the product.
    elsewhere = ""
    if other:
        qs_other = ["run=%s" % man["run_id"]]
        if sev_filter:
            qs_other.append("sev=%s" % sev_filter)
        if scanner_filter:
            qs_other.append("scanner=%s" % scanner_filter)
        if not looking_at_tests:
            qs_other.append("where=tests")
        elsewhere = (
            "<div class='card tight' style='margin-bottom:.8rem'>"
            "<span style='font-size:.88rem'><a href='/findings?%s' "
            "style='color:inherit'><b class='mono'>%d</b></a> more finding(s) "
            "%s. %s</span></div>"
            % (E("&amp;".join(qs_other)).replace("&amp;amp;", "&amp;"),
               len(other),
               "are in this target's test code"
               if not looking_at_tests else "are in the product code",
               "An assert in a test is what a test is made of; the same line "
               "in shipped code is a finding. Both are recorded — this page "
               "shows the product first."
               if not looking_at_tests
               else "This page is showing the test code."))

    # One advisory is one row, grouped by (scanner, rule) — the same key Triage
    # uses, so the two pages never disagree on the count. Grouping by the message
    # text instead split one rule into several rows whenever its wording varied
    # by match (e.g. the mode in a file-permissions finding), and the "3 here / 4
    # in triage" that came from was exactly the confusion this removes.
    groups: Dict[Tuple[str, str], dict] = {}
    for f in shown:
        rule = rule_of(f)
        gk = (f["scanner"], rule)
        g = groups.setdefault(gk, {"scanner": f["scanner"], "rule": rule,
                                   "title": f["title"], "sev": f["severity"],
                                   "items": [], "detail": f.get("detail") or {}})
        g["items"].append(f)
        if SEVERITY_ORDER.index(f["severity"]) < SEVERITY_ORDER.index(g["sev"]):
            g["sev"] = f["severity"]
        if not g["detail"]:
            g["detail"] = f.get("detail") or {}

    # Worst severity first, then volume: the group to open first belongs at the
    # top, and volume alone would put the biggest pile of lows there instead.
    ordered = sorted(groups.values(),
                     key=lambda g: (SEVERITY_ORDER.index(g["sev"]), -len(g["items"])))

    blocks = []
    for g in ordered:
        # Method and Evidence are DAST fields; a SAST group leaves them empty,
        # and an always-blank column reads as broken. Show a column only when
        # some instance in the group has it.
        has_method = any((f.get("detail") or {}).get("method") for f in g["items"])
        has_ev = any(_real_evidence((f.get("detail") or {}).get("evidence"))
                     for f in g["items"])
        inst_rows = []
        for f in sorted(g["items"], key=lambda x: x["path"]):
            h = hist.get(f["identity"])
            tl = timeline.get((f["scanner"], f["identity"])) or {}
            if tl.get("status") == "regressed":
                # Loud on purpose: it was gone and it is back. The dates are
                # the evidence.
                seen = ("<span class='regress'>regressed &middot; resolved %s, back "
                        "%s</span>" % (E(_fmt_run_time(tl.get("resolved_on") or "")),
                                        E(_fmt_run_time(tl.get("regressed_on") or ""))))
            elif not h or h["runs"] <= 1:
                seen = "<span class='muted'>first seen this run</span>"
            else:
                seen = ("<span class='muted'>seen in %d runs &middot; first %s"
                        "</span>" % (h["runs"], E(_fmt_run_time(h["first"]))))
            det = f.get("detail") or {}
            cells = ["<td class='mono' style='font-size:.78rem'>%s</td>"
                     % E(f["path"] or "/")]
            if has_method:
                cells.append("<td class='mono muted' style='font-size:.72rem'>%s"
                             "</td>" % E(str(det.get("method", ""))))
            if has_ev:
                cells.append("<td class='mono muted' style='font-size:.72rem'>%s"
                             "</td>" % E(_real_evidence(det.get("evidence"))[:80]))
            cells.append("<td style='font-size:.75rem'>%s</td>" % seen)
            cells.append("<td class='mono muted' style='font-size:.68rem'>%s</td>"
                         % E(f["identity"]))
            inst_rows.append("<tr>" + "".join(cells) + "</tr>")
        heads = ["<th>Path</th>"]
        if has_method:
            heads.append("<th>Method</th>")
        if has_ev:
            heads.append("<th>Evidence</th>")
        heads.append("<th>History</th><th>Identity</th>")
        n = len(g["items"])
        # The decision on this group, from the ledger, and any regression in
        # it: both belong on the summary line, because both change what the
        # reader does next.
        dec = summarize([cur.get((f["scanner"], f["identity"])) for f in g["items"]])
        n_reg = sum(1 for f in g["items"]
                    if (timeline.get((f["scanner"], f["identity"])) or {}).get("status")
                    == "regressed")
        chips = ""
        if n_reg:
            chips += "<span class='dchip regress'>%d regressed</span>" % n_reg
        dec_line = ""
        if dec["status"] != "open":
            label = (dec["status"] if dec["status"] != "partial"
                     else "%s %d/%d" % (dec["latest"], dec["decided"], dec["total"]))
            chips += ("<span class='dchip dec'>%s &middot; %s &middot; %s</span>"
                      % (E(label), E(dec["who"]), E(_fmt_run_time(dec["at"]))))
            dec_line = ("<div class='muted' style='font-size:.8rem;margin-bottom:.4rem'>"
                        "Decision: <b>%s</b> by %s, %s%s</div>"
                        % (E(label), E(dec["who"]), E(_fmt_run_time(dec["at"])),
                           (" &mdash; " + E(dec["note"])) if dec["note"] else ""))
        blocks.append(
            "<details class='card tight' style='margin-bottom:.6rem'>"
            "<summary style='cursor:pointer;display:flex;gap:.7rem;"
            "align-items:center;padding:.15rem 0'>%s"
            "<b style='flex:1'>%s</b>"
            "<span class='mono muted' style='font-size:.75rem'>%s &middot; %s</span>"
            "%s<span class='dchip'>%d instance%s</span></summary>"
            "<div style='padding:.6rem 0 .2rem'>%s%s"
            "<div style='overflow-x:auto'><table style='margin-top:.7rem'>"
            "<thead><tr>%s</tr></thead><tbody>%s</tbody>"
            "</table></div></div></details>"
            % (sev_pill(g["sev"]), E(g["title"]), E(g["scanner"]), E(g["rule"]),
               chips, n, "" if n == 1 else "s", dec_line, _detail_block(g["detail"]),
               "".join(heads), "".join(inst_rows)))

    n_reg_total = sum(1 for f in shown
                      if (timeline.get((f["scanner"], f["identity"])) or {}).get("status")
                      == "regressed")
    summary = ("<p class='sub'>%d finding(s) in %d group(s)%s%s. Expand a row for "
               "what it is, what proved it, what to do, and whether it has "
               "appeared before.</p>"
               % (len(shown), len(ordered),
                  " &middot; <span class='regress'>%d regressed</span>" % n_reg_total
                  if n_reg_total else "",
                  " &middot; %d resolved before this run" % n_resolved
                  if n_resolved else ""))
    ran = (
"<details class='card tight' style='margin-top:.6rem'><summary "
           "style='cursor:pointer'>What ran &mdash; coverage for this run"
           "</summary><div style='padding-top:.5rem'>%s</div></details>"
           % coverage_panel(man))
    return head + controls + elsewhere + summary + "".join(blocks) + fixed + ran


def view_history(root: str) -> str:
    runs = list_runs(root)
    if not runs:
        return ("<h1>History</h1><p class='sub'>Run cadence and identity-level "
                "drift.</p>"
                + empty_state("history", "No history yet",
                              "Each run is kept as immutable evidence; once a "
                              "target has two runs, the drift between them shows here.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))
    groups: Dict[str, List[dict]] = {}
    for m in runs:
        groups.setdefault(target_key(m), []).append(m)
    blocks = ["<h1>History</h1><p class='sub'>Diffs only compare runs of the "
              "same target. A scanner that did not run in both is <i>silent</i>, "
              "never <i>resolved</i>.</p><div class='grid cols-auto'>"]
    for group in groups.values():
        group_sorted = sorted(group, key=lambda m: m["run_id"], reverse=True)
        newest = group_sorted[0]
        head = ("<h3>%s <span class='muted' style='font-weight:400'>· %s</span></h3>"
                "<div class='mono muted' style='font-size:.72rem;margin-bottom:.5rem'>%s</div>"
                % (E(_short_target(newest.get("target", ""))),
                   E(newest.get("service_label", "")),
                   E(mask_account(newest.get("target", "")))))
        # The target's remediation record as of its newest run: what is open,
        # what was resolved and when, what came back. Regressions are loud.
        entries, persisted = history_entries(root, newest)
        counts = history_counts(entries)
        dated = sorted(((k, v) for k, v in entries.items()
                        if v.get("status") in ("resolved", "regressed")),
                       key=lambda kv: (kv[1].get("regressed_on") or kv[1].get("resolved_on")
                                       or "", kv[0]), reverse=True)
        tl_rows = "".join(
            "<tr><td class='mono' style='font-size:.72rem'>%s &middot; %s</td><td>%s</td></tr>"
            % (E(t), E(i),
               ("<span class='regress'>regressed %s</span> <span class='muted'>after "
                "resolved %s</span>" % (E(_fmt_run_time(v.get("regressed_on") or "")),
                                        E(_fmt_run_time(v.get("resolved_on") or ""))))
               if v.get("status") == "regressed" else
               "<span class='removed'>resolved %s</span>"
               % E(_fmt_run_time(v.get("resolved_on") or "")))
            for (t, i), v in dated[:60])
        timeline_html = (
            "<div style='display:flex;gap:.4rem;flex-wrap:wrap;margin:.2rem 0 .5rem'>"
            "<span class='dchip'>%d open</span><span class='dchip'>%d resolved</span>"
            "%s</div>%s"
            % (counts.get("open", 0), counts.get("resolved", 0),
               "<span class='dchip regress'>%d regressed</span>" % counts["regressed"]
               if counts.get("regressed") else "",
               ("<details><summary class='muted' style='cursor:pointer;font-size:.8rem'>"
                "Resolved and regressed, with dates%s</summary><table><tbody>%s</tbody>"
                "</table></details>"
                % ("" if persisted else " (reconstructed now)", tl_rows))
               if tl_rows else ""))
        if len(group_sorted) < 2:
            body = ("<p class='muted' style='font-size:.85rem'>One run so far "
                    "(%s) — nothing to diff against yet.</p>"
                    % E(_fmt_run_time(newest["run_id"])))
        else:
            d = diff_runs(group_sorted[1], newest)
            rows = []
            for tool, info in d.items():
                if info["silent"]:
                    cell = "<span class='silent'>silent — %s</span>" % E(info["reason"])
                else:
                    parts = []
                    if info["added"]:
                        parts.append("<span class='added'>+%d new</span>"
                                     % len(info["added"]))
                    if info["removed"]:
                        parts.append("<span class='removed'>&minus;%d resolved</span>"
                                     % len(info["removed"]))
                    if not parts:
                        parts.append("<span class='muted'>no change (%d)</span>"
                                     % info["unchanged"])
                    cell = " · ".join(parts)
                rows.append("<tr><td class='mono' style='width:90px'>%s</td>"
                            "<td>%s</td></tr>" % (E(tool), cell))
            body = ("<div class='muted' style='font-size:.75rem;margin-bottom:.3rem'>"
                    "%s &rarr; %s</div><table><tbody>%s</tbody></table>"
                    "<a class='btn ghost' style='margin-top:.6rem' "
                    "href='/compare?run=%s'>%s What changed</a>"
                    % (E(_fmt_run_time(group_sorted[1]["run_id"])),
                       E(_fmt_run_time(newest["run_id"])), "".join(rows),
                       E(newest["run_id"]), icon("compare")))
        blocks.append("<div class='card'>%s%s%s</div>" % (head, timeline_html, body))
    blocks.append("</div>")
    return "".join(blocks)


def _cmp_section(title: str, sub: str, body: str) -> str:
    return ("<div class='card'><h3>%s</h3>"
            "<p class='muted' style='font-size:.82rem'>%s</p>%s</div>"
            % (title, sub, body))


def risk_trend(runs: List[dict]) -> str:
    """A spike line of every run of one target over time. y is a -5..+5 rating
    with the target's median run at 0; higher is cleaner (fewer, less-severe
    findings). A run that could not fully scan is drawn hollow, so a zero that
    means 'did not look' is never read as a +5."""
    pts = sorted(runs, key=lambda m: m["run_id"])
    if len(pts) < 2:
        return ""
    scores = [_run_score(m) for m in pts]
    # The scale is set by runs that actually looked. An incomplete run's low
    # score is a floor, not a reading, so it must not pull the median or the
    # spread — otherwise a string of gap runs would redefine "median" as "did
    # not scan" and flatter every real run against it.
    complete = [scores[i] for i in range(len(pts)) if not _run_incomplete(pts[i])]
    ref = sorted(complete) if complete else sorted(scores)
    n = len(ref)
    median = ref[n // 2] if n % 2 else (ref[n // 2 - 1] + ref[n // 2]) / 2.0
    spread = max(abs(s - median) for s in ref) or 1

    def rating(s):
        return max(-5.0, min(5.0, (median - s) / spread * 5.0))

    width, height, padx, pady = 720, 150, 34, 18
    x0, x1, ytop, ybot = padx, width - 12, pady, height - pady

    def xat(i):
        return x0 + (x1 - x0) * (i / (len(pts) - 1))

    def yat(r):
        return ybot - (r + 5) / 10.0 * (ybot - ytop)

    poly = " ".join("%.1f,%.1f" % (xat(i), yat(rating(scores[i])))
                    for i in range(len(pts)))
    dots = []
    for i, m in enumerate(pts):
        r = rating(scores[i])
        cx, cy = xat(i), yat(r)
        tip = "%s | %d finding(s) | rating %+.1f%s" % (
            _fmt_run_time(m["run_id"]), m.get("counts", {}).get("total", 0), r,
            " | could not fully scan" if _run_incomplete(m) else "")
        if _run_incomplete(m):
            dots.append("<circle cx='%.1f' cy='%.1f' r='4.5' fill='var(--panel)'"
                        " stroke='var(--gap)' stroke-width='2'><title>%s</title>"
                        "</circle>" % (cx, cy, E(tip)))
        else:
            dots.append("<circle cx='%.1f' cy='%.1f' r='4' fill='var(--accent)'>"
                        "<title>%s</title></circle>" % (cx, cy, E(tip)))
    grid = ("<line x1='%d' y1='%.1f' x2='%d' y2='%.1f' stroke='var(--line)' "
            "stroke-dasharray='3 3'/>" % (x0, yat(5), x1, yat(5))
            + "<line x1='%d' y1='%.1f' x2='%d' y2='%.1f' stroke='var(--line)' "
              "stroke-dasharray='3 3'/>" % (x0, yat(-5), x1, yat(-5)))
    midline = ("<line x1='%d' y1='%.1f' x2='%d' y2='%.1f' stroke='var(--faint)'"
               " stroke-width='1'/>" % (x0, yat(0), x1, yat(0)))
    labels = ("<text x='4' y='%.1f' font-size='9' fill='var(--faint)'>+5</text>"
              "<text x='4' y='%.1f' font-size='9' fill='var(--faint)'>0</text>"
              "<text x='4' y='%.1f' font-size='9' fill='var(--faint)'>-5</text>"
              % (yat(5) + 3, yat(0) + 3, yat(-5) + 3))
    return ("<svg viewBox='0 0 " + str(width) + " " + str(height) + "' "
            "width='100%' role='img' aria-label='findings rating over time' "
            "style='max-width:100%;height:auto;display:block'>"
            + grid + midline + labels
            + "<polyline points='" + poly + "' fill='none' "
              "stroke='var(--accent)' stroke-width='2' stroke-linejoin='round'/>"
            + "".join(dots) + "</svg>")


def view_compare(root: str, run_id: Optional[str]) -> str:
    """What a rescan changed against the previous run of the same target:
    remediated (present before, gone now), new, and coverage that moved. A
    scanner that did not run OK in both runs is silent, never 'resolved' —
    otherwise a rescan that skipped a tool would read as its findings fixed."""
    runs = list_runs(root)
    if not runs:
        return ("<h1>What changed</h1><p class='sub'>What a rescan moved.</p>"
                + empty_state("compare", "No runs yet",
                              "Run a scan, then rescan the same target to see "
                              "what moved.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))
    man = (next((m for m in runs if m["run_id"] == run_id), None)
           if run_id else runs[0])
    if man is None:
        return ("<h1>No such run</h1>" + empty_state(
            "compare", "That run id is not on record",
            "The id in the address matches no run in this evidence root."))
    same = sorted((m for m in runs if target_key(m) == target_key(man)),
                  key=lambda m: m["run_id"])
    ids = [m["run_id"] for m in same]
    prior = same[ids.index(man["run_id"]) - 1] if ids.index(man["run_id"]) else None

    head = ("<div style='display:flex;align-items:flex-start;justify-content:"
            "space-between;gap:1rem'><div><h1>What changed</h1>"
            "<p class='sub'>%s &middot; %s</p></div>%s</div>%s"
            % (E(mask_account(man.get("target", ""))),
               E(man.get("service_label", "")),
               rescan_form(man.get("service", ""), man.get("target", ""),
                           "Rescan again"),
               run_picker(runs, man, "/compare")))

    if prior is None:
        return head + empty_state(
            "compare", "First run of this target",
            "There is nothing earlier to compare against yet. Rescan this "
            "target and this page shows what was remediated, what is new, and "
            "whether coverage held.",
            "<a class='btn' href='/findings?run=%s'>See this run's findings</a>"
            % E(man["run_id"]))

    old_by = dict(((f["scanner"], f["identity"]), f)
                  for f in load_findings(prior["_dir"]))
    new_by = dict(((f["scanner"], f["identity"]), f)
                  for f in load_findings(man["_dir"]))

    remediated, added, persisting, silent = [], [], 0, []
    for tool, info in diff_runs(prior, man).items():
        if info["silent"]:
            silent.append((tool, info["reason"]))
            continue
        for ident in info["removed"]:
            if (tool, ident) in old_by:
                remediated.append(old_by[(tool, ident)])
        for ident in info["added"]:
            if (tool, ident) in new_by:
                added.append(new_by[(tool, ident)])
        persisting += info["unchanged"]

    def cov_map(m):
        out = {}
        for row in m.get("ledger", []):
            out[row.get("tool")] = (row.get("status"), row.get("coverage"))
        return out
    oc, nc = cov_map(prior), cov_map(man)
    cov_rows = []
    for tool in sorted(set(oc) | set(nc)):
        ostat, ocov = oc.get(tool, (None, None))
        nstat, ncov = nc.get(tool, (None, None))
        oe = ocov.get("examined") if ocov else None
        ne = ncov.get("examined") if ncov else None
        if oe == ne and ostat == nstat:
            continue
        unit = (ncov or ocov or {}).get("unit", "targets")
        if oe is not None and oe > 0 and ne == 0:
            note = ("<span class='removed'>examined %d %s &rarr; 0 — stopped "
                    "finding anything to scan</span>" % (oe, E(unit)))
        elif ne is not None and ne > 0 and oe == 0:
            note = ("<span class='added'>examined 0 &rarr; %d %s — coverage "
                    "restored</span>" % (ne, E(unit)))
        elif oe is not None and ne is not None and oe != ne:
            cls = "added" if ne > oe else "removed"
            note = ("<span class='%s'>examined %d &rarr; %d %s</span>"
                    % (cls, oe, ne, E(unit)))
        else:
            note = ("<span class='muted'>%s &rarr; %s</span>"
                    % (E(str(ostat)), E(str(nstat))))
        cov_rows.append("<tr><td class='mono' style='width:90px'>%s</td>"
                        "<td>%s</td></tr>" % (E(tool), note))

    def rows(xs):
        ordered = sorted(xs, key=lambda f: (SEVERITY_ORDER.index(f["severity"]),
                                            f["scanner"], f["path"] or ""))
        return "".join(
            "<details class='card tight' style='margin:.4rem 0'>"
            "<summary style='cursor:pointer;display:flex;gap:.6rem;"
            "align-items:center;padding:.1rem 0'>%s<b style='flex:1'>%s</b>"
            "<span class='mono muted' style='font-size:.72rem'>%s</span>"
            "<span class='mono muted' style='font-size:.68rem'>%s</span>"
            "</summary><div style='padding:.5rem 0 .2rem'>%s"
            "<div class='mono muted' style='font-size:.66rem;margin-top:.4rem'>"
            "%s</div></div></details>"
            % (sev_pill(f["severity"]), E(f["title"]), E(f["scanner"]),
               E(f["path"] or "/"), _detail_block(f.get("detail") or {}),
               E(f["identity"]))
            for f in ordered)

    span = ("<p class='sub'>%s &rarr; %s</p>"
            % (E(_fmt_run_time(prior["run_id"])),
               E(_fmt_run_time(man["run_id"]))))
    chips = ("<div style='display:flex;gap:.5rem;flex-wrap:wrap;"
             "margin:.4rem 0 1rem'><span class='dchip'>%d remediated</span>"
             "<span class='dchip'>%d new</span>"
             "<span class='dchip'>%d still present</span>"
             "<span class='dchip'>%d coverage change%s</span></div>"
             % (len(remediated), len(added), persisting, len(cov_rows),
                "" if len(cov_rows) == 1 else "s"))

    sections = []
    if remediated:
        sections.append(_cmp_section(
            "Remediated since last run",
            "Present in the previous run, gone now — for scanners that ran in "
            "both runs.", rows(remediated)))
    if added:
        sections.append(_cmp_section(
            "New this run", "Not present in the previous run.", rows(added)))
    if cov_rows:
        sections.append(
            "<div class='card'><h3>Coverage changes</h3>"
            "<p class='muted' style='font-size:.82rem'>What each scanner "
            "examined, previous run &rarr; this run. A drop to zero is a new "
            "gap, not a clean result.</p><table><tbody>%s</tbody></table></div>"
            % "".join(cov_rows))
    if silent:
        srows = "".join("<tr><td class='mono' style='width:90px'>%s</td>"
                        "<td class='silent'>%s</td></tr>" % (E(t), E(r))
                        for t, r in silent)
        sections.append(
            "<div class='card'><h3>Silent scanners</h3>"
            "<p class='muted' style='font-size:.82rem'>These did not run in "
            "both runs, so nothing they cover can be called remediated.</p>"
            "<table><tbody>%s</tbody></table></div>" % srows)
    if not (remediated or added or cov_rows):
        sections.append(empty_state(
            "compare", "No change since last run",
            "Same findings and same coverage as the previous run of this "
            "target — %d finding(s) still present." % persisting))

    trend_svg = risk_trend(same)
    trend_card = ""
    if trend_svg:
        trend_card = (
            "<div class='card'><h3>Findings rating over time</h3>"
            "<p class='muted' style='font-size:.82rem'>Every run of this target, "
            "oldest to newest. The line is a &minus;5 to +5 rating with this "
            "target's median run at 0; higher is cleaner — fewer and less-severe "
            "findings. A hollow point is a run that could not fully scan (a gap "
            "or a zero denominator), so a low score there means <i>did not "
            "look</i>, not <i>clean</i>. Hover a point for its run and rating."
            "</p>" + trend_svg + "</div>")
    return head + span + chips + trend_card + "".join(sections)


def run_picker(runs: List[dict], man: dict, action: str, extra: str = "") -> str:
    """The dropdown that says which run you are looking at and lets you change
    it. Reported from the field as "where is this priority list coming from?" —
    the page named a run in its header and offered no way to see the others or
    to pick one, so the answer was "whichever was newest, chosen for you"."""
    opts = "".join(
        "<option value='%s'%s>%s &middot; %s &middot; %s</option>"
        % (E(m["run_id"]), " selected" if m["run_id"] == man["run_id"] else "",
           E(_short_target(m.get("target", ""))),
           E(m.get("service_label", "")), E(_fmt_run_time(m["run_id"])))
        for m in runs)
    return ("<form method='get' action='%s' class='card tight' "
            "style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;"
            "margin-bottom:1rem'>"
            "<span class='mono muted' style='font-size:.72rem;"
            "letter-spacing:.09em;text-transform:uppercase'>Run</span>"
            "<select name='run' onchange='this.form.submit()'>%s</select>%s"
            "<span class='muted' style='margin-left:auto;font-size:.8rem'>"
            "%d run(s) on record &middot; "
            "<a href='/findings?run=%s'>findings</a> &middot; "
            "<a href='/compare?run=%s'>what changed</a></span></form>"
            % (E(action), opts, extra, len(runs), E(man["run_id"]),
               E(man["run_id"])))


def view_priority(root: str, run_id: Optional[str]) -> str:
    """The shortlist: what to act on first, and why each item is there. A run
    with four hundred findings should leave an operator with an hour a list
    they can finish. The feed status is stated up front, every item carries
    its reason, and everything below the line is counted, never hidden."""
    runs = list_runs(root)
    if not runs:
        return ("<h1>Priority</h1><p class='sub'>What to act on first.</p>"
                + empty_state("priority", "No runs yet",
                              "Run a scan and its shortlist lands here.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))
    man = (next((m for m in runs if m["run_id"] == run_id), None)
           if run_id else runs[0])
    if man is None:
        return ("<h1>No such run</h1>" + empty_state(
            "priority", "That run id is not on record",
            "The id in the address matches no run in this evidence root."))
    findings = load_findings(man["_dir"])
    feeds = load_feeds(root)
    ranked = rank_run(findings, feeds)

    head = ("<h1>Priority</h1><p class='sub'>What to act on first in one run, "
            "and why each item is on the list. This is one run's shortlist; "
            "<a href='/intel'>Intel</a> is the same question across every "
            "target.</p>%s"
            % run_picker(runs, man, "/priority"))
    ages = dict((n, (a, d)) for n, a, d in feed_ages(root))
    if not ranked["feeds_present"]:
        feed_line = ("<div class='card tight' style='border-left:4px solid "
                     "var(--gap)'><b>Exploitability feeds not fetched.</b> "
                     "<span class='muted'>Nothing below is ranked by whether it "
                     "is exploited; the tiers fall back to severity and each "
                     "item says so. Run <span class='mono'>squawk.py --feeds"
                     "</span> to fetch CISA KEV and EPSS.</span></div>")
    else:
        stale = [n for n, (a, _d) in ages.items()
                 if a is not None and a > FEED_STALE_DAYS]
        age = (ages.get("kev") or (None, ""))[0]
        feed_line = ("<div class='card tight' style='border-left:4px solid %s'>"
                     "<b>Feeds: CISA KEV %d, EPSS %d entries, fetched %s day(s) "
                     "ago.</b> <span class='muted'>%s</span></div>"
                     % ("var(--gap)" if stale else "var(--ok)",
                        len(feeds["kev"]), len(feeds["epss"]),
                        age if age is not None else 0,
                        "STALE: exploitation observed since the fetch is not "
                        "reflected here; run --feeds." if stale else
                        "Reachability is not assessed: no scanner in this run "
                        "reports whether a vulnerable package is on a live path."))

    def rows(items):
        out = []
        for g in items:
            n = len(g["items"])
            paths = sorted({f.get("path") or "/" for f in g["items"]})[:4]
            out.append(
                "<details class='card tight' style='margin:.4rem 0'>"
                "<summary style='cursor:pointer;display:flex;gap:.6rem;"
                "align-items:center;padding:.1rem 0'>%s<b style='flex:1'>%s</b>"
                "<span class='mono muted' style='font-size:.72rem'>%s &middot; %s"
                "</span><span class='dchip'>%d instance%s</span></summary>"
                "<div style='padding:.5rem 0 .2rem'>"
                "<div class='mono muted' style='font-size:.66rem;letter-spacing:"
                ".09em;text-transform:uppercase'>Why it is here</div>"
                "<div style='font-size:.85rem;margin:.2rem 0 .5rem'>%s</div>%s"
                "<div class='mono muted' style='font-size:.7rem;margin-top:.4rem'>"
                "%s</div></div></details>"
                % (sev_pill(g["sev"]), E(g["title"]), E(g["scanner"]),
                   E(g["rule"]), n, "" if n == 1 else "s", _why(g["why"]),
                   _detail_block(g["detail"]), E(" · ".join(paths))))
        return "".join(out)

    sections = []
    shortlisted = 0
    for key, title, desc in PRIORITY_TIERS:
        items = ranked["tiers"][key]
        if not items:
            continue
        shortlisted += sum(len(g["items"]) for g in items)
        sections.append("<div class='card'><h3>%s <span class='dchip'>%d</span>"
                        "</h3><p class='muted' style='font-size:.82rem'>%s</p>%s"
                        "</div>" % (E(title), len(items), E(desc), rows(items)))
    below_n = sum(ranked["below"].values())
    below = " &middot; ".join("%d %s" % (ranked["below"][s], s)
                              for s in SEVERITY_ORDER if ranked["below"].get(s))
    tail = ("<div class='card tight'><b>Below the shortlist: %d finding(s) in "
            "%d group(s).</b> <span class='muted'>%s. They are not hidden; open "
            "<a href='/findings?run=%s'>Findings</a> to see all %d.</span></div>"
            % (below_n, ranked["groups"] - sum(len(v) for v in ranked["tiers"].values()),
               E(below) if below else "nothing", E(man["run_id"]), len(findings)))
    if not sections:
        sections.append(empty_state(
            "priority", "Nothing on the shortlist",
            "No finding in this run is exploited now, likely to be, or of "
            "critical or high severity. %d finding(s) sit below the line."
            % below_n))
    summary = ("<p class='sub'>%d of %d finding(s) shortlisted%s.</p>"
               % (shortlisted, len(findings),
                  " across %d tier(s)" % len(sections) if shortlisted
                  else "; no tier has an entry"))
    return head + feed_line + summary + "".join(sections) + tail


def _intel_chip(row: dict) -> str:
    """One source's state, age and size. A source that has not been fetched is
    shown saying so, never left out: an absent row reads as a source nobody
    needed rather than one nobody has."""
    if row["state"] != "ok":
        return ("<span class='attn-i gap'>%s &middot; not fetched</span>"
                % E(row["source"]))
    bits = []
    if row.get("entries"):
        bits.append("%d entries" % row["entries"])
    days = row.get("age_days")
    stale = days is not None and days >= FEED_STALE_DAYS
    if days is not None:
        bits.append("%d day(s) old" % days)
    if row.get("sha256"):
        bits.append("sha256 %s" % str(row["sha256"])[:12])
    return ("<span class='attn-i%s' title='%s'>%s &middot; %s</span>"
            % (" stale" if stale else "", E(str(row.get("url", ""))),
               E(row["source"]), E(" · ".join(bits) or "ok")))


def _cve_rows(cves: Dict[str, List[dict]], keep, feeds: dict, root: str,
              order) -> Tuple[str, int]:
    """A table of CVEs across the estate: where each one is, how bad, and why
    it is on this list. Returns (html, count)."""
    rows = []
    chosen = [c for c in cves if keep(c)]
    for cve in sorted(chosen, key=order):
        finds = cves[cve]
        targets = sorted({str(f.get("_target", "")) for f in finds})
        worst = min((f["severity"] for f in finds),
                    key=lambda s: SEVERITY_ORDER.index(s)
                    if s in SEVERITY_ORDER else len(SEVERITY_ORDER))
        kev = feeds.get("kev", {}).get(cve) or {}
        ep = feeds.get("epss", {}).get(cve)
        why = []
        if kev:
            why.append("KEV %s" % E(str(kev.get("added", "?"))))
            if kev.get("ransomware"):
                why.append("<b>ransomware</b>")
        if ep:
            why.append("EPSS %.2f (%dth)" % (ep[0], int(ep[1] * 100)))
        detail = load_intel(root, cve)
        summary = str((detail or {}).get("summary", ""))[:110]
        rows.append(
            "<tr><td class='mono' style='white-space:nowrap'>"
            "<a href='/intel?cve=%s'>%s</a></td>"
            "<td>%s</td><td style='font-size:.8rem'>%s</td>"
            "<td class='muted' style='font-size:.78rem'>%s</td>"
            "<td class='muted' style='font-size:.75rem'>%s</td></tr>"
            % (E(cve), E(cve), sev_pill(worst), " &middot; ".join(why),
               E(summary) if detail else
               "<span class='silent'>detail not fetched</span>",
               E(", ".join(_short_target(t) for t in targets[:2]))
               + (" and %d more" % (len(targets) - 2) if len(targets) > 2 else "")))
    if not rows:
        return "", 0
    return ("<div style='overflow-x:auto'><table><thead><tr><th>CVE</th>"
            "<th>Worst severity</th><th>Why it is here</th><th>What it is</th>"
            "<th>Where</th></tr></thead><tbody>%s</tbody></table></div>"
            % "".join(rows), len(rows))


def view_intel(root: str, cve: Optional[str] = None) -> str:
    """Exploited now, likely soon, and what any one of them actually is.

    Every list on this page states what it is out of, every source states when
    it was fetched, and a source that has not been fetched says so rather than
    contributing a zero. Nothing here reaches the network: fetching is
    `squawk feeds --intel`, which is explicit, logged and recorded."""
    feeds = load_feeds(root)
    prov = intel_provenance(root)
    strip = "<div class='attn'>%s</div>" % "".join(_intel_chip(r) for r in prov)

    live, vanished, _by_target = estate_runs(root)
    cves = estate_cves(list(live.values()), load_findings) if live else {}
    # A CVE lookup does not depend on having scanned anything. Bailing out here
    # meant a link to /intel?cve=X on a fresh evidence root answered "no live
    # targets yet" instead of what the CVE is, which is the one thing the page
    # can always say.
    if cve:
        return _intel_detail(root, cve.upper(), cves, feeds, strip)
    if not live:
        return ("<h1>Threat intel</h1><p class='sub'>What is being exploited, "
                "out of what you actually run.</p>" + strip
                + empty_state("priority", "No live targets yet",
                              "Scan something and its CVEs are cross-referenced "
                              "here against CISA KEV and FIRST EPSS. "
                              "<a href='/intel?scope=feed'>What is being "
                              "exploited at large</a> works without one.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))

    n_targets = len(live)
    cached = sum(1 for c in cves if load_intel(root, c))
    head = ("<h1>Threat intel</h1>"
            "<p class='sub'>Across the newest run of %d live target%s"
            "%s. %d distinct CVE(s); detail cached for %d of them. "
            "<a href='/intel?scope=feed'>What is being exploited at large "
            "&rarr;</a></p>%s"
            % (n_targets, "" if n_targets == 1 else "s",
               "; %d vanished target(s) are not counted" % len(vanished)
               if vanished else "", len(cves), cached, strip))

    if not feeds.get("present"):
        return head + empty_state(
            "priority", "The exploitability feeds have not been fetched",
            "Without CISA KEV and FIRST EPSS, nothing here can say whether a "
            "CVE is being exploited. That is unknown, which is not the same as "
            "none, so no count is shown. Run: squawk feeds")

    kev_html, kev_n = _cve_rows(
        cves, lambda c: c in feeds["kev"], feeds, root,
        order=lambda c: (feeds["kev"].get(c, {}).get("added", ""), c))
    hot_html, hot_n = _cve_rows(
        cves, lambda c: (c not in feeds["kev"]
                         and (feeds["epss"].get(c) or (0, 0))[0] >= EPSS_HOT),
        feeds, root,
        order=lambda c: (-(feeds["epss"].get(c) or (0, 0))[0], c))
    rest = len(cves) - kev_n - hot_n

    body = [head]
    body.append(_cmp_section(
        "Exploited now", "In CISA KEV, which means exploitation has been "
        "observed in the wild, not predicted. %d of %d CVE(s) in the estate."
        % (kev_n, len(cves)),
        kev_html or "<p class='muted' style='font-size:.85rem'>None of the "
                    "estate's CVEs is in KEV. The feed is %s.</p>"
                    % (("%d day(s) old" % (prov[0].get("age_days") or 0))
                       if prov[0].get("age_days") is not None else "present")))
    body.append(_cmp_section(
        "Likely to be exploited soon",
        "EPSS at or above %.2f, which is a probability of exploitation in the "
        "next thirty days, not a severity. %d of %d CVE(s), excluding those "
        "already in KEV above." % (EPSS_HOT, hot_n, len(cves)),
        hot_html or "<p class='muted' style='font-size:.85rem'>No CVE outside "
                    "KEV scores at or above %.2f.</p>" % EPSS_HOT))
    body.append(
        "<div class='card tight'><p class='muted' style='font-size:.85rem;"
        "margin:0'><b>%d</b> further CVE(s) are in the estate and on neither "
        "list. They are counted here rather than hidden: not exploited today "
        "is a reading, and it can change with the next feed fetch. "
        "Reachability is not assessed anywhere on this page.</p></div>" % rest)
    return "".join(body)


def _mine(cve: str, cves: Dict[str, List[dict]]) -> str:
    """Whether a CVE from the wider feed is in the estate.

    "Not in your estate" is a statement about what you have scanned, never
    about what you run. The distinction is the whole reason this column reads
    "not in what you have scanned" rather than "not affected"."""
    if cve in cves:
        n = len(cves[cve])
        return ("<a href='/intel?cve=%s'><b>yours</b> &middot; %d instance%s</a>"
                % (E(cve), n, "" if n == 1 else "s"))
    return "<span class='muted'>not in what you have scanned</span>"


def _cve_vendor(cve: str, feeds: dict) -> str:
    """Vendor and product for a CVE, where anything on disk knows it. KEV names
    them; EPSS does not, so a CVE outside the catalogue has no vendor here
    until its detail is fetched."""
    entry = (feeds.get("kev") or {}).get(cve) or {}
    both = ("%s %s" % (entry.get("vendor", ""), entry.get("product", ""))).strip()
    return both or "—"


def _cve_what(root: str, cve: str, feeds: dict) -> str:
    """One line saying what a CVE is: the catalogue's own name for it, else the
    fetched summary, else a statement that it has not been fetched. Never a
    blank, because a blank in this column reads as "nothing to say" when the
    truth is "nobody asked"."""
    entry = (feeds.get("kev") or {}).get(cve) or {}
    if entry.get("name"):
        return str(entry["name"])[:90]
    detail = load_intel(root, cve)
    if detail and detail.get("summary"):
        return str(detail["summary"])[:90]
    return "not fetched — squawk feeds --intel"


def _feed_table(rows: List[dict], cves: Dict[str, List[dict]]) -> str:
    return ("<div style='overflow-x:auto'><table><thead><tr><th>CVE</th>"
            "<th>Vendor and product</th><th>What it is</th><th>Added</th>"
            "<th>In your estate?</th></tr></thead><tbody>%s</tbody></table></div>"
            % "".join(
                "<tr><td class='mono' style='white-space:nowrap'>"
                "<a href='/intel?cve=%s'>%s</a>%s</td>"
                "<td style='font-size:.82rem'>%s</td>"
                "<td style='font-size:.8rem'>%s</td>"
                "<td class='muted' style='white-space:nowrap;font-size:.78rem'>%s</td>"
                "<td style='font-size:.8rem'>%s</td></tr>"
                % (E(str(r.get("cve", ""))), E(str(r.get("cve", ""))),
                   " <span class='regress'>ransomware</span>"
                   if r.get("ransomware") else "",
                   E("%s %s" % (r.get("vendor", ""), r.get("product", ""))).strip(),
                   E(str(r.get("name") or r.get("summary", ""))[:90]),
                   E(str(r.get("added", ""))),
                   _mine(str(r.get("cve", "")), cves))
                for r in rows))


def view_intel_feed(root: str, days: int = 30) -> str:
    """The other half of intelligence: what is being exploited in the world,
    whether or not you run it.

    The catalogue is already on disk after `squawk feeds` — about 1,700 KEV
    entries and a third of a million EPSS scores — and until now the tool only
    ever asked it about the handful of CVEs in the estate. Everything here is
    that data read straight, with one column added that the raw feed cannot
    give you: whether it is in what you have scanned."""
    feeds = load_feeds(root)
    prov = intel_provenance(root)
    strip = "<div class='attn'>%s</div>" % "".join(_intel_chip(r) for r in prov)
    head = ("<h1>What is being exploited</h1>"
            "<p class='sub'>The catalogue at large, not filtered to your estate. "
            "<a href='/intel'>Your estate &rarr;</a></p>%s" % strip)
    if not feeds.get("present"):
        return head + empty_state(
            "priority", "The feeds have not been fetched",
            "CISA KEV and FIRST EPSS are the source for everything on this "
            "page. Nothing is shown rather than a zero, because a zero here "
            "would be a claim about the world. Run: squawk feeds")

    live, _vanished, _by = estate_runs(root)
    cves = estate_cves(list(live.values()), load_findings) if live else {}
    recent = kev_recent(feeds, days)
    mine_recent = sum(1 for r in recent if r["cve"] in cves)
    ransom = kev_ransomware(feeds)
    hot = epss_top(feeds)
    n_kev, n_epss = len(feeds["kev"]), len(feeds["epss"])

    caveat = ("<div class='banner'><b>The last column is about coverage, not "
              "exposure.</b> <span class='muted'>It says whether a CVE appears "
              "in the newest run of a target you have scanned. It cannot say "
              "whether you run the affected product somewhere this has never "
              "been pointed at, and most estates have more of those than "
              "not.</span></div>")

    body = [head, caveat]
    body.append(_cmp_section(
        "Added to KEV in the last %d days" % days,
        "%d of %d catalogue entries. %s"
        % (len(recent), n_kev,
           "%d of them %s in your estate."
           % (mine_recent, "is" if mine_recent == 1 else "are") if mine_recent
           else "None of them is in what you have scanned."),
        _feed_table(recent, cves) if recent else
        "<p class='muted' style='font-size:.85rem'>Nothing was added in that "
        "window. The feed is %s.</p>"
        % (("%d day(s) old" % prov[0]["age_days"])
           if prov[0].get("age_days") is not None else "present")))

    body.append(_cmp_section(
        "Flagged for use in ransomware",
        "%d of %d catalogue entries carry the flag; the %d most recent are "
        "shown. This is CISA's own marking, not an inference."
        % (sum(1 for e in feeds["kev"].values() if e.get("ransomware")),
           n_kev, len(ransom)),
        _feed_table(ransom, cves)))

    body.append(_cmp_section(
        "Highest EPSS scores overall",
        "The %d highest of %d scored CVEs. EPSS is a probability of "
        "exploitation in the next thirty days, not a severity, and a high "
        "score on something you do not run is not your problem."
        % (len(hot), n_epss),
        "<div style='overflow-x:auto'><table><thead><tr><th>CVE</th>"
        "<th>Vendor and product</th><th>What it is</th><th>EPSS</th>"
        "<th>In your estate?</th></tr></thead><tbody>%s</tbody></table></div>"
        % "".join(
            "<tr><td class='mono' style='white-space:nowrap'>"
            "<a href='/intel?cve=%s'>%s</a>%s</td>"
            "<td style='font-size:.82rem'>%s</td>"
            "<td style='font-size:.8rem'>%s</td>"
            "<td style='white-space:nowrap'>%.4f <span class='muted' "
            "style='font-size:.78rem'>%dth</span></td>"
            "<td style='font-size:.8rem'>%s</td></tr>"
            % (E(cve), E(cve),
               " <span class='regress'>ransomware</span>"
               if (feeds["kev"].get(cve) or {}).get("ransomware") else
               (" <span class='muted' style='font-size:.72rem'>KEV</span>"
                if cve in feeds["kev"] else ""),
               E(_cve_vendor(cve, feeds)), E(_cve_what(root, cve, feeds)),
               score, int(pct * 100), _mine(cve, cves))
            for cve, score, pct in hot)))

    vendors = kev_by_vendor(feeds)
    body.append(
        "<div class='card'><h3>Where exploitation is concentrated</h3>"
        "<p class='muted' style='font-size:.82rem'>KEV entries by vendor, "
        "across the whole catalogue. A crude shape, and useful mainly for "
        "recognising a vendor you run and have never pointed this at.</p>"
        "<div style='display:flex;gap:.4rem;flex-wrap:wrap'>%s</div></div>"
        % "".join("<span class='dchip'>%s &middot; %d</span>" % (E(v), n)
                  for v, n in vendors))
    return "".join(body)


# The authoritative record for a CVE, derived from the id alone. These need no
# fetch and are correct whether or not anything has been cached, which is the
# point: a CVE page with nothing fetched used to be a dead end that told you to
# run a command. Squawk does not follow these; the browser does, in a new tab.
CVE_SOURCES = (
    ("NVD", "https://nvd.nist.gov/vuln/detail/%s"),
    ("MITRE CVE", "https://www.cve.org/CVERecord?id=%s"),
    ("CISA KEV catalogue", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                           "?search_api_fulltext=%s"),
    ("OSV", "https://osv.dev/vulnerability/%s"),
)


def _cve_source_links(cve: str) -> str:
    """Out to the record itself. Every link opens in a new tab so the page a
    reader is working through is not replaced by a vendor site."""
    return ("<div class='card'><h3>Look it up at the source</h3>"
            "<p class='muted' style='font-size:.82rem'>The authoritative record, "
            "wherever the detail below came from or did not. Squawk does not "
            "follow these; your browser does, in a new tab.</p>"
            "<div style='display:flex;gap:.5rem;flex-wrap:wrap'>%s</div></div>"
            % "".join(
                "<a class='btn ghost' href='%s' target='_blank' "
                "rel='noopener noreferrer'>%s &#8599;</a>"
                % (E(url % cve), E(name)) for name, url in CVE_SOURCES))


def _intel_detail(root: str, cve: str, cves: Dict[str, List[dict]],
                  feeds: dict, strip: str) -> str:
    """One CVE: what it is, how it scores in words, where it is in the estate,
    and which source said each thing and when."""
    head = ("<h1>%s</h1><p class='sub'><a href='/intel'>&larr; all intel</a> "
            "&middot; <a href='/intel?scope=feed'>what is being exploited</a>"
            "</p>%s" % (E(cve), strip))
    finds = cves.get(cve) or []
    detail = load_intel(root, cve)
    cards = [_cve_source_links(cve)]

    kev = feeds.get("kev", {}).get(cve) or {}
    ep = feeds.get("epss", {}).get(cve)
    ex_rows = []
    if not feeds.get("present"):
        ex_rows.append("<tr><td colspan='2' class='silent'>KEV and EPSS have not "
                       "been fetched, so exploitation is unknown, not absent. "
                       "Run: squawk feeds</td></tr>")
    else:
        ex_rows.append("<tr><td style='width:130px'>CISA KEV</td><td>%s</td></tr>"
                       % ("added %s%s" % (E(str(kev.get("added", "?"))),
                                          ", used in ransomware"
                                          if kev.get("ransomware") else "")
                          if kev else "not listed"))
        ex_rows.append("<tr><td>FIRST EPSS</td><td>%s</td></tr>"
                       % ("%.4f, %dth percentile" % (ep[0], int(ep[1] * 100))
                          if ep else "no score published"))
    cards.append("<div class='card'><h3>Exploitation</h3><table><tbody>%s"
                 "</tbody></table></div>" % "".join(ex_rows))

    if detail is None:
        cards.append(
            "<div class='card'><h3>What it is</h3>"
            "<p class='muted' style='font-size:.85rem'>Not fetched. The summary, "
            "the CVSS vector, the weakness class and the references come from OSV "
            "and NVD, and neither has been fetched for this CVE. That is unknown, "
            "not absent. Run: <span class='mono'>squawk feeds --intel</span></p>"
            "</div>")
    else:
        cvss = detail.get("cvss") or {}
        words = cvss_words(str(cvss.get("vector", "")))
        rows = []
        if detail.get("summary"):
            rows.append("<tr><td style='width:130px'>Summary</td><td>%s</td></tr>"
                        % E(str(detail["summary"])))
        if cvss.get("vector"):
            rows.append("<tr><td>CVSS</td><td><b>%s</b> %s "
                        "<span class='mono muted' style='font-size:.72rem'>%s</span>"
                        "<div class='muted' style='font-size:.82rem;margin-top:.25rem'>"
                        "%s</div></td></tr>"
                        % (E(str(cvss.get("score", "?"))),
                           E(str(cvss.get("severity", ""))), E(str(cvss["vector"])),
                           E("; ".join(words)) if words
                           else "<span class='silent'>the vector did not parse "
                                "into words</span>"))
        if detail.get("cwe"):
            rows.append("<tr><td>Weakness</td><td class='mono'>%s</td></tr>"
                        % E(", ".join(str(c) for c in detail["cwe"])))
        if detail.get("aliases"):
            rows.append("<tr><td>Also known as</td><td class='mono' "
                        "style='font-size:.78rem'>%s</td></tr>"
                        % E(", ".join(str(a) for a in detail["aliases"][:8])))
        if detail.get("published"):
            rows.append("<tr><td>Published</td><td>%s</td></tr>"
                        % E(str(detail["published"])))
        cards.append("<div class='card'><h3>What it is</h3><table><tbody>%s"
                     "</tbody></table></div>" % "".join(rows))

        # Exploit-typed references first: a reader chasing this wants the proof
        # of exploitability before the vendor advisory.
        rank = {"EXPLOIT": 0, "ADVISORY": 1, "REPORT": 2, "FIX": 3}
        refs = sorted(detail.get("references") or [],
                      key=lambda r: (rank.get(str(r.get("type", "")).upper(), 9),
                                     str(r.get("url", ""))))
        if refs:
            cards.append(
                "<div class='card'><h3>References</h3>"
                "<p class='muted' style='font-size:.82rem'>Exploit references "
                "first. These are links the source published; Squawk does not "
                "visit them.</p><table><tbody>%s</tbody></table></div>"
                % "".join("<tr><td class='mono' style='width:90px;font-size:.72rem'>"
                          "%s</td><td class='mono' style='font-size:.74rem'>%s</td>"
                          "</tr>" % (E(str(r.get("type", ""))),
                                     E(str(r.get("url", ""))))
                          for r in refs[:25]))

        src_rows = []
        for name, rec in sorted((detail.get("sources") or {}).items()):
            if rec.get("error"):
                src_rows.append("<tr><td class='mono'>%s</td><td class='silent'>"
                                "fetch failed: %s</td></tr>"
                                % (E(name), E(str(rec["error"])[:120])))
            else:
                src_rows.append("<tr><td class='mono'>%s</td>"
                                "<td class='mono muted' style='font-size:.72rem'>%s"
                                "<br>%d bytes &middot; sha256 %s</td></tr>"
                                % (E(name), E(str(rec.get("url", ""))),
                                   rec.get("bytes", 0),
                                   E(str(rec.get("sha256", ""))[:16])))
        cards.append("<div class='card'><h3>Where this came from</h3>"
                     "<p class='muted' style='font-size:.82rem'>Fetched %s. "
                     "Re-fetch and these hashes change only when the source "
                     "did.</p><table><tbody>%s</tbody></table></div>"
                     % (E(_fmt_run_time(str(detail.get("fetched_at", "")))),
                        "".join(src_rows)))

    if finds:
        find_rows = "".join(
            "<tr><td>%s</td><td class='mono' style='font-size:.75rem'>%s</td>"
            "<td class='mono' style='font-size:.72rem'>%s</td>"
            "<td><a href='/findings?run=%s'>open &rarr;</a></td></tr>"
            % (sev_pill(f["severity"]),
               E(_short_target(str(f.get("_target", "")))),
               E(str(f.get("path", ""))[:60]), E(str(f.get("_run", ""))))
            for f in sorted(finds,
                            key=lambda f: SEVERITY_ORDER.index(f["severity"])
                            if f["severity"] in SEVERITY_ORDER else 9)[:50])
        cards.append("<div class='card'><h3>Where it is, in your estate</h3>"
                     "<p class='muted' style='font-size:.82rem'>%d instance(s) "
                     "across the newest run of each live target.%s</p>"
                     "<table><tbody>%s</tbody></table></div>"
                     % (len(finds),
                        " Showing the first 50." if len(finds) > 50 else "", find_rows))
    else:
        cards.append(empty_state(
            "priority", "Not in the estate",
            "No live target's newest run carries %s. It may have been "
            "remediated, or it may never have been here." % cve))
    return head + "".join(cards)



def _chip_link(label: str, base: dict, drop: str) -> str:
    """An active filter, shown with the way to remove it. A filter you cannot
    see is a filter that silently changes every number under it."""
    rest = {k: v for k, v in base.items() if k != drop and v}
    qs = "&amp;".join("%s=%s" % (E(k), E(str(v))) for k, v in sorted(rest.items()))
    return ("<a class='dchip' href='/estate%s' title='Remove this filter'>%s "
            "&times;</a>" % ("?" + qs if qs else "", E(label)))


def view_estate(root: str, params: Dict[str, str]) -> str:
    """Every open finding across every live target, grouped the way one run's
    Findings page groups, with what each number is out of.

    Until this, every findings view was one run, so the question a security
    engineer actually asks — where is this rule failing across everything I
    look after — had no page, and the Overview's own totals had nowhere to link
    to show their proof."""
    live, vanished, _by = estate_runs(root)
    if not live:
        return ("<h1>Estate</h1><p class='sub'>Every finding across every "
                "target you look after.</p>"
                + empty_state("findings", "No live targets yet",
                              "Scan something and it appears here beside "
                              "everything else you have scanned.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))

    rows = estate_rows(root, live)
    q = {k: str(params.get(k, "") or "").strip() for k in
         ("sev", "scanner", "target", "status", "q", "sort")}
    try:
        page_no = int(params.get("page", "1") or 1)
    except ValueError:
        page_no = 1
    res = apply_estate_query(rows, sev=q["sev"] or None, scanner=q["scanner"] or None,
                             target=q["target"] or None, status=q["status"] or None,
                             q=q["q"] or None, sort=q["sort"] or None,
                             page=max(1, page_no))

    stale_n = sum(1 for m in live.values() if rel_time(m["run_id"])[1])
    gap_n = sum(1 for m in live.values() if _run_incomplete(m))
    sub = ("<p class='sub'>%d live target%s &middot; %d scanned in the last %d "
           "days &middot; %d with a coverage gap or an aborted newest run, "
           "counted and flagged &middot; %d vanished, not counted. Grouped the "
           "way one run's <a href='/findings'>Findings</a> page groups, so the "
           "two never disagree about what one advisory is.</p>"
           % (len(live), "" if len(live) == 1 else "s", len(live) - stale_n,
              STALE_SCAN_DAYS, gap_n, len(vanished)))

    scanners = sorted({r["scanner"] for r in rows})
    targets = sorted({t for r in rows for t in r["targets"]})

    def sel(name, current, options, label):
        opts = "".join("<option value='%s'%s>%s</option>"
                       % (E(o), " selected" if o == current else "",
                          E(_short_target(o) if name == "target" and o else (o or label)))
                       for o in ["", *list(options)])
        return ("<select name='%s' onchange='this.form.submit()'>%s</select>"
                % (name, opts))

    controls = (
        "<form method='get' action='/estate' class='card tight' "
        "style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;"
        "margin-bottom:.6rem'>"
        "<input type='search' name='q' value='%s' placeholder='search title, "
        "rule, identity or path' style='min-width:260px'>%s%s%s%s%s"
        "<button class='btn ghost' type='submit'>Search</button>"
        "<span class='muted' style='margin-left:auto;font-size:.82rem'>"
        "%d row(s) &middot; %d instance(s) &middot; %d target(s)</span></form>"
        % (E(q["q"]), sel("sev", q["sev"], [*SEVERITY_ORDER, "critical,high"],
                          "All severities"),
           sel("scanner", q["scanner"], scanners, "All scanners"),
           sel("target", q["target"], targets, "All targets"),
           sel("status", q["status"], ESTATE_STATUSES, "Any status"),
           sel("sort", q["sort"], ESTATE_SORTS, "Sort: severity"),
           res["total"], res["instances"], res["targets"]))

    active = [_chip_link("%s: %s" % (k, v), q, k)
              for k, v in sorted(q.items()) if v and k != "sort"]
    chips = ("<div style='display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.6rem'>"
             "%s</div>" % "".join(active)) if active else ""

    if not res["rows"]:
        why = ("%d row(s) across the estate; the filters above exclude them all."
               % len(rows))
        if res.get("unknown_filters"):
            # Say which value could never match, or "0 rows" under a chip
            # reads as "nothing critical" rather than "you misspelt it".
            why = ("%s &mdash; nothing can match it, so 0 rows here means the "
                   "value, not the estate." % E("; ".join(res["unknown_filters"])))
        return ("<h1>Estate</h1>" + sub + controls + chips
                + empty_state("findings", "Nothing matches", why))

    blocks = []
    for r in res["rows"]:
        tgt_rows = "".join(
            "<tr><td><b>%s</b><div class='mono muted' style='font-size:.7rem'>%s"
            "</div></td><td>%d instance%s</td><td>%s</td>"
            "<td><a href='/findings?run=%s'>findings &rarr;</a> &middot; "
            "<a href='/triage?run=%s'>triage &rarr;</a></td></tr>"
            % (E(_short_target(t)), E(t), d["instances"],
               "" if d["instances"] == 1 else "s",
               ("<span class='regress'>%d regressed</span>" % d["regressed"])
               if d["regressed"] else
               ("<span class='attn-i gap'>gap</span>" if d["incomplete"]
                else "<span class='muted'>open</span>"),
               E(d["run_id"]), E(d["run_id"]))
            for t, d in sorted(r["targets"].items()))
        dec = r["decision"]
        marks = ""
        if r["regressed"]:
            marks += "<span class='dchip regress'>%d regressed</span>" % r["regressed"]
        if dec["status"] != "open":
            label = (dec["status"] if dec["status"] != "partial"
                     else "%s %d/%d" % (dec["latest"], dec["decided"], dec["total"]))
            marks += ("<span class='dchip dec'>%s &middot; %s</span>"
                      % (E(label), E(dec["who"])))
        seen = ""
        if r["first_seen"]:
            seen = ("<div class='muted' style='font-size:.78rem;margin:.3rem 0'>"
                    "First seen %s &middot; last %s</div>"
                    % (E(_fmt_run_time(r["first_seen"])),
                       E(_fmt_run_time(r["last_seen"] or r["first_seen"]))))
        blocks.append(
            "<details class='card tight' style='margin-bottom:.6rem'>"
            "<summary style='cursor:pointer;display:flex;gap:.7rem;"
            "align-items:center;padding:.15rem 0'>%s<b style='flex:1'>%s</b>"
            "<span class='mono muted' style='font-size:.75rem'>%s &middot; %s</span>"
            "%s<span class='dchip'>%d target%s</span>"
            "<span class='dchip'>%d instance%s</span></summary>"
            "<div style='padding:.6rem 0 .2rem'>%s"
            "<div style='overflow-x:auto'><table><thead><tr><th>Target</th>"
            "<th>Instances</th><th>State</th><th></th></tr></thead>"
            "<tbody>%s</tbody></table></div></div></details>"
            % (sev_pill(r["severity"]), E(r["title"]), E(r["scanner"]), E(r["rule"]),
               marks, len(r["targets"]), "" if len(r["targets"]) == 1 else "s",
               r["instances"], "" if r["instances"] == 1 else "s", seen, tgt_rows))

    def page_link(n, label):
        rest = {k: v for k, v in q.items() if v}
        rest["page"] = n
        return ("<a class='btn ghost' href='/estate?%s'>%s</a>"
                % ("&amp;".join("%s=%s" % (E(k), E(str(v)))
                                for k, v in sorted(rest.items())), E(label)))

    nav = ""
    if res["pages"] > 1:
        bits = []
        if res["page"] > 1:
            bits.append(page_link(res["page"] - 1, "← previous"))
        if res["page"] < res["pages"]:
            bits.append(page_link(res["page"] + 1, "next →"))
        nav = ("<div style='display:flex;gap:.5rem;align-items:center;"
               "margin-top:.8rem'>%s</div>" % "".join(bits))

    count = ("<p class='sub'>Showing %d&ndash;%d of %d row(s), page %d of %d. "
             "%d instance(s) across %d target(s). Sorted by %s.%s%s</p>"
             % (res["first"], res["last"], res["total"], res["page"], res["pages"],
                res["instances"], res["targets"], E(res["sort"]),
                " The sort you asked for is not one this page knows, so it fell "
                "back to severity." if res["sort_fell_back"] else "",
                " There is no page %d, so this is the last one."
                % page_no if res["clamped"] else ""))
    if res.get("unknown_filters"):
        count += ("<p class='sub' style='color:var(--gap)'>&#9650; %s &mdash; nothing "
                  "can match it, so 0 rows here means the value, not the estate.</p>"
                  % E("; ".join(res["unknown_filters"])))
    return ("<h1>Estate</h1>" + sub + controls + chips + count
            + "".join(blocks) + nav)


def _cloud_found(man: dict) -> str:
    """What a cloud read with no findings actually did.

    "none returned" is right for a Security Hub read that came back empty, and
    wrong for an inventory that examined three hundred resources and joined no
    toxic combination — the second is a real negative and printing it as
    emptiness makes a run that worked look like a run that did not."""
    if man.get("service") == "cloudinventory":
        return ("<span class='muted'>no combination fired</span>")
    return "<span class='muted'>none returned</span>"


def _cloud_doubt(man: dict) -> str:
    """What a cloud run could NOT answer, as a cell of its own.

    A severity row on its own says "here is what we found", and a reader takes
    the absence of a pill as the absence of a problem. For a cloud read that is
    exactly wrong: a region whose security groups were denied produces no pill
    and no finding, and the run looks cleaner than the one that could see
    everything. So the unknowns get a column, next to the findings, at the same
    size (I1)."""
    unknown = [c for c in (man.get("correlations") or [])
               if isinstance(c, dict) and c.get("state") == "unknown"]
    if not unknown:
        return "<span class='muted'>&mdash;</span>"
    return ("<span class='pill' style='background:var(--gap-bg);color:var(--gap)' "
            "title='%s'>%d question(s) unanswered</span>"
            % (E(" · ".join(c.get("why", "") for c in unknown[:4])), len(unknown)))


STATE_COLOURS = {"on": "var(--ok)", "off": "var(--high)",
                 "partial": "var(--gap)", "unknown": "var(--muted)"}


def _state_pill(state: str) -> str:
    colour = STATE_COLOURS.get(state, "var(--muted)")
    return ("<span class='pill' style='border:1px solid %s;color:%s;"
            "font-size:.68rem;letter-spacing:.04em;text-transform:uppercase'>"
            "%s</span>" % (colour, colour, E(state)))


def _named_regions(regions: "List[str]", cap: int = 4) -> str:
    """A region list a person reads, capped — the full list is one click away."""
    names = [as_text(r) for r in regions]
    if len(names) <= cap:
        return ", ".join(names)
    return "%s and %d more" % (", ".join(names[:cap]), len(names) - cap)


def _service_tile(row: dict) -> str:
    """One service: is it watching, where is it not, and what does it do.

    The state word is the headline because it is the question. The region
    count sits under it because "on" and "on in 1 of 17 regions" are different
    answers and only one of them is this account's."""
    colour = STATE_COLOURS.get(row["state"], "var(--muted)")
    # The region list is capped at four with "and N more", so on an account
    # with seventeen regions the ones a reader most wants are the ones the tile
    # cannot show. Each phrase links to the full list, which is what the
    # services_on / services_off / services_unknown views hold -- three drill
    # keys that existed and that nothing on the page linked to.
    bits = []
    if row["off"]:
        bits.append(drill_link("services_off",
                               E("off in %s" % _named_regions(row["off"]))))
    if row["unknown"]:
        bits.append(drill_link(
            "services_unknown",
            E("could not tell in %s" % _named_regions(row["unknown"]))))
    note = ""
    if bits:
        note = ("<div class='muted' style='font-size:.72rem;margin-top:.3rem'>%s"
                "</div>" % " \u00b7 ".join(bits))
    sample = ""
    if row["sample"]:
        sample = ("<div class='muted' style='font-size:.72rem;margin-top:.15rem'>"
                  "%s</div>" % E(row["sample"]))
    detail = E(row["detail"] or "\u2014")
    if row["on"]:
        detail = drill_link("services_on", detail)
    return ("<div class='card tight'>"
            "<div style='display:flex;justify-content:space-between;gap:.5rem;"
            "align-items:center'><b style='font-size:.9rem'>%s</b>%s</div>"
            "<div class='mono' style='font-size:1.05rem;font-weight:700;"
            "color:%s;margin-top:.35rem'>%s</div>"
            "<div class='muted' style='font-size:.72rem'>%s</div>%s%s</div>"
            % (E(row["label"]), _state_pill(row["state"]), colour,
               detail, E(row["what"]), sample, note))


def cloud_watching_panel(root: str, inventory: "Optional[dict]" = None) -> str:
    """What is on, what is off, and where — from the newest enablement read.

    An account with GuardDuty off in sixteen of seventeen regions looks, to
    every tool that reads only Security Hub, exactly like an account with
    nothing wrong in sixteen regions. This is the panel that refuses to let
    that stand."""
    data, row, _man = _cloud_reading(root, "cloudenable")
    if data is None:
        return _unavailable("What is watching this account", row, _man)
    summary = enablement_summary(data)
    tiles = "".join(_service_tile(r) for r in summary["services"])

    feats = summary["guardduty_features"]
    strip = ""
    if feats["on"] or feats["off"]:
        pills = "".join(
            "<span class='pill' style='font-size:.68rem;border:1px solid %s;"
            "color:%s'>%s</span>"
            % (("var(--ok)", "var(--ok)", E(f)) if f in feats["on"]
               else ("var(--muted)", "var(--muted)", E(f)))
            for f in sorted(feats["on"] + feats["off"]))
        strip = ("<div class='card tight'><div class='muted' style='font-size:"
                 ".72rem;letter-spacing:.06em;text-transform:uppercase;"
                 "margin-bottom:.4rem'>GuardDuty features &mdash; %d on, %d off"
                 "</div><div style='display:flex;flex-wrap:wrap;gap:.3rem'>%s"
                 "</div></div>" % (len(feats["on"]), len(feats["off"]), pills))

    gaps = watching_gaps(inventory or {}, summary)
    blind = ""
    if gaps:
        blind = ("<div class='card tight' style='border-left:4px solid var(--crit)'>"
                 "<h3 style='margin:0 0 .35rem'>Running, and not watched</h3>"
                 "<ul style='font-size:.85rem;margin:0 0 0 1rem'>%s</ul></div>"
                 % "".join("<li>%s</li>" % _why(g) for g in gaps))

    unread = ""
    if summary["regions_unread"]:
        unread = ("<p class='muted' style='font-size:.78rem;margin:.4rem 0 0'>"
                  "%d region(s) were never asked: %s. Nothing above covers them."
                  "</p>" % (len(summary["regions_unread"]),
                            E(", ".join(summary["regions_unread"][:8]))))

    return (_partial_notice(row)
            + "<h2 style='margin:1.2rem 0 0'>What is watching this account</h2>"
            "<p class='muted' style='font-size:.82rem;margin:.25rem 0 .6rem'>"
            "%d service check(s) across %d of %d enabled region(s), %d read-only "
            "API call(s). Off and <i>could not tell</i> are different answers "
            "and are shown as different words.</p>"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>%s%s%s"
            % (sum(1 for _ in summary["services"]), summary["regions_read"],
               summary["regions_enabled"], summary["api_calls"],
               tiles, strip, blind, unread))


# Which evidence file each cloud stage writes, and the tool key its ledger row
# carries. The ledger is the authority on whether that file is a reading.
CLOUD_READINGS = {
    "cloudorg": "cloud-org.json",
    "cloudinv": "cloud-inventory.json",
    "cloudenable": "cloud-enablement.json",
    "cloudiam": "cloud-iam.json",
    "cloudedge": "cloud-edge.json",
    "cloudfront": "cloud-frontdoor.json",
    "cloudstore": "cloud-storage.json",
    "cloudcontain": "cloud-containers.json",
    "clouddata": "cloud-dataservices.json",
    "cloudanalyzer": "cloud-analyzer.json",
}


def _ledger_row(man: dict, tool: str) -> "Optional[dict]":
    for row in (man.get("ledger") or []):
        if isinstance(row, dict) and row.get("tool") == tool:
            return row
    return None


def _cloud_reading(root: str, tool: str) -> "Tuple[Optional[dict], Optional[dict], Optional[dict]]":
    """(payload, ledger row, manifest) for one cloud stage's newest run.

    The payload is returned ONLY when the ledger says that stage is `ok`.

    Every panel used to open the raw file and reason over whatever it held. A
    stage the ledger marks `error` still wrote a payload — `{"users": [],
    "counts": {}}` for IAM, `{"regional": {}}` for edge — and the panel
    rendered it as a reading of an empty account. The review ran exactly that:
    a denied IAM read printed "the devices and keys were read, not assumed"
    (R-2).

    It also stops the panels walking back through older runs hunting for a file
    that parses. A number from a reading three days ago, shown without saying
    so, is a worse answer than none."""
    for man in list_runs(root):
        if man.get("service") != "cloudinventory":
            continue
        row = _ledger_row(man, tool)
        if row is None:
            continue                     # this run did not have the stage
        # `gap` covers two different things and the difference is already in
        # the ledger. A stage that read SOME things and had one read fail has a
        # real payload and a non-zero `examined`; refusing to render that hid
        # everything the stage did read because of one thing it did not -- in field use one
        # unused-access analyzer failing took dozens of findings from the working analyzer off the
        # page, while the ledger
        # went on counting them (review 2, R-21). A stage that read NOTHING has
        # `examined` zero, and rendering that would be R-2 again: a denied read
        # printed as an empty account.
        status = row.get("status")
        examined = (row.get("coverage") or {}).get("examined")
        partial = (status == "gap"
                   and isinstance(examined, int) and examined > 0)
        if status != "ok" and not partial:
            return None, row, man
        data = _read_raw(man, CLOUD_READINGS.get(tool, ""))
        if data is None:
            # The ledger says ok and the file will not parse. That is a third
            # thing, and it is not a reading either.
            return None, dict(row, status="error",
                              detail="the ledger recorded this stage as ok and "
                                     "its evidence could not be read"), man
        return data, row, man
    return None, None, None


def _unavailable(title: str, row: "Optional[dict]", man: "Optional[dict]",
                 blurb: str = "") -> str:
    """The card a panel renders instead of a reading it does not have."""
    if row is None:
        return ""                         # the stage has never run: show nothing
    when = _fmt_run_time(as_text((man or {}).get("run_id"))) if man else ""
    detail = as_text(row.get("detail"))
    return ("<h2 style='margin:1.2rem 0 .3rem'>%s</h2>"
            "%s<div class='card tight' style='border-left:4px solid var(--gap)'>"
            "<b>This reading is not available.</b> "
            "<span class='muted'>The %s stage reported <span class='mono'>%s</span> "
            "on the newest run (%s), so there is nothing here to show. What it "
            "said: %s</span>"
            "<p class='muted' style='font-size:.78rem;margin:.45rem 0 0'>"
            "Nothing older is substituted. A number from an earlier reading, "
            "shown without saying so, is a worse answer than none.</p></div>"
            % (E(title),
               ("<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>%s</p>"
                % blurb) if blurb else "",
               E(as_text(row.get("tool"))), E(as_text(row.get("status"))),
               E(when or "unknown"), _why(detail or "nothing")))


def _unavailable_banner(row: "Optional[dict]", man: "Optional[dict]") -> str:
    """The estate banner when the organization read is not a reading.

    It sits above every number it qualifies, so when it cannot say what
    fraction of the estate this covers it has to say that, not nothing."""
    if row is None:
        return ""
    detail = as_text(row.get("detail"))
    return ("<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin:.6rem 0'><b>How much of the estate this covers is not "
            "available.</b> <span class='muted'>The organization stage "
            "reported <span class='mono'>%s</span> on the newest run. "
            "Everything below is about one account, and whether there are "
            "others is not known here. What it said: %s</span></div>"
            % (E(as_text(row.get("status"))), _why(detail or "nothing")))


def _read_raw(man: dict, name: str) -> "Optional[dict]":
    """One stage's evidence from a run, or None. A file that will not parse is
    None and not {} — an empty reading and an unreadable one are different."""
    path = os.path.join(man.get("_dir", ""), "raw", name)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def drill_link(key: str, body: str) -> str:
    """Wrap a number in a link to what is behind it.

    A count is a claim, and a claim a reader cannot check is one they have to
    take on trust. Every figure that names a set of resources links to that
    set — from the same saved reading, so the list and the number can never
    disagree. A key with no extractor renders as plain text rather than a dead
    link, because a link that goes nowhere is worse than none."""
    if key not in CLOUD_DRILL:
        return body
    return ("<a href='/cloud/detail?what=%s' style='color:inherit;"
            "text-decoration:none;border-bottom:1px dotted currentColor' "
            "title='Show what is behind this number'>%s</a>" % (E(key), body))


def _num(key: str, value: object, colour: str = "inherit",
         weight: str = "500", size: str = "1rem") -> str:
    """One number on a tile, linked to what is behind it."""
    return drill_link(key, "<span class='mono' style='font-size:%s;"
                           "font-weight:%s;color:%s'>%s</span>"
                      % (size, weight, colour, E(str(value))))


# The headline facts are named for what they say, not for the count they are
# drawn from, so this says which set each one expands to.
HEADLINE_DRILL = {"regions": "regions_active", "instances": "running",
                  "reachable": "public_instances", "open": "risky_open_groups",
                  "roles": "broad_roles", "unread": "regions_unread",
                  "denied": "regions_denied"}


def view_cloud_detail(root: str, key: str) -> str:
    """The resources behind one number on the Cloud page."""
    entry = CLOUD_DRILL.get(key or "")
    if not entry:
        return ("<h1>Nothing to show</h1>" + empty_state(
            "cloud", "That is not a figure this page can expand",
            "The address names a detail view that does not exist. Nothing was "
            "substituted for it.",
            "<a class='btn' href='/cloud'>Back to Cloud</a>"))
    title, filename, _fn = entry
    tool = next((t for t, f in CLOUD_READINGS.items() if f == filename), "")
    data, row, man = _cloud_reading(root, tool)
    if data is None:
        return ("<h1>%s</h1>" % E(title) + empty_state(
            "cloud",
            "That stage did not produce a reading"
            if row is not None else "No reading holds this yet",
            ("Its ledger row on the newest run says %s: %s. There is nothing "
             "behind the number because the number is not there either."
             % (as_text(row.get("status")),
                redact_identifiers(as_text(row.get("detail")))))
            if row is not None else
            ("The stage that produces %s has not run. Nothing is shown rather "
             "than an empty list, which would read as \u201cnothing there\u201d."
             % filename),
            "<a class='btn' href='/cloud'>Back to Cloud</a>"))
    rows = cloud_drill(key, data)
    body = "".join(
        "<tr><td class='mono'>%s</td><td class='mono muted'>%s</td>"
        "<td>%s</td></tr>"
        % (E(r["name"]), E(r["where"]), E(r["note"])) for r in rows)
    if not body:
        body = ("<tr><td colspan='3' class='muted'>None. That is what the "
                "reading found, not a failure to look — the count above it is "
                "zero for the same reason.</td></tr>")
    stamp = as_text(data.get("read_at"))
    # One number on the page is a sum rather than a count of rows: Squawk reads
    # ECS services, not individual tasks. Saying which field adds up to the
    # figure above is the difference between a reconcilable list and one that
    # looks like it disagrees with the tile that led here.
    summed = DRILL_SUMS.get(key)
    counted = "%d row(s)" % len(rows)
    if summed:
        total = sum(int(r.get(summed) or 0) for r in rows
                    if isinstance(r.get(summed), (int, float)))
        counted = ("%d row(s), %d in total — the figure on the tile is the sum "
                   "of the \u201c%s\u201d column, not the number of rows"
                   % (len(rows), total, summed))
    return ("<h1>%s</h1><p class='sub'>%s, from the reading taken at "
            "<span class='mono'>%s</span>. This is the same saved reading the "
            "number came from — not a fresh query — so the list and the number "
            "cannot disagree.</p>"
            "<p class='muted' style='font-size:.8rem'>"
            "<a href='/cloud'>&larr; Back to Cloud</a> &middot; evidence "
            "<span class='mono'>%s</span></p>"
            "<div class='card tight'><div style='overflow-x:auto'><table>"
            "<thead><tr><th>Name</th><th>Where</th><th>What the reading says"
            "</th></tr></thead><tbody>%s</tbody></table></div></div>"
            % (E(title), E(counted), E(stamp or "unknown"),
               E(os.path.join(as_text((man or {}).get("run_id")), "raw", filename)),
               body))


def cloud_estate_banner(root: str) -> str:
    """How much of the estate this reading covers, said before anything else.

    Every number below it is a count about one account. On a standalone
    account that is the estate; in an organization it is a fraction, and the
    same number then means something different. Putting this last would be
    letting the reader form the wrong impression first and correcting it
    afterwards."""
    data, _row, _man = _cloud_reading(root, "cloudorg")
    if data is None:
        return _unavailable_banner(_row, _man)
    if not data:
        return ""
    summary = org_summary(data)
    if summary["standalone"]:
        return ("<div class='card tight' style='border-left:4px solid var(--ok);"
                "margin:.6rem 0'><b>One account, and it is the whole estate.</b> "
                "<span class='muted'>This account is not part of an AWS "
                "Organization, so every count below covers all of it.</span>"
                "</div>")
    if summary["org_error"]:
        return ("<div class='card tight' style='border-left:4px solid var(--gap);"
                "margin:.6rem 0'><b>How much of the estate this covers is "
                "unknown.</b> <span class='muted'>The organization could not be "
                "read (%s). Everything below is about this account; whether "
                "there are others is not known.</span></div>"
                % E(summary["org_error"]))
    total = summary["accounts_total"]
    if total <= 1:
        # The stage learned this account IS in an organization -- it has an
        # org id and did not report standalone -- and the account list either
        # was refused or holds this account alone. `list-accounts` is the call
        # a member account is usually not allowed to make, so the refusal is
        # the ORDINARY case for a read-only audit role. It arrived here under
        # `org_error` and never reached this card (review 3, R-37); and a
        # one-account organization, whose list answered in full, was told its
        # coverage was unknown (R-42).
        if summary["org_id"] and summary.get("accounts_error"):
            return ("<div class='card tight' style='border-left:4px solid "
                    "var(--gap);margin:.6rem 0'><b>This account is in an AWS "
                    "Organization, and how much of it this covers is not "
                    "known.</b> <span class='muted'>The organization answered "
                    "and its account list did not: %s. Listing the accounts "
                    "needs a permission the identity reading this does not "
                    "have, which is the usual answer for a member account. "
                    "Every count below is about this one account. Whether that "
                    "is the whole estate or one account of many is the "
                    "question this reading could not settle, and unread is not "
                    "clean.%s</span></div>"
                    % (_why(summary["accounts_error"]),
                       " This is the organization's management account, so the "
                       "permission is more likely to be grantable here."
                       if summary["is_management"] else ""))
        if summary["org_id"] and total == 1:
            return ("<div class='card tight' style='border-left:4px solid "
                    "var(--ok);margin:.6rem 0'><b>One account, and it is the "
                    "whole organization.</b> <span class='muted'>The "
                    "organization answered and its account list holds this "
                    "account alone, so every count below covers all of it."
                    "</span></div>")
        if summary["org_id"]:
            return ("<div class='card tight' style='border-left:4px solid "
                    "var(--gap);margin:.6rem 0'><b>This account is in an AWS "
                    "Organization whose account list came back empty.</b> "
                    "<span class='muted'>The organization answered and listed "
                    "no active account, not even this one. Every count below "
                    "is about this one account, and unread is not clean."
                    "</span></div>")
        return ""
    unread = len(summary["accounts_unread"])
    reachable = summary["accounts_reachable"]
    extra = ""
    if reachable > 1:
        extra = (" <span class='muted'>%d account(s) are reachable from this "
                 "machine with profiles you already have — run again with "
                 "<span class='mono'>AWS_PROFILE</span> set to each.</span>"
                 % reachable)
    return ("<div class='card tight' style='border-left:4px solid var(--high);"
            "margin:.6rem 0'><b>This is 1 of %d accounts in the "
            "organization.</b> <span class='muted'>Every count below is about "
            "this one account, not the estate. %d account(s) have no "
            "configured profile here, so nothing on this page covers them — "
            "unread is not clean.%s</span>%s</div>"
            % (total, unread, extra,
               "<p class='muted' style='font-size:.78rem;margin:.4rem 0 0'>"
               "This is the organization's management account.</p>"
               if summary["is_management"] else ""))


def cloud_storage_panel(root: str) -> str:
    """Where the data is, and what is keeping people out of it."""
    data, row, _man = _cloud_reading(root, "cloudstore")
    if data is None:
        return _unavailable("Where the data is", row, _man)
    if not data:
        return ""
    summary = storage_summary(data)
    blocked = data.get("account_block_on") is True
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("buckets", summary["bucket_total"], "S3 buckets", False),
            # A tile that says "0" over a bucket whose policy status was
            # refused is a zero over nothing (review 3, R-46). The count of
            # unreadable buckets travels on the label.
            ("buckets_public", c["buckets_public"],
             "with a public policy%s" % _unreadable_note(c["buckets_unreadable"]),
             True),
            ("buckets_unencrypted", c["buckets_unencrypted"],
             "with no default encryption%s"
             % _unreadable_note(c["buckets_unreadable"]), True),
            ("databases", c["databases"], "databases", False),
            ("databases_public", c["databases_public"], "publicly accessible", True),
            ("databases_unencrypted", c["databases_unencrypted"],
             "with unencrypted storage", True)))

    raw_inv, _r2, _m2 = _cloud_reading(root, "cloudinv")
    # Through the shared renderer. Three panels each carried their own copy of
    # it, and each copy had a slightly different severity-to-colour map -- so
    # a `low` finding was grey on one panel and the default gap colour on
    # another, and only one of the three would have picked up a new level.
    found = _finding_rows(
        storage_findings(data, raw_inv),
        "No bucket is public and no database is reachable from the internet. "
        "AWS evaluated each bucket policy itself and said so — this is not a "
        "guess from the policy text.", row=row)

    caveats = "".join("<li>%s</li>" % E(x)
                      for x in storage_caveats(summary, blocked))
    return (_partial_notice(row)
            + "<h2 style='margin:1.2rem 0 .3rem'>Where the data is</h2>"
            "<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>"
            "%d bucket(s) and %d database(s), read in %d read-only API "
            "call(s). Whether a bucket is public is AWS's own answer, from "
            "<span class='mono'>get-bucket-policy-status</span> — nothing here "
            "reimplements policy evaluation.</p>"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>"
            "<div class='card tight'>%s</div>"
            "<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>What this does "
            "not tell you</h3><ul class='muted' style='font-size:.82rem;"
            "margin:0 0 0 1rem'>%s</ul></div>"
            % (summary["bucket_total"], c["databases"], summary["api_calls"],
               tiles, found, caveats))


def _unreadable_note(count: object) -> str:
    """The suffix a tile carries when part of what it counts was refused."""
    return (" (%d unreadable)" % count
            if isinstance(count, int) and not isinstance(count, bool) and count
            else "")


def _is_partial(row: "Optional[dict]") -> bool:
    """Whether this stage read some things and had a read fail."""
    return isinstance(row, dict) and row.get("status") == "gap"


def _partial_notice(row: "Optional[dict]") -> str:
    """Said ABOVE the numbers when a stage read some things and not others.

    Not a caveat at the bottom: every count in the section below it is short by
    whatever the failed read held, and a reader who stops at the tiles would
    take them at face value."""
    if not isinstance(row, dict) or not _is_partial(row):
        return ""
    return ("<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin-bottom:.6rem'><b>Part of this reading failed.</b> "
            "<span class='muted'>%s Every count below is short by whatever "
            "that read held — it is a floor, not a total.</span></div>"
            % _why(row.get("detail")))


def _panel(title: str, blurb: str, tiles: str, found: str, caveats: str,
           extra: str = "", row: "Optional[dict]" = None) -> str:
    """The shape every cloud section shares: a blurb, linked tiles, what was
    found, and what the reading does not settle."""
    return ("<h2 style='margin:1.2rem 0 .3rem'>%s</h2>"
            "<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>%s</p>"
            "%s"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>"
            "<div class='card tight'>%s</div>%s"
            "<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>What this does "
            "not tell you</h3><ul class='muted' style='font-size:.82rem;"
            "margin:0 0 0 1rem'>%s</ul></div>"
            % (E(title), blurb, _partial_notice(row), tiles, found,
               extra, caveats))


def _why(text: object) -> str:
    """One escape for anything a read said about itself.

    `_aws_json` already redacts before the string reaches evidence, so this is
    the belt for those braces: a future read that builds its own error text is
    still masked on screen, and a page can never be the place an address gets
    out. Everything that renders a `why`, a `detail` or an `unreadable` string
    comes through here (review R-3)."""
    return E(redact_identifiers(text))


def _finding_rows(rows: "List[dict]", empty: str,
                  row: "Optional[dict]" = None,
                  collapse: "Sequence[Tuple[str, str, str]]" = ()) -> str:
    """The findings a section names, one block each.

    A rule that fires on dozens of resources is one pattern, not dozens of
    things to read, and printing a paragraph for each of them buries the
    findings that are not a pattern -- the analyzer section ran to six pages
    of identical text in field use. `collapse` names those rules, as
    (the finding's key, the number on this page holding the same set, the
    sentence to print). The count is exact and the number links to every
    member, so nothing is hidden: it moves behind the number, which is where
    the rest of this page keeps its detail (I12).
    """
    folded = set(key for key, _drill, _phrase in collapse)
    counted = {}  # type: Dict[str, int]
    body = []
    for found in rows:
        key = as_text(found.get("key"))
        if key in folded:
            counted[key] = counted.get(key, 0) + 1
            continue
        colour = {"critical": "var(--crit)", "high": "var(--high)",
                  "medium": "var(--gap)", "low": "var(--muted)"}.get(
                      found["severity"], "var(--gap)")
        body.append("<div style='border-left:3px solid %s;padding:.35rem 0 "
                    ".35rem .6rem;margin-bottom:.45rem'><b class='mono'>%s</b> "
                    "<span class='muted' style='font-size:.75rem'>%s</span><br>"
                    "<span style='font-size:.85rem'>%s</span></div>"
                    % (colour, E(found["resource"]), E(found.get("region", "")),
                       _why(found["why"])))
    for key, drill, phrase in collapse:
        if not counted.get(key):
            continue
        body.append("<div style='border-left:3px solid var(--muted);"
                    "padding:.35rem 0 .35rem .6rem;margin-bottom:.45rem'>"
                    "<span style='font-size:.85rem'>%s %s</span></div>"
                    % (drill_link(drill, "<b class='mono'>%d</b>"
                                  % counted[key]), E(phrase)))
    if body:
        return "".join(body)
    if _is_partial(row):
        # The clean negative is exactly what must not print over a read that
        # was refused (I1). The counts above are real and the section still
        # renders them; "nothing was found" is not a sentence this reading has
        # earned.
        return ("<p class='muted' style='font-size:.85rem;margin:0'>Nothing "
                "was found in what could be read, and part of this reading "
                "failed — so this is not the same as nothing being there.</p>")
    return "<p class='muted' style='font-size:.85rem;margin:0'>%s</p>" % empty


def cloud_containers_panel(root: str, inventory: "Optional[dict]" = None) -> str:
    """ECS and EKS — the compute an account has when it has no instances."""
    data, row, _man = _cloud_reading(root, "cloudcontain")
    raw_inv, _r2, _m2 = _cloud_reading(root, "cloudinv")
    if data is None:
        return _unavailable("What runs in containers", row, _man)
    if not data:
        return ""
    summary = container_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("eks_clusters", c["eks_clusters"], "EKS clusters", False),
            ("eks_public", c["eks_public"], "with a public API endpoint", True),
            ("eks_without_logs", c["eks_without_logs"],
             "with no control-plane logging", True),
            ("ecs_services", c["ecs_services"], "ECS services", False),
            ("ecs_public", c["ecs_public"], "assigning public addresses", True),
            ("ecs_tasks", c["ecs_tasks"], "running tasks", False)))
    found = _finding_rows(
        container_findings(data, raw_inv),
        "No cluster answers the internet without an address restriction, and "
        "no service puts its tasks on a public address. The endpoints and the "
        "subnets were read, not assumed.", row=row)
    caveats = "".join("<li>%s</li>" % E(x) for x in (
        (["More clusters or services exist in at least one region than were "
          "examined, so these counts are a floor. Raise cloud_max_items in a "
          "profile."] if summary.get("truncated") else [])
        + ["A task's own IAM role is not read, so the four-leg combination an "
         "instance gets — public address, route, a world-open rule and a role "
         "that can do far more than read — cannot be built for a task. The "
         "one combination that would justify a critical here is the one this "
         "does not read.",
         "Task definitions are not read, so an environment variable holding a "
         "secret would not appear here.",
         "Kubernetes itself is not read — only the AWS side of the cluster. "
         "RBAC, admission control and what runs in the cluster are invisible "
         "from the API this uses."]
        + (["%d region(s) were never reached." % len(summary["regions_unread"])]
           if summary["regions_unread"] else [])
        + partial_caveat(summary)))
    return _panel(
        "What runs in containers",
        "%d cluster(s) and %d service(s) across %d of %d enabled region(s), "
        "%d read-only API call(s). An account whose workloads are tasks has no "
        "instances to find." % (c["eks_clusters"], c["ecs_services"],
                                summary["regions_read"],
                                summary["regions_enabled"],
                                summary["api_calls"]),
        tiles, found, caveats, row=row)


def _outside_pairs(root: str) -> "List[Tuple[str, str]]":
    """What the readers on this page called reachable from outside, as
    (panel, name), from every reading that judges a kind the analyzer also
    reports on. The comparison used to take roles only, so a bucket both the
    storage reader and the analyzer flagged was "a disagreement" (review 3,
    R-38)."""
    ours: List[Tuple[str, str]] = []
    raw_iam, _r, _m = _cloud_reading(root, "cloudiam")
    if raw_iam:
        iam = iam_summary(raw_iam)
        for role in (_rows(iam.get("roles_with_escalation"))
                     + _rows(iam.get("roles_already_admin"))):
            if as_text(role.get("reach")) in OUTSIDE_REACH:
                ours.append(("roles", as_text(role.get("name"))))
    raw_store, _r, _m = _cloud_reading(root, "cloudstore")
    if raw_store:
        for bucket in _rows(raw_store.get("buckets")):
            if bucket.get("public"):
                ours.append(("buckets", as_text(bucket.get("name"))))
    raw_data, _r, _m = _cloud_reading(root, "clouddata")
    if raw_data:
        regional = raw_data.get("regional")
        for per in (regional.values() if isinstance(regional, dict) else []):
            if not isinstance(per, dict):
                continue
            for panel in ("topics", "queues", "repositories"):
                for item in _rows(per.get(panel)):
                    if item.get("public"):
                        ours.append((panel, as_text(item.get("name"))))
    return ours


def cloud_analyzer_panel(root: str) -> str:
    """What AWS's own external-access analyzer found, beside what this page
    worked out by reading policies."""
    data, row, _man = _cloud_reading(root, "cloudanalyzer")
    if data is None:
        return _unavailable("What AWS says is reachable from outside", row, _man)
    if not data:
        return ""
    summary = analyzer_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("analyzers", c["analyzers"], "active analyzers", False),
            ("analyzer_findings", c["findings"], "resources reachable from "
             "outside the account", False),
            ("analyzer_public", c["public"], "of those, reachable by anyone",
             True),
            ("analyzer_external", c["external"], "by a named account or "
             "organization", True),
            ("analyzer_own_federation", c["own_federation"],
             "through this account's own identity federation", False)))

    # Both halves, always. A disagreement is the most interesting thing here.
    agree = analyzer_agreement(data, _outside_pairs(root))
    compare = ""
    parts = []
    if agree["asked"]:
        if agree["aws_only"]:
            parts.append("<li><b>%d</b> that AWS names and the policy readers "
                         "on this page do not: %s. AWS evaluated conditions, "
                         "SCPs and resource control policies; the readers "
                         "here cannot see any of the three, so this is the "
                         "answer to trust.</li>"
                         % (len(agree["aws_only"]),
                            E(", ".join(agree["aws_only"][:6]))))
        if agree["own_unpinned"]:
            parts.append("<li><b>%d</b> that AWS files under this account's "
                         "own federation and this page reads as reachable by "
                         "ANYONE: %s. AWS is right that the provider is this "
                         "account's; this page is right that nothing pins "
                         "which identity the provider admits. Both are true, "
                         "and the second is the finding.</li>"
                         % (len(agree["own_unpinned"]),
                            E(", ".join(agree["own_unpinned"][:6]))))
        if agree["ours_only"]:
            parts.append("<li><b>%d</b> that the policy readers name and AWS "
                         "does not: %s. Either something outside the policy "
                         "text stops the path — a boundary, an SCP — or the "
                         "resource is a kind the analyzer does not cover. "
                         "Both are worth knowing and neither is a false "
                         "alarm.</li>"
                         % (len(agree["ours_only"]),
                            E(", ".join(agree["ours_only"][:6]))))
        set_aside = agree["own_federation"] - len(agree["own_unpinned"])
        if parts and set_aside > 0:
            parts.append("<li>%d finding(s) are left out of this comparison on "
                         "purpose: roles the account's own OIDC and SAML "
                         "providers can assume, whose trust this page reads "
                         "as pinned. The analyzer counts a federated principal "
                         "as outside its zone of trust, so putting them here "
                         "would manufacture a disagreement about definitions "
                         "rather than about the account.</li>" % set_aside)
    if parts:
        compare = ("<div class='card tight' style='border-left:4px solid "
                   "var(--gap);margin-top:.6rem'><h3 style='margin:0 0 .35rem'>"
                   "Where AWS and this page disagree</h3>"
                   "<ul style='font-size:.85rem;margin:0 0 0 1rem'>%s</ul></div>"
                   % "".join(parts))
    elif agree["asked"] and agree["own_federation"]:
        compare = ("<div class='card tight' style='border-left:4px solid "
                   "var(--ok);margin-top:.6rem'><h3 style='margin:0 0 .35rem'>"
                   "Where AWS and this page agree</h3>"
                   "<p class='muted' style='font-size:.85rem;margin:0'>Nothing "
                   "outside this account's own control is named by either. The "
                   "%d finding(s) above are roles the account's own OIDC and "
                   "SAML providers can assume — the analyzer counts a "
                   "federated principal as outside its zone of trust, and this "
                   "page reads the same trust policies and finds each pinned "
                   "to a repository, a service account or an audience. Same "
                   "answer, different words.</p></div>"
                   % agree["own_federation"])
    unjudged = ""
    if agree["unjudged"]:
        unjudged = ("<li>%d finding(s) are about kinds the readers on this "
                    "page do not judge — %s — and are AWS's answer alone.</li>"
                    % (len(agree["unjudged"]),
                       E(", ".join(agree["unjudged"][:6]))))

    found = _finding_rows(
        analyzer_findings(data),
        "Every active analyzer answered and none reports a resource reachable "
        "from outside this account. That is AWS's own evaluation, not a "
        "reading of the policy text.", row=row,
        collapse=(("analyzer-own-federation", "analyzer_own_federation",
                   "resource(s) are reachable from outside the account only "
                   "because they trust a provider this account created — its "
                   "own EKS cluster, its own GitHub Actions OIDC, its own "
                   "SAML. That is how the federation works, not a grant to a "
                   "third party; what decides whether it is safe is the "
                   "condition on the claim, which the identity section of this "
                   "page reads. Every one of them is behind that number."),))
    caveats = ("".join("<li>%s</li>" % E(x) for x in analyzer_caveats(summary))
               + unjudged)
    return _panel(
        "What AWS says is reachable from outside",
        "%d active analyzer(s) across %d of %d enabled region(s), %d read-only "
        "API call(s). Access Analyzer evaluates the policy the way IAM does — "
        "this asks it what it found, rather than only whether it is on."
        % (c["analyzers"], summary["regions_read"], summary["regions_enabled"],
           summary["api_calls"]),
        tiles, found + compare, caveats, row=row)


def cloud_dataservices_panel(root: str) -> str:
    """Topics, queues, secrets and repositories — reachable by policy alone."""
    data, row, _man = _cloud_reading(root, "clouddata")
    if data is None:
        return _unavailable("Queues, topics, secrets and images", row, _man)
    if not data:
        return ""
    summary = dataservice_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("topics", c["topics"], "SNS topics", False),
            ("queues", c["queues"], "SQS queues", False),
            ("messaging_public", c["topics_public"] + c["queues_public"],
             "usable by any AWS principal", True),
            ("secrets", c["secrets"], "secrets", False),
            ("repositories", c["repositories"], "container repositories", False),
            ("repositories_public", c["repositories_public"],
             "repositories any principal can pull", True)))
    found = _finding_rows(
        dataservice_findings(data),
        "No topic, queue or repository admits a principal outside this "
        "account. Every resource policy was read, not assumed.", row=row)
    caveats = "".join("<li>%s</li>" % E(x)
                      for x in dataservice_caveats(summary))
    return _panel(
        "Queues, topics, secrets and images",
        "%d topic(s), %d queue(s), %d secret(s) and %d repository(ies) across "
        "%d of %d enabled region(s), %d read-only API call(s). These are "
        "reachable by policy alone — there is no subnet or security group "
        "between a caller and them."
        % (c["topics"], c["queues"], c["secrets"], c["repositories"],
           summary["regions_read"], summary["regions_enabled"],
           summary["api_calls"]),
        tiles, found, caveats, row=row)


def cloud_frontdoor_panel(root: str) -> str:
    """Where traffic from the internet actually arrives.

    Sits directly above the edge panel, because on an account with no public
    instances and no internet-facing load balancers this is the section that
    decides whether "0 reachable from the internet" is a finding or an
    artefact of not having looked."""
    data, row, _man = _cloud_reading(root, "cloudfront")
    if data is None:
        return _unavailable("Where traffic arrives", row, _man)
    if not data:
        return ""
    summary = frontdoor_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("apis", c["apis"], "API Gateway APIs", False),
            ("apis_public", c["apis_public"], "reachable from the internet", False),
            ("apis_with_open_routes", c["apis_with_open_routes"],
             "with routes that authenticate nothing", True),
            ("distributions", c["distributions_enabled"], "CloudFront distributions", False),
            ("distributions_without_waf", c["distributions_without_waf"], "with no web ACL", True),
            ("frontdoor_regions_unread", len(summary["regions_unread"]),
             "regions never reached", True)))

    found = _finding_rows(
        frontdoor_findings(data),
        "Every API route and every distribution was read, and none is open "
        "without authentication.", row=row)

    caveats = "".join("<li>%s</li>" % E(x) for x in frontdoor_caveats(summary))
    return (_partial_notice(row)
            + "<h2 style='margin:1.2rem 0 .3rem'>Where traffic arrives</h2>"
            "<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>"
            "%d API(s) and %d distribution(s) across %d of %d enabled "
            "region(s), %d read-only API call(s). An account with no public "
            "instance and no internet-facing load balancer can still have a "
            "front door here.</p>"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>"
            "<div class='card tight'>%s</div>"
            "<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>What this does "
            "not tell you</h3><ul class='muted' style='font-size:.82rem;"
            "margin:0 0 0 1rem'>%s</ul></div>"
            % (c["apis"], c["distributions"], summary["regions_read"],
               summary["regions_enabled"], summary["api_calls"], tiles, found,
               caveats))


def cloud_edge_panel(root: str, inventory: "Optional[dict]" = None) -> str:
    """What the internet can actually talk to.

    On a container-first account the instance count is the wrong denominator.
    A hundred and three interfaces against seven instances says the workloads
    are Lambda, ECS tasks and load balancers — and until this read, none of
    them were looked at, so every reachability answer was a clean result from
    checks that had no subject."""
    data, row, _man = _cloud_reading(root, "cloudedge")
    raw_inv, _r2, _m2 = _cloud_reading(root, "cloudinv")
    if data is None:
        return _unavailable("What the internet can talk to", row, _man)
    if not data:
        return ""
    summary = edge_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("functions", c["functions"], "Lambda functions", False),
            ("function_urls", c["urls"], "with a function URL", False),
            ("urls_without_auth", c["urls_without_auth"], "URLs with no authentication", True),
            ("load_balancers", c["load_balancers"], "load balancers", False),
            ("internet_facing", c["internet_facing"], "internet-facing", False),
            ("edge_unreadable", len(summary["unreadable"]),
             "reads that failed", True)))

    found = _finding_rows(
        edge_findings(data) + edge_gaps(raw_inv or {}, data),
        "No function URL is open without authentication, and no "
        "internet-facing load balancer admits the world on a risky port. The "
        "URLs and the groups were read, not assumed.", row=row)

    owners = interface_owners(raw_inv or {})
    strip = ""
    if owners:
        pills = "".join(
            "<span class='pill' style='font-size:.72rem'>%s &middot; %d</span>"
            % (E(name), count) for name, count in owners)
        strip = ("<div class='card tight' style='margin-top:.6rem'>"
                 "<div class='muted' style='font-size:.72rem;letter-spacing:"
                 ".06em;text-transform:uppercase;margin-bottom:.4rem'>What owns "
                 "the network interfaces &mdash; %d in total</div>"
                 "<div style='display:flex;flex-wrap:wrap;gap:.3rem'>%s</div>"
                 "<p class='muted' style='font-size:.75rem;margin:.4rem 0 0'>"
                 "Interfaces outnumber instances on any account that runs "
                 "containers or functions. This says by how much, and what the "
                 "difference is.</p></div>"
                 % (sum(n for _o, n in owners), pills))

    caveat = ""
    bits = []
    if summary["truncated"]:
        bits.append("more functions exist than were read, so the counts are a "
                    "floor")
    if summary["unreadable"]:
        bits.append("%d read(s) failed: %s"
                    % (len(summary["unreadable"]),
                       "; ".join(summary["unreadable"][:3])))
    if summary["regions_unread"]:
        bits.append("%d region(s) were never reached"
                    % len(summary["regions_unread"]))
    bits.extend(partial_caveat(summary))
    bits.append("A network load balancer carries no security group, so what it "
                "admits is decided by its listeners and by the groups on the "
                "targets behind it. Neither is read: an internet-facing one is "
                "reported as unknown rather than as clear.")
    bits.append("Container workloads are read in their own section of this "
                "page, so a task behind a load balancer is counted there and "
                "not here. API Gateway and CloudFront are read, in the "
                "section above this one.")
    caveat = ("<div class='card tight' style='border-left:4px solid var(--gap);"
              "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>What this does "
              "not tell you</h3><ul class='muted' style='font-size:.82rem;"
              "margin:0 0 0 1rem'>%s</ul></div>"
              % "".join("<li>%s</li>" % E(b) for b in bits))

    return (_partial_notice(row)
            + "<h2 style='margin:1.2rem 0 .3rem'>What the internet can talk to</h2>"
            "<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>"
            "%d function(s) and %d load balancer(s) across %d of %d enabled "
            "region(s), %d read-only API call(s).</p>"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>"
            "<div class='card tight'>%s</div>%s%s"
            % (c["functions"], c["load_balancers"], summary["regions_read"],
               summary["regions_enabled"], summary["api_calls"], tiles, found,
               strip, caveat))


# The role findings, one card per reach. They shared one card headed
# "Reachable from outside, and able to grant itself more" -- which was true of
# the critical rows and false of the low ones about the organization's own
# accounts, and would have been false of the unknown ones about accounts the
# organization read could not place (review 3, R-37).
# Each card carries the drill key its members live behind, or "" when the page
# has no extractor for that set. The card lists eight at most, so without a key
# the ninth member is behind no number anywhere — which is the silent cap this
# page refuses (I12).
_ROLE_CARDS = (
    (("escalation-reachable-from-outside",
      "administrative-reachable-from-outside"), "var(--crit)",
     "Reachable from outside, and able to grant itself more",
     "Either half is ordinary. The combination is a path from outside this "
     "account to more permission than the role was given, and the two halves "
     "live in different documents.", "roles_reachable_from_outside"),
    (("role-trust-unsettled",), "var(--gap)",
     "Assumable from an account this run could not place",
     "The organization answered and its account list was refused, so whether "
     "the trusted account is a sibling or a stranger is unknown. Not a "
     "critical, and not nothing.", "roles_trust_unsettled"),
    (("role-assumable-within-the-organization",), "var(--muted)",
     "Assumable from within the organization",
     "An organization is a trust boundary somebody chose. Stated, not raised.",
     ""),
)


def _role_cards(rows: "List[dict]") -> str:
    out = []
    for keys, colour, title, blurb, drill in _ROLE_CARDS:
        mine = [r for r in rows if as_text(r.get("key")) in keys]
        if not mine:
            continue
        items = "".join(
            "<li><b class='mono'>%s</b> — %s<br>"
            "<span class='muted' style='font-size:.78rem'>%s</span></li>"
            % (E(as_text(r.get("role"))), _why(r.get("why")),
               _why("; ".join(r.get("escalation", [])[:2])))
            for r in mine[:8])
        # The count, linked to the set. Eight members are shown and the number
        # is exact, so a card with nine says nine and opens all nine.
        plain = "<b class='mono'>%d</b>" % len(mine)
        count = drill_link(drill, plain) if drill else plain
        rest = ("" if len(mine) <= 8 else
                "<li class='muted' style='font-size:.78rem'>and %d more, "
                "behind the count above</li>" % (len(mine) - 8))
        out.append("<div class='card tight' style='border-left:4px solid %s;"
                   "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>%s %s</h3>"
                   "<p class='muted' style='font-size:.8rem;margin:0 0 .4rem'>"
                   "%s</p><ul style='font-size:.85rem;margin:0 0 0 1rem'>%s%s"
                   "</ul></div>"
                   % (colour, count, E(title), E(blurb), items, rest))
    return "".join(out)


def cloud_iam_panel(root: str) -> str:
    """Who exists in this account, and which of them can become more.

    The counts are the frame; the findings are the point. A user without MFA
    is worth a line, and a user without MFA that can attach itself a policy is
    a different sentence — so the second is not shown as a stronger version of
    the first, it replaces it."""
    data, row, _man = _cloud_reading(root, "cloudiam")
    if data is None:
        return _unavailable("Who can do what", row, _man)
    if not data:
        return ""
    summary = iam_summary(data)
    c = summary["counts"]
    tiles = "".join(
        "<div class='card tight'><div style='line-height:1.1'>%s</div>"
        "<div style='font-size:.8rem;margin-top:.2rem'>%s</div></div>"
        % (_num(key, value,
                "var(--high)" if weight and value else "inherit", "700",
                "1.4rem"), E(label))
        for key, value, label, weight in (
            ("users", c["users"], "IAM users", False),
            ("users_without_mfa", c["users_without_mfa"], "without an MFA device", True),
            ("users_with_keys", c["users_with_keys"], "with an active access key", True),
            ("iam_roles", c["roles"], "roles", False),
            ("roles_that_can_escalate", c["roles_that_can_escalate"],
             "roles that can grant themselves more", True),
            ("roles_already_admin", c.get("roles_already_admin", 0), "roles that are already "
             "administrative", False),
            ("roles_reachable_from_outside", c.get("roles_reachable_from_outside", 0),
             "of those, assumable from outside the account", True)))

    rows = []
    for row in summary["findings"]:
        colour = {"critical": "var(--crit)", "high": "var(--high)",
                  "info": "var(--muted)"}.get(row["severity"], "var(--gap)")
        extra = ""
        if row.get("escalation"):
            extra = ("<ul class='muted' style='font-size:.78rem;margin:.3rem 0 0 1rem'>"
                     "%s</ul>" % "".join("<li>%s</li>" % E(r)
                                         for r in row["escalation"][:6]))
        rows.append("<div style='border-left:3px solid %s;padding:.35rem 0 .35rem "
                    ".6rem;margin-bottom:.45rem'><b class='mono'>%s</b> "
                    "<span style='font-size:.85rem'>%s</span>%s</div>"
                    % (colour, E(row["user"]), _why(row["why"]), extra))
    found = ("".join(rows) if rows else
             "<p class='muted' style='font-size:.85rem;margin:0'>Every user has "
             "an MFA device, or has no credential that MFA would guard. That is "
             "a real negative — the devices and keys were read, not assumed.</p>")

    admin = ""
    if summary.get("roles_already_admin"):
        rows_admin = summary["roles_already_admin"]
        names = ", ".join(E(as_text(r.get("name"))) for r in rows_admin[:8])
        admin = ("<p class='muted' style='font-size:.8rem;margin:.6rem 0 0'>"
                 "<b>%d role(s)</b> are already administrative — they hold a "
                 "wildcard action, so there is nothing for them to escalate "
                 "to: <span class='mono'>%s</span>%s. That is a fact about how "
                 "the account is built, not a privilege-escalation path.</p>"
                 % (len(rows_admin), names,
                    " and more" if len(rows_admin) > 8 else ""))
    outside = _role_cards(summary.get("role_findings") or [])
    esc = ""
    if summary["roles_with_escalation"]:
        names = ", ".join(
            "%s <span class='muted'>(%s)</span>"
            % (E(as_text(r.get("name"))), E(reach_words(r)))
            for r in summary["roles_with_escalation"][:10])
        esc = ("<p class='muted' style='font-size:.8rem;margin:.6rem 0 0'>"
               "<b>%d role(s)</b> carry a permission that can grant more than "
               "they already hold: <span class='mono'>%s</span>%s. A role is "
               "only a path for whoever can assume it.</p>"
               % (len(summary["roles_with_escalation"]), names,
                  " and more" if len(summary["roles_with_escalation"]) > 10 else ""))

    caveats = "".join("<li>%s</li>" % E(c2) for c2 in iam_caveats(summary))
    return (_partial_notice(row)
            + "<h2 style='margin:1.2rem 0 .3rem'>Who can do what</h2>"
            "<p class='muted' style='font-size:.82rem;margin:0 0 .6rem'>"
            "%d principal(s) and %d policy(ies), read in %d API call(s). MFA "
            "and access keys are read per user; no credential report is "
            "generated, because generating one would be a write.</p>"
            "<div class='grid cols-3' style='margin-bottom:.7rem'>%s</div>"
            "<div class='card tight'>%s%s</div>"
            "<div class='card tight' style='border-left:4px solid var(--gap);"
            "margin-top:.6rem'><h3 style='margin:0 0 .35rem'>What this does not "
            "settle</h3><ul class='muted' style='font-size:.82rem;margin:0 0 0 "
            "1rem'>%s</ul></div>"
            % (c["users"] + c["roles"] + c["groups"], c["policies"],
               summary["api_calls"], tiles, found, outside + esc + admin,
               caveats))


def cloud_change_panel(root: str) -> str:
    """What changed between the two newest readings.

    Named things first, counts second. A count that moved is a question — why
    are there three more subnets? — and a named thing that appeared or vanished
    is usually the answer. Most diffs are shown the other way round, which is
    why most diffs need a second tool to interpret."""
    # A comparison is only as good as the two readings under it. A run whose
    # inventory stage failed is not a reading, so it is not one of the two --
    # otherwise "nothing changed" would be measured against an empty payload
    # and every resource in the account would read as vanished.
    pairs = []
    for man in list_runs(root):
        if man.get("service") != "cloudinventory":
            continue
        row = _ledger_row(man, "cloudinv")
        if row is None or row.get("status") != "ok":
            continue
        inv = _read_raw(man, "cloud-inventory.json")
        if inv:
            pairs.append((man, inv, _read_raw(man, "cloud-enablement.json")))
        if len(pairs) == 2:
            break
    if len(pairs) < 2:
        return ("<h2 style='margin:1.2rem 0 .3rem'>What changed since the last "
                "reading</h2><div class='card tight'><p class='muted' style="
                "'font-size:.82rem;margin:0'>Only one reading is on record, so "
                "there is nothing to compare it against yet. Run the inventory "
                "again and this fills in — a second reading is what turns a "
                "snapshot into a trend.</p></div>")
    (new_man, new_inv, new_en), (old_man, old_inv, old_en) = pairs
    diff = compare_readings(old_inv, new_inv, old_en, new_en)

    def pill(text, weight=""):
        colour = "var(--high)" if weight == "warn" else "var(--muted)"
        return ("<span class='pill' style='border:1px solid %s;color:%s;"
                "font-size:.75rem'>%s</span>" % (colour, colour, E(text)))

    blocks = []
    if diff["watching"]:
        blocks.append("<div style='display:flex;flex-wrap:wrap;gap:.35rem;"
                      "margin-bottom:.5rem'>%s</div>"
                      % "".join(pill("%s in %s: %s → %s%s"
                                     % (r["label"], r["region"], r["before"],
                                        r["after"],
                                        " · %s" % r["why"] if r["why"] else ""),
                                     r["weight"])
                                for r in diff["watching"]))
    named = ([("appeared", r) for r in diff["appeared"][:12]]
             + [("vanished", r) for r in diff["vanished"][:12]])
    if named:
        blocks.append("<div style='display:flex;flex-wrap:wrap;gap:.35rem;"
                      "margin-bottom:.5rem'>%s</div>"
                      % "".join(pill("%s: %s %s in %s"
                                     % (word, r["kind"], r["id"], r["region"]))
                                for word, r in named))
    extra = len(diff["appeared"]) + len(diff["vanished"]) - 24
    if extra > 0:
        blocks.append("<p class='muted' style='font-size:.78rem;margin:0 0 .5rem'>"
                      "… and %d more named change(s); the evidence has them all."
                      "</p>" % extra)
    if diff["moved"]:
        blocks.append("<div style='display:flex;flex-wrap:wrap;gap:.35rem'>%s</div>"
                      % "".join(pill("%s: %d → %d (%+d)"
                                     % (r["label"], r["before"], r["after"],
                                        r["delta"]), r["weight"])
                                for r in diff["moved"]))
    if not diff["changes"]:
        blocks.append("<p class='muted' style='font-size:.85rem;margin:0'>"
                      "Nothing changed, over readings that covered the same "
                      "ground both times. That is a result, not an absence of "
                      "one.</p>")
    gaps = ""
    if diff["incomparable"]:
        gaps = ("<details style='margin-top:.6rem'><summary class='muted' "
                "style='font-size:.8rem;cursor:pointer'>%d path(s) could not be "
                "compared — said out loud rather than reported as \u201cno "
                "change\u201d</summary><ul class='muted' style='font-size:.8rem;"
                "margin:.4rem 0 0 1rem'>%s</ul></details>"
                % (len(diff["incomparable"]),
                   "".join("<li>%s</li>" % _why(w) for w in diff["incomparable"])))
    apart = ""
    if diff.get("apart_hours") is not None:
        apart = " · %s apart" % human_hours(diff["apart_hours"])
    return ("<div style='display:flex;justify-content:space-between;"
            "align-items:baseline;flex-wrap:wrap;gap:.6rem;margin:1.2rem 0 .3rem'>"
            "<h2 style='margin:0'>What changed since the last reading</h2>"
            "<span class='muted' style='font-size:.8rem'>%d change(s)%s</span>"
            "</div>"
            "<div class='card tight'>"
            "<p class='muted' style='font-size:.8rem;margin:0 0 .55rem'>"
            "<span class='mono'>%s</span> → <span class='mono'>%s</span>. "
            "A count that moved is a question; a named thing that appeared or "
            "vanished is usually the answer.</p>%s%s</div>"
            % (diff["changes"], apart, E(diff["from"] or old_man["run_id"]),
               E(diff["to"] or new_man["run_id"]), "".join(blocks), gaps))


def _reading_header(summary: dict, man: dict) -> str:
    """Where these numbers came from, said before any of them are shown.

    A figure on a page is worth what the reader knows about its provenance:
    which identity took it, when, and what it cost. And the page must not imply
    it is live — everything below is one saved reading, so it dates itself and
    says how old it is rather than letting a reader assume it is now."""
    age = reading_age(summary)
    who = redact_identifiers(summary.get("read_as") or "")
    bits = ["account <span class='mono'>%s</span>"
            % E(mask_account(summary.get("account")))]
    if who:
        bits.append("read as <span class='mono'>%s</span>" % E(who))
    if summary.get("read_at"):
        bits.append("<span class='mono'>%s</span>" % E(summary["read_at"]))
    if age is not None:
        bits.append("%s ago" % E(human_hours(age)))
    if summary.get("api_calls"):
        bits.append("%d read-only API call(s) in %ss"
                    % (summary["api_calls"], summary.get("elapsed_seconds", 0)))
    stale = ""
    if age is not None and age >= READING_STALE_HOURS:
        # Not an error. An estate changes, and a snapshot cannot know what
        # happened after it was taken — so the page says which estate it is
        # describing rather than quietly describing the wrong one.
        stale = ("<div class='card tight' style='border-left:4px solid var(--gap);"
                 "margin:.5rem 0'><b>This reading is %s old.</b> "
                 "<span class='muted'>An estate changes; a stale snapshot "
                 "describes the estate that was. Take a fresh one with "
                 "<span class='mono'>SQUAWK_CLOUD_ACK=1 squawk.pyz run "
                 "cloudinventory</span>, or with the button above.</span></div>"
                 % E(human_hours(age)))
    return ("<h2 style='margin:0'>What is in this account</h2>"
            "<p class='muted' style='font-size:.82rem;margin:.25rem 0 0'>%s.<br>"
            "Every figure below is from that one saved reading — a page load "
            "costs nothing and dates itself. %d resources across %d of %d "
            "enabled region(s).</p>%s"
            % (" &middot; ".join(bits), summary["resources"],
               summary["regions_read"], summary["regions_enabled"], stale))


def _headline_row(summary: dict) -> str:
    """The few numbers worth reading before the rest of the page."""
    cells = []
    for fact in headline_facts(summary):
        colour = "var(--high)" if (fact["weight"] == "warn"
                                   and fact["value"] not in ("0", "—")) else "inherit"
        cells.append(
            "<div class='card tight'><div style='line-height:1.1'>%s</div>"
            "<div style='font-size:.8rem;margin-top:.2rem'>%s</div>"
            "<div class='muted' style='font-size:.72rem;margin-top:.15rem'>%s</div>"
            "</div>" % (_num(HEADLINE_DRILL.get(fact["key"], fact["key"]),
                             fact["value"], colour, "700", "1.5rem"),
                        E(fact["label"]), E(fact["note"])))
    return ("<div class='grid cols-3' style='margin:.7rem 0'>%s</div>"
            % "".join(cells))


def human_hours(hours: float) -> str:
    """An age a person reads without arithmetic: 40m, 3.2h, 4d."""
    if hours < 1:
        return "%dm" % max(1, round(hours * 60))
    if hours < 48:
        return "%.1fh" % hours
    return "%.1fd" % (hours / 24.0)


def _inv_tile(domain: dict) -> str:
    """One domain tile: the headline, then each count with its meaning.

    Counts that carry a security meaning are coloured; the rest are plain
    facts. A tile of twelve identical grey numbers is a table pretending to be
    a dashboard."""
    rows = []
    for item in domain["items"]:
        weight = item["weight"] if item["count"] else ""
        colour = {"warn": "var(--high)", "note": "var(--accent)"}.get(weight,
                                                                     "inherit")
        rows.append(
            "<div style='display:flex;justify-content:space-between;gap:.8rem;"
            "align-items:baseline;padding:.22rem 0'>"
            "<span class='muted' style='font-size:.8rem'>%s</span>%s</div>"
            % (E(item["label"]),
               _num(item["key"], item["count"], colour,
                    "700" if weight == "warn" else "500")))
    return ("<div class='card tight'><h3 style='margin:0 0 .45rem'>%s</h3>%s</div>"
            % (E(domain["label"]), "".join(rows)))


def cloud_inventory_panel(root: str) -> "Tuple[str, dict]":
    """What the account actually contains, from the newest inventory read.

    The first real run examined 318 resources across 17 regions and the screen
    said "0 findings" and nothing else. The reasoning had run; the inventory it
    reasoned over was in a raw file nobody opens. An operator asking "what is
    out there" was handed a zero."""
    data, row, man = _cloud_reading(root, "cloudinv")
    if data is None:
        return _unavailable("What is in this account", row, man), {}
    summary = inventory_summary(data)
    tiles = "".join(_inv_tile(d) for d in summary["domains"])

    ports = summary["world_open_ports"]
    ports_line = ""
    if ports:
        ports_line = ("<p class='muted' style='font-size:.8rem;margin:.6rem 0 0'>"
                      "Admitted from anywhere, somewhere in the account: "
                      "<span class='mono'>%s</span></p>"
                      % E(", ".join(ports[:12])))

    head = _reading_header(summary, man or {})
    facts = _headline_row(summary)

    # Regions that hold only the default VPC are one fact, not sixteen rows.
    rows, default_only = split_regions(summary)
    body = "".join(
        "<tr><td class='mono'>%s</td><td>%d</td><td>%s</td><td>%d</td>"
        "<td>%s</td><td>%s</td><td>%s</td></tr>"
        % (E(r["region"]), r["vpcs"],
           _count_cell(r["public_subnets"], r["subnets"], "note"),
           r["groups"],
           _count_cell(r["risky_open_groups"], r["world_open_groups"]),
           _count_cell(r["public_instances"], r["running"]),
           ("<span class='mono' style='color:var(--gap)'>%s</span>"
            % E(", ".join(r["unreadable"]))) if r["unreadable"]
           else "<span class='muted'>&mdash;</span>")
        for r in rows)
    if default_only:
        body += ("<tr><td class='muted' colspan='7' style='padding-top:.55rem'>"
                 "<b>%d region(s)</b> hold nothing but the default VPC AWS "
                 "created there — no instances, no interfaces, nothing admitted "
                 "on a risky port: <span class='mono' style='font-size:.78rem'>"
                 "%s</span></td></tr>"
                 % (len(default_only),
                    E(", ".join(r["region"] for r in default_only))))
    if not body:
        body = ("<tr><td colspan='7' class='muted'>Every region read came back "
                "empty. That is a real answer — it is what an account with no "
                "networking in those regions looks like.</td></tr>")
    table = ("<div class='card tight'><div style='overflow-x:auto'><table>"
             "<thead><tr><th>Region</th><th>VPCs</th><th>Public subnets</th>"
             "<th>Groups</th><th>Open to the world, on a risky port</th>"
             "<th>Reachable instances</th><th>Could not read</th></tr></thead>"
             "<tbody>%s</tbody></table></div>%s</div>" % (body, ports_line))

    notes = inventory_notes(summary)
    worth = ""
    if notes:
        worth = ("<div class='card tight' style='border-left:4px solid var(--high)'>"
                 "<h3 style='margin:0 0 .35rem'>Worth knowing</h3>"
                 "<ul style='font-size:.85rem;margin:0 0 0 1rem'>%s</ul></div>"
                 % "".join("<li>%s</li>" % E(n) for n in notes))
    caveats = "".join("<li>%s</li>" % E(c) for c in inventory_caveats(summary))
    limits = ("<div class='card tight' style='border-left:4px solid var(--gap)'>"
              "<h3 style='margin:0 0 .35rem'>What this does not tell you</h3>"
              "<ul class='muted' style='font-size:.82rem;margin:0 0 0 1rem'>"
              "%s</ul></div>" % caveats)

    # The notice every other panel carries above its numbers when a read was
    # refused; these two did not (review 3, R-46).
    return ("%s%s%s<div class='grid cols-4' style='margin:.7rem 0'>%s</div>%s%s%s"
            % (_partial_notice(row), head, facts, tiles, table, worth, limits),
            summary)


def _count_cell(n: int, of: "Optional[int]", weight: str = "warn") -> str:
    """A count with its denominator, coloured by what a non-zero one means.
    `4 of 12` says more than `4`, and a zero stays grey either way."""
    tail = "<span class='muted'> of %d</span>" % of if of else ""
    if not n:
        return "<span class='muted'>0%s</span>" % (" of %d" % of if of else "")
    colour = "var(--high)" if weight == "warn" else "var(--accent)"
    return ("<span class='mono' style='font-weight:%s;color:%s'>%d</span>%s"
            % ("700" if weight == "warn" else "600", colour, n, tail))


def _panel_failed(label: str, exc: BaseException) -> str:
    """One panel, replaced by what went wrong with it.

    A reader that raises should not be possible -- TestACloudReaderNeverRaises
    holds the readers to that. This is the second layer, for the case the
    corpus did not think of: one unreadable evidence file costs its own panel
    and nothing else. It names the exception type rather than swallowing it,
    because a panel that silently disappeared would be the substitution I1
    exists to refuse (review R-14).
    """
    LOG.warning("CLOUD panel %s raised %s: %s", label, type(exc).__name__, exc)
    return ("<h2 style='margin:1.2rem 0 .3rem'>%s</h2>"
            "<div class='card tight' style='border-left:4px solid var(--gap)'>"
            "<b>This reading could not be read.</b> <span class='muted'>The "
            "panel raised <span class='mono'>%s</span> while reading its "
            "evidence file — most likely a truncated or hand-edited one. The "
            "rest of this page is unaffected, and this section is missing "
            "rather than empty: nothing here is a statement that there is "
            "nothing to find.</span></div>"
            % (E(label), E(type(exc).__name__)))


def _isolated(label: str, panel: "Callable[..., str]", *args: object) -> str:
    """Render one panel, or say why it could not be rendered."""
    try:
        return panel(*args)
    except Exception as exc:
        return _panel_failed(label, exc)


def _isolated_pair(label: str, panel: "Callable[..., Tuple[str, dict]]",
                   *args: object) -> "Tuple[str, dict]":
    """The same, for the one panel that also returns a summary its siblings
    need. They get an empty one, and each says its own piece about it."""
    try:
        return panel(*args)
    except Exception as exc:
        return _panel_failed(label, exc), {}


def view_cloud(root: str) -> str:
    """The cloud page: who the credential chain resolves to, whether a live
    query is acknowledged, and what the last Security Hub reads found. It
    names the identity before anything is queried (credential rule 3) and
    never shows an empty account as clean."""
    ident, why = aws_identity()
    acked, ack_reason = cloud_target_ok()
    if ident:
        who = ("<div class='card tight' style='border-left:4px solid var(--ok)'>"
               "<b>Identity:</b> <span class='mono'>%s</span> "
               "<span class='muted'>account %s, from your AWS credential chain "
               "(AWS_PROFILE / ~/.aws). Squawk holds no credential.</span></div>"
               % (E(redact_identifiers(ident["Arn"])), E(mask_account(ident["Account"]))))
    else:
        who = ("<div class='card tight' style='border-left:4px solid var(--gap)'>"
               "<b>No AWS identity.</b> <span class='muted'>%s. Point AWS_PROFILE at "
               "a read-only identity (SecurityAudit / ViewOnlyAccess) and reload.</span>"
               "</div>" % _why(why))
    ack = ("<div class='card tight' style='border-left:4px solid %s'><b>%s</b> "
           "<span class='muted'>%s</span></div>"
           % ("var(--ok)" if acked else "var(--gap)",
              "Live query acknowledged." if acked else "Live query not acknowledged.",
              E(ack_reason)))
    def _launch(service: str, label: str) -> str:
        if not (ident and acked):
            hint = ""
            if ident and not acked:
                # The usual case, and it used to read like a dead end: the
                # acknowledgement is an environment variable, and the SERVER
                # is the process that needs it -- setting it in the shell that
                # runs the CLI does nothing for a server started without it.
                hint = ("<br>The server process is the one that needs it: "
                        "<span class='mono'>SQUAWK_CLOUD_ACK=1 python3 "
                        "squawk.pyz serve</span>, or run it from the terminal.")
            return ("<p class='muted' style='font-size:.82rem;margin-top:.6rem'>A "
                    "read needs both an identity and the acknowledgement above.%s"
                    "</p>" % hint)
        return ("<form method='post' action='/run' style='margin-top:.6rem'>"
                "<input type='hidden' name='service' value='%s'>"
                "<input type='hidden' name='target' value='credential-chain'>"
                "<button class='btn' type='submit'>%s %s as %s</button></form>"
                % (E(service), icon("cloud"), E(label),
                   E(mask_account(ident["Account"]))))
    launch = _launch("cloudaws", "Read Security Hub")
    launch_inv = _launch("cloudinventory", "Read the account's resources")
    # Both cloud services, not only Security Hub. The inventory read is the one
    # that works when Security Hub is off, so a page that listed only Hub runs
    # would hide the answer an operator came here for.
    cloud_services = {"cloudaws": "Security Hub", "cloudinventory": "Inventory"}
    runs = [m for m in list_runs(root) if m.get("service") in cloud_services]
    if runs:
        rows = "".join(
            "<tr><td class='muted' style='white-space:nowrap'>%s</td>"
            "<td>%s</td><td class='mono'>account %s</td><td>%s</td><td>%s</td>"
            "<td><a href='/findings?run=%s'>findings &rarr;</a> &middot; "
            "<a href='/priority?run=%s'>priority &rarr;</a></td></tr>"
            % (E(_fmt_run_time(m["run_id"])),
               E(cloud_services.get(m.get("service", ""), "")),
               E(mask_account(m.get("target", ""))),
               " ".join(sev_pill(sv, m.get("severities", {}).get(sv, 0))
                        for sv in SEVERITY_ORDER
                        if m.get("severities", {}).get(sv))
               or _cloud_found(m),
               _cloud_doubt(m), E(m["run_id"]), E(m["run_id"]))
            for m in runs[:12])
        history = ("<div class='card'><h3>Cloud reads</h3><div style="
                   "'overflow-x:auto'><table><thead><tr><th>When</th><th>Read</th>"
                   "<th>Account</th><th>Found</th><th>Could not answer</th><th></th>"
                   "</tr></thead><tbody>%s</tbody></table></div></div>" % rows)
    else:
        history = empty_state("cloud", "No cloud reads yet",
                              "A read lands here with the account it was made as, "
                              "and its findings rank on the Priority page like any "
                              "other run.")
    estate = _isolated("this account's estate", cloud_estate_banner, root)
    inventory_panel, inv_summary = _isolated_pair(
        "What is in this account", cloud_inventory_panel, root)
    inventory_panel = estate + inventory_panel
    for label, panel, args in (
            ("What is watching this account", cloud_watching_panel,
             (root, inv_summary)),
            ("Where the data is", cloud_storage_panel, (root,)),
            ("Where traffic arrives", cloud_frontdoor_panel, (root,)),
            ("What runs in containers", cloud_containers_panel,
             (root, inv_summary)),
            ("Queues, topics, secrets and images", cloud_dataservices_panel,
             (root,)),
            ("What the internet can talk to", cloud_edge_panel,
             (root, inv_summary)),
            ("Who can do what", cloud_iam_panel, (root,)),
            ("What AWS says is reachable from outside", cloud_analyzer_panel,
             (root,)),
            ("What changed since the last reading", cloud_change_panel,
             (root,))):
        inventory_panel += _isolated(label, panel, *args)
    return (
        "<h1>Cloud</h1><p class='sub'>Two different questions. <b>The account's "
        "own resources</b> — what exists, what the internet can reach, and which "
        "combinations of ordinary settings add up to something dangerous — read "
        "through the API whether or not the account runs any security service. "
        "And <b>what the account already knows about itself</b>, from Security "
        "Hub. Both read-only, as the identity in your credential chain.</p>%s%s"
        "<div class='cols-2'>"
        "<div class='card'><h3>Read the account's resources</h3>"
        "<p class='muted' style='font-size:.82rem'>%s</p>%s</div>"
        "<div class='card'><h3>Read Security Hub</h3><p class='muted' style="
        "'font-size:.82rem'>%s</p>%s</div></div>%s%s"
        % (who, ack, E(SERVICES["cloudinventory"].not_covered), launch_inv,
           E(SERVICES["cloudaws"].not_covered), launch,
           inventory_panel, history))


def view_triage(root: str, run_id: Optional[str]) -> str:
    """Group findings by DECISION, not by row: one advisory affecting four
    packages is one decision showing '4 items'. Anything matching a posted
    baseline is hidden as already filed, with a count and a way to show it."""
    runs = list_runs(root)
    if not runs:
        return ("<h1>Triage</h1><p class='sub'>Decide once per advisory, not "
                "once per row.</p>"
                + empty_state("triage", "Nothing to triage",
                              "Run a scan first — its findings queue up here.",
                              "<a class='btn' href='/scan'>Run a scan</a>"))
    # An unknown run id is a bad request, not a reason to show a different run.
    # Silently substituting one made the header assert a run nobody asked for.
    man = next((m for m in runs if m["run_id"] == run_id), None) if run_id else runs[0]
    if man is None:
        return ("<h1>No such run</h1>" + empty_state(
            "findings", "That run id is not on record",
            "The id in the address does not match any run in this evidence "
            "root. Nothing was substituted for it.",
            "<a class='btn' href='%s'>Newest run</a>" % '/triage'))
    findings = load_findings(man["_dir"])
    baseline = baseline_identity_set(root)
    # What has been decided about these findings, from the ledger: every mark
    # ever recorded for this target, latest per identity.
    cur = current_decisions(root, man.get("target", ""))

    # decision key: the advisory/rule (first identity segment) per scanner
    decisions: Dict[Tuple[str, str], dict] = {}
    for f in findings:
        key = (f["scanner"], rule_of(f))
        d = decisions.setdefault(key, {
            "scanner": f["scanner"], "rule": key[1], "title": f["title"],
            "severity": f["severity"], "items": [], "filed": 0})
        d["items"].append(f)
        if SEVERITY_ORDER.index(f["severity"]) < SEVERITY_ORDER.index(d["severity"]):
            d["severity"] = f["severity"]
        if f["identity"] in baseline.get(f["scanner"], set()):
            d["filed"] += 1

    ordered = sorted(decisions.values(), key=lambda d: (
        SEVERITY_ORDER.index(d["severity"]), -len(d["items"])))
    filed_hidden = sum(1 for d in ordered if d["filed"] == len(d["items"]))

    picker = "".join(
        "<option value='%s'%s>%s · %s · %s</option>"
        % (E(m["run_id"]), " selected" if m["run_id"] == man["run_id"] else "",
           E(_short_target(m.get("target", ""))), E(m.get("service_label", "")),
           E(_fmt_run_time(m["run_id"])))
        for m in runs)

    payload = json.dumps([
        {"scanner": d["scanner"], "rule": d["rule"], "title": d["title"],
         "severity": d["severity"], "n": len(d["items"]),
         "filed": d["filed"] == len(d["items"]),
         "ids": [f["identity"] for f in d["items"]],
         "state": summarize([cur.get((d["scanner"], f["identity"])) for f in d["items"]]),
         "paths": sorted({f["path"] for f in d["items"] if f["path"]})[:6],
         # What a reader needs to decide, not just where it is. Expanding a row
         # used to show a list of bare paths, which is the finding without the
         # reason for it: a finding with no fix line is a complaint, and one
         # with no evidence is an assertion.
         "what": _first_of(d["items"], ("description", "what")),
         "fix": _first_of(d["items"], ("remediation", "fix", "solution")),
         "evidence": _first_of(d["items"], ("evidence", "attack", "code")),
         "ref": _first_of(d["items"], ("reference", "url"))}
        for d in ordered])

    sev_json = json.dumps({s: SEV_COLORS[s] for s in SEVERITY_ORDER})
    marks_json = json.dumps(SEV_MARKS)

    filed_banner = (
        "<div class='banner'>%d decision(s) match the posted baseline and are "
        "hidden as <b>already filed</b>. <a href='#' id='showfiled'>Show them "
        "anyway</a>. <span class='muted'>A match means this exact identity was "
        "filed — not necessarily from this target.</span></div>" % filed_hidden
        if filed_hidden else "")

    return (
        "<h1>Triage</h1>"
        "<p class='sub'>Run: <b>%s</b> &middot; %s &middot; %s</p>"
        "<p class='sub'>One row per decision. <span class='mono'>j/k</span> move · "
        "<span class='mono'>x</span> select · <span class='mono'>a</span> all open · "
        "<span class='mono'>r</span> reviewed · <span class='mono'>f</span> flagged · "
        "<span class='mono'>s</span> skipped · <span class='mono'>o</span> reopen · "
        "<span class='mono'>n</span> note. Every mark is recorded in the evidence "
        "store with who, when and why, and shows on every later run of this "
        "target. The markdown is an export of that record.</p>"
        "<form method='get' action='/triage' class='card tight' "
        "style='margin-bottom:1rem'>"
        "<select name='run' onchange='this.form.submit()'>%s</select> "
        "<button type='button' class='btn ghost' id='finish'>Finish → markdown"
        "</button></form>%s"
        "<div class='banner' id='dmsg' style='display:none'></div>"
        "<div class='card tight'><table id='tq'><thead><tr><th></th>"
        "<th>Severity</th><th>Decision</th><th>Items</th><th>Status</th></tr>"
        "</thead><tbody></tbody></table></div>"
        "<div class='card' id='out' style='display:none'><h3>Paste-ready "
        "report</h3><textarea id='md' class='mono' style='width:100%%;"
        "min-height:220px;background:var(--panel-2);color:var(--ink);"
        "border:1px solid var(--line-2);border-radius:8px;padding:.7rem'>"
        "</textarea></div>"
        "<script>\n"
        "var DECISIONS=%s,SEV=%s,MARKS=%s,RUN=%s;\n"
        "var showFiled=false,cur=0,sel={},expanded={};\n"
        "function key(d){return d.scanner+'|'+d.rule}\n"
        "function visible(){return DECISIONS.filter(function(d){"
        "return showFiled||!d.filed})}\n"
        "function fail(msg){var m=document.getElementById('dmsg');"
        "m.textContent='Not recorded: '+msg;m.style.display='block'}\n"
        "function post(d,st,note){var body='run='+encodeURIComponent(RUN)"
        "+'&scanner='+encodeURIComponent(d.scanner)+'&rule='+encodeURIComponent(d.rule)"
        "+'&status='+encodeURIComponent(st)+'&note='+encodeURIComponent(note||'')"
        "+'&ids='+encodeURIComponent(JSON.stringify(d.ids));"
        "fetch('/decide',{method:'POST',credentials:'same-origin',"
        "headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})"
        ".then(function(r){return r.json().then(function(j){return [r.status,j]})})"
        ".then(function(x){if(x[0]!==200||!x[1].ok){"
        "fail((x[1]&&x[1].error)||('HTTP '+x[0]));return}"
        "d.state=x[1].state;document.getElementById('dmsg').style.display='none';"
        "render()}).catch(function(e){fail(String(e))})}\n"
        "function pill(s){var c=SEV[s]||'var(--info)';"
        "var soft=\"color-mix(in srgb,\"+c+\" 13%%,transparent)\";"
        "var brd=\"color-mix(in srgb,\"+c+\" 42%%,transparent)\";"
        "return \"<span class='pill' style='color:\"+c+\";background:\"+soft+"
        "\";border-color:\"+brd+\"'>\""
        "+\"<span class='mark' style='background:\"+c+\"'>\""
        "+(MARKS[s]||'?')+'</span>'+s+'</span>'}\n"
        "function esc(s){return String(s).replace(/</g,'&lt;')}\n"
        "function when(at){return at?at.slice(0,4)+'-'+at.slice(4,6)+'-'+at.slice(6,8)"
        "+' '+at.slice(9,11)+':'+at.slice(11,13)+'Z':''}\n"
        "function stcell(d){var s=d.state||{status:'open'};var t=s.status;"
        "if(t==='partial')t=s.latest+' '+s.decided+'/'+s.total;"
        "var who=s.who?\"<div class='muted' style='font-size:.7rem'>\"+esc(s.who)"
        "+' · '+esc(when(s.at))+'</div>':'';"
        "var note=s.note?\"<div class='muted' style='font-size:.7rem'>\"+esc(s.note)"
        "+'</div>':'';return \"<span class='mono'>\"+esc(t)+'</span>'+who+note}\n"
        "function render(){var tb=document.querySelector('#tq tbody');"
        "var rows=visible();if(cur>=rows.length)cur=rows.length?rows.length-1:0;"
        "tb.innerHTML=rows.map(function(d,i){"
        "var mark=sel[key(d)]?'&#9632;':'&#9633;';var open=expanded[key(d)];"
        "var main=\"<tr data-i='\"+i+\"' style='cursor:pointer;\"+(i===cur?"
        "'outline:2px solid var(--accent);outline-offset:-2px':'')+\"'>\""
        "+\"<td class='cbx mono' style='cursor:pointer'>\"+mark+'</td>'"
        "+'<td>'+pill(d.severity)+'</td>'"
        "+\"<td><b>\"+(open?'&#9660; ':'&#9654; ')+esc(d.title)+'</b>'"
        "+\"<div class='mono muted' style='font-size:.72rem'>\"+esc(d.scanner)+' · '"
        "+esc(d.rule)+(d.filed?' · already filed':'')+'</div></td>'"
        "+'<td>'+d.n+'</td>'"
        "+'<td>'+stcell(d)+'</td></tr>';"
        "if(!open)return main;"
        "function field(label,val,mono){if(!val)return '';"
        "return \"<div style='margin:.5rem 0'><div class='mono muted' \""
        "+\"style='font-size:.66rem;letter-spacing:.09em;text-transform:uppercase'>\""
        "+label+\"</div><div class='\"+(mono?'mono':'')"
        "+\"' style='font-size:.85rem;max-width:96ch'>\"+esc(val)+'</div></div>'}\n"
        "var items=(d.paths||[]).map(function(p){"
        "return \"<div class='mono' style='font-size:.72rem'>\"+esc(p)+'</div>'})"
        ".join('');if(d.n>(d.paths||[]).length)items+=\"<div class='mono muted' \""
        "+\"style='font-size:.72rem'>+\"+(d.n-(d.paths||[]).length)+' more</div>';"
        "var body=field('What it is',d.what)+field('Recommendation',d.fix)"
        "+field('Evidence',d.evidence,true)+field('Reference',d.ref,true)"
        "+field('Where',null)+\"<div style='margin:.5rem 0'>\""
        "+\"<div class='mono muted' style='font-size:.66rem;letter-spacing:.09em;\""
        "+\"text-transform:uppercase'>Where</div>\"+items+'</div>';"
        "if(!d.what&&!d.fix)body=\"<p class='muted' style='font-size:.82rem'>\""
        "+'This scanner supplied no description or remediation for the finding.'"
        "+'</p>'+body;"
        "return main+\"<tr class='det'><td></td><td colspan='4' \""
        "+\"style='padding-top:.2rem'>\"+body+'</td></tr>'}).join('');"
        "Array.prototype.forEach.call(tb.querySelectorAll('tr[data-i]'),"
        "function(tr){tr.onclick=function(ev){var i=+tr.getAttribute('data-i');"
        "cur=i;var d=visible()[i];"
        "if(ev.target.classList.contains('cbx'))sel[key(d)]=!sel[key(d)];"
        "else expanded[key(d)]=!expanded[key(d)];render()}})}\n"
        "function mark(st){var rows=visible();var any=false;"
        "rows.forEach(function(d){if(sel[key(d)]){post(d,st,'');any=true}});"
        "if(!any&&rows[cur])post(rows[cur],st,'');sel={};render()}\n"
        "function note(){var rows=visible();var d=rows[cur];if(!d)return;"
        "var n=window.prompt('Why? Recorded with your name and the time.',"
        "(d.state&&d.state.note)||'');if(n===null)return;"
        "var st=(d.state&&d.state.status)||'open';"
        "if(st==='partial')st=d.state.latest||'open';post(d,st,n)}\n"
        "document.addEventListener('keydown',function(ev){"
        "if(ev.target.tagName==='TEXTAREA'||ev.target.tagName==='INPUT'"
        "||ev.target.tagName==='SELECT')return;"
        "var rows=visible();"
        "if(ev.key==='j')cur=Math.min(cur+1,rows.length-1);"
        "else if(ev.key==='k')cur=Math.max(cur-1,0);"
        "else if(ev.key==='x'&&rows[cur])sel[key(rows[cur])]=!sel[key(rows[cur])];"
        "else if(ev.key==='a')rows.forEach(function(d){"
        "if(((d.state&&d.state.status)||'open')==='open')sel[key(d)]=true});"
        "else if(ev.key==='r')return mark('reviewed');"
        "else if(ev.key==='f')return mark('flagged');"
        "else if(ev.key==='s')return mark('skipped');"
        "else if(ev.key==='o')return mark('open');"
        "else if(ev.key==='n'){ev.preventDefault();return note()}"
        "else return;ev.preventDefault();render()});\n"
        "var sf=document.getElementById('showfiled');"
        "if(sf)sf.onclick=function(e){e.preventDefault();showFiled=!showFiled;"
        "sf.textContent=showFiled?'Hide them again':'Show them anyway';render()};\n"
        "var finBtn=document.getElementById('finish');"
        "if(finBtn)finBtn.onclick=function(){"
        "var groups={reviewed:[],flagged:[],skipped:[],partial:[],open:[]};"
        "visible().forEach(function(d){groups[(d.state&&d.state.status)||'open'].push(d)});"
        "var md=['# Local scan report — triage of '+RUN,''];"
        "['flagged','reviewed','skipped','partial','open'].forEach(function(g){"
        "if(!groups[g].length)return;md.push('## '+g+' ('+groups[g].length+')','');"
        "groups[g].forEach(function(d){var s=d.state||{};"
        "md.push('- **'+d.severity+'** '+d.title+"
        "' — '+d.scanner+' `'+d.rule+'` ('+d.n+' item'+(d.n>1?'s':'')+')'"
        "+(s.who?' — '+s.status+(s.status==='partial'?' '+s.decided+'/'+s.total:'')"
        "+' by '+s.who+' on '+when(s.at)+(s.note?': '+s.note:''):''));"
        "if(d.what)md.push('  - what: '+d.what);"
        "if(d.fix)md.push('  - recommendation: '+d.fix);"
        "d.paths.forEach(function(p){md.push('  - `'+p+'`')})});md.push('')});"
        "var out=document.getElementById('out');out.style.display='block';"
        "document.getElementById('md').value=md.join('\\n');"
        "document.getElementById('md').focus()};\n"
        "render();\n</script>"
        % (E(_short_target(man.get("target", ""))),
           E(man.get("service_label", "")), E(_fmt_run_time(man["run_id"])),
           picker, filed_banner, payload, sev_json, marks_json,
           json.dumps(man["run_id"])))


def view_baselines(root: str, repo: Optional[str], gh_repo: Optional[str],
                   generate_run: Optional[str], sync_msg: Optional[str]) -> str:
    cache = load_baselines(root)
    runs = list_runs(root)

    status_rows = ""
    if cache.get("scanners"):
        status_rows = (
            "<div class='card'><h3>Pulled baseline — %s issue #%s</h3>"
            "<p class='muted' style='font-size:.8rem'>synced %s · only scanners "
            "whose posted hash reconciles are used; the rest are excluded with "
            "the reason shown</p><table><thead><tr><th>Scanner</th><th>Status</th>"
            "<th>Detail</th></tr></thead><tbody>%s</tbody></table></div>"
            % (E(cache.get("repo", "")), E(str(cache.get("issue", "?"))),
               E(cache.get("synced_at", "")),
               "".join(
                   "<tr><td class='mono'>%s</td><td>%s</td><td class='muted'>%s"
                   "</td></tr>"
                   % (E(t), ("<span class='removed'>hash reconciles</span>"
                             if e["status"] == "ok" else
                             "<span class='added'>unusable</span>"),
                      E(e["reason"]))
                   for t, e in sorted(cache["scanners"].items()))))
    else:
        status_rows = ("<div class='card'><h3>No pulled baseline</h3>"
                       "<p class='muted'>Sync reads issues titled "
                       "'<span class='mono'>%s</span>' from GitHub (read-only, "
                       "via your gh login) so a fresh machine can still diff "
                       "per finding.</p></div>" % E(BASE_TITLE))

    sync_form = (
        "<form method='post' action='/sync-baselines' class='card tight' "
        "style='display:flex;gap:.5rem;align-items:center;flex-wrap:wrap'>"
        "<input type='text' name='gh_repo' value='%s' placeholder='owner/name'>"
        "<button class='btn'>Sync baselines</button>"
        "<span class='muted' style='font-size:.8rem'>read-only — Squawk never "
        "writes to GitHub</span></form>" % E(gh_repo or ""))
    banner = ("<div class='banner'>%s</div>" % E(sync_msg)) if sync_msg else ""

    gen = ["<div class='card'><h3>Publish this run's baseline</h3>"
           "<p class='muted' style='font-size:.85rem'>Generate the comment(s), "
           "then file an issue titled '<span class='mono'>%s</span>' and paste "
           "them onto it in order. Squawk generates but <b>never posts</b> — a "
           "write to a shared repository stays your decision.</p>" % E(BASE_TITLE)]
    if runs:
        opts = "".join("<option value='%s'%s>%s · %s</option>"
                       % (E(m["run_id"]),
                          " selected" if m["run_id"] == generate_run else "",
                          E(_fmt_run_time(m["run_id"])),
                          E(m.get("service_label", "")))
                       for m in runs)
        gen.append("<form method='get' action='/baselines' style='display:flex;"
                   "gap:.5rem;flex-wrap:wrap'><select name='generate'>%s</select>"
                   "<button class='btn ghost'>Generate</button></form>" % opts)
        if generate_run:
            man = next((m for m in runs if m["run_id"] == generate_run), None)
            if man:
                for i, comment in enumerate(generate_baseline_comments(man["_dir"]), 1):
                    gen.append(
                        "<h3 style='margin-top:1rem'>Comment %d</h3>"
                        "<textarea readonly class='mono' style='width:100%%;"
                        "min-height:160px;background:var(--panel-2);"
                        "color:var(--ink);border:1px solid var(--line-2);"
                        "border-radius:8px;padding:.7rem'>%s</textarea>"
                        % (i, E(comment)))
    else:
        gen.append("<p class='muted'>No runs yet.</p>")
    gen.append("</div>")

    return ("<h1>Baselines</h1><p class='sub'>Per-finding baselines posted to a "
            "GitHub issue let a fresh machine diff against what is already "
            "filed. The truncation guard means a partial set is rejected, never "
            "read as resolved findings.</p>%s%s%s%s"
            % (banner, sync_form, status_rows, "".join(gen)))


# --------------------------------------------------------------------------- #
# HTTP server (loopback only)
# --------------------------------------------------------------------------- #


def reload_interval(elapsed: float) -> int:
    """How often a running job's page reloads itself, in seconds.

    A forty-minute probe reloaded this page twelve hundred times at two
    seconds apiece, each one a full render. The first half-minute is when an
    operator is watching closely; after that a slower beat says the same thing
    for a fraction of the work.

    A function rather than an expression inside the handler, because the only
    test the backoff had was one that searched the handler's SOURCE for the
    literals -- which a comment satisfies, and which says nothing about the
    number the page actually carries (review R-17)."""
    if elapsed < 30:
        return 2
    if elapsed < 300:
        return 5
    return 15


def make_handler(evidence_root: str, repo: Optional[str]):

    class Handler(BaseHTTPRequestHandler):
        server_version = "Squawk/2"

        def log_message(self, fmt, *a) -> None:
            # Previously this was `pass`, so nothing the server did was
            # recorded. Requests go to the log file instead of the console:
            # quiet for the operator, but auditable afterwards.
            try:
                LOG.info("http %s - %s", self.address_string(), fmt % a)
            except Exception as exc:
                # A logging failure must not break the request — but it must
                # not be silent either, or the log goes quiet and the tool
                # still looks healthy.
                sys.stderr.write("squawk: request log failed: %s\n" % exc)

        def _send(self, body: bytes, code: int = 200,
                  ctype: str = "text/html; charset=utf-8") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _ctx(self) -> str:
            n = count_runs(evidence_root)
            return ("<span class='lbl'>Evidence</span>"
                    "<span class='path mono' title='%s'>%s</span>"
                    "<span class='sep'>·</span><b>%d</b> runs"
                    "<span class='sep'>·</span>"
                    "<span class='badge' title='Bound to 127.0.0.1 — never "
                    "reachable off this machine'>loopback only</span>"
                    % (E(evidence_root), E(evidence_root), n))

        def _host_ok(self) -> bool:
            """Refuse any request whose Host header is not this machine's
            loopback, GET included.

            The bind is loopback, but a browser that has been DNS-rebound to
            127.0.0.1 arrives here carrying `Host: attacker.example:8787`, and
            a page from that origin is then same-origin with Squawk: it can
            read every finding and POST a scan at anything on the LAN, and
            the Origin check below passes it, because Origin and Host are
            both the attacker's. Reproduced against a live server with curl
            before this method existed. 421 is the code for exactly this."""
            if host_is_loopback(self.headers.get("Host", "")):
                return True
            LOG.warning("REFUSED non-loopback Host: host=%s path=%s",
                        self.headers.get("Host", "-"), urlparse(self.path).path)
            self._send(page("Refused", empty_state(
                "shield", "Request refused",
                "This request named a host that is not this machine. Squawk "
                "answers only to its own loopback address; a browser reaching "
                "it under another name has been redirected to it, and it does "
                "not answer that."), "", ""), 421)
            return False

        def do_GET(self) -> None:
            if not self._host_ok():
                return
            # A view that raises used to reach the base handler unguarded, which
            # sent a blank 500 to the browser and a traceback to the terminal.
            # That is the web version of this tool's cardinal sin: a page that
            # failed looking like a page with nothing on it. Surface the error
            # instead, so the next failure names its cause rather than blanking.
            try:
                self._route()
            except Exception as exc:  # a view crash must be shown, not hidden
                import traceback
                LOG.error("view crashed for %s: %s", self.path, exc)
                tb = html.escape(traceback.format_exc())
                body = ("<h1>This page hit an error</h1>"
                        "<p class='sub'>The view raised rather than rendering. "
                        "This is a bug in Squawk, not in your data. The detail "
                        "below is what to send.</p>"
                        "<pre style='white-space:pre-wrap;overflow:auto;"
                        "background:var(--panel);padding:1rem;border-radius:6px;"
                        "font-size:.8rem'>%s</pre>" % tb)
                try:
                    self._send(page("Error", body, "", self._ctx()), 500)
                except Exception:  # last resort if even the shell fails
                    self._send(("<pre>%s</pre>" % tb).encode("utf-8"), 500)

        def _route(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            ctx = self._ctx()
            if path in ("/", "/overview"):
                self._send(page("Overview", view_overview(evidence_root),
                                "overview", ctx))
            elif path in ("/scan", "/kiosk"):
                self._send(page("Run a scan",
                                view_scan(evidence_root, repo,
                                          qs.get("browse", [None])[0]),
                                "scan", ctx))
            elif path == "/estate":
                self._send(page("Estate",
                                view_estate(evidence_root,
                                            {k: v[0] for k, v in qs.items()}),
                                "estate", ctx))
            elif path == "/findings":
                self._send(page("Findings",
                                view_findings(evidence_root,
                                              qs.get("run", [None])[0],
                                              qs.get("sev", [None])[0],
                                              qs.get("scanner", [None])[0],
                                              qs.get("where", [None])[0]),
                                "findings", ctx))
            elif path == "/cloud/detail":
                self._send(page("Cloud detail",
                                view_cloud_detail(evidence_root,
                                                  qs.get("what", [""])[0]),
                                "cloud", ctx))
            elif path == "/history":
                self._send(page("History", view_history(evidence_root),
                                "history", ctx))
            elif path == "/compare":
                self._send(page("What changed",
                                view_compare(evidence_root,
                                             qs.get("run", [None])[0]),
                                "history", ctx))
            elif path == "/priority":
                self._send(page("Priority",
                                view_priority(evidence_root,
                                              qs.get("run", [None])[0]),
                                "priority", ctx))
            elif path == "/intel":
                if qs.get("scope", [""])[0] == "feed":
                    self._send(page("What is being exploited",
                                    view_intel_feed(evidence_root),
                                    "intel", ctx))
                else:
                    self._send(page("Threat intel",
                                    view_intel(evidence_root,
                                               qs.get("cve", [None])[0]),
                                    "intel", ctx))
            elif path == "/cloud":
                self._send(page("Cloud", view_cloud(evidence_root), "cloud", ctx))
            elif path == "/triage":
                self._send(page("Triage",
                                view_triage(evidence_root,
                                            qs.get("run", [None])[0]),
                                "triage", ctx))
            elif path == "/baselines":
                gh_repo = resolve_gh_repo(None, repo)
                self._send(page("Baselines",
                                view_baselines(evidence_root, repo, gh_repo,
                                               qs.get("generate", [None])[0],
                                               qs.get("msg", [None])[0]),
                                "baselines", ctx))
            elif path.startswith("/job/"):
                job = JOBS.get(path.split("/job/")[1])
                if not job:
                    self._send(page("Job", "<h1>Unknown job</h1>", "", ctx), 404)
                    return
                # A forty-minute probe reloaded this page twelve hundred
                # times at two seconds apiece, each one a full render. The
                # first half-minute is when an operator is watching closely;
                # after that a slower beat says the same thing for a fraction
                # of the work.
                secs = reload_interval(job.elapsed())
                refresh = ("<meta http-equiv='refresh' content='%d'>" % secs
                           if job.status == "running" else "")
                self._send(page("Scan", view_job(job, evidence_root), "scan", ctx,
                                head_extra=refresh))
            elif path == "/healthz":
                rec = read_pid_file(evidence_root) or {}
                ver = verify_state(evidence_root)
                body = json.dumps({
                    "ok": True, "pid": os.getpid(), "version": __version__,
                    "runs": len(list_runs(evidence_root)),
                    "jobs_running": sum(1 for j in JOBS.values()
                                        if j.status == "running"),
                    "started_at": rec.get("started_at", ""),
                    # Never verified is reported as "never", not as ok. A health
                    # document that says ok about a check nobody ran is the
                    # exact failure this tool exists to refuse.
                    "verify_status": ver["status"],
                    "verified_at": ver["at"],
                    "verify_summary": ver["summary"],
                    "evidence": evidence_root})
                self._send(body.encode("utf-8"), 200, "application/json")
            else:
                self._send(page("Not found",
                                empty_state("findings", "Not found",
                                            "That page does not exist."),
                                "", ctx), 404)

        def _decide(self, form: Dict[str, List[str]]) -> None:
            """Record one triage decision and answer JSON. It refuses, with the
            reason, anything it could not later stand behind: an unknown run,
            a status outside the vocabulary, or an identity the run did not
            record. Cross-origin posts were already refused above."""
            def reply(code: int, payload: dict) -> None:
                self._send(json.dumps(payload).encode("utf-8"), code, "application/json")
            run_id = (form.get("run", [""])[0] or "").strip()
            man = next((m for m in list_runs(evidence_root) if m["run_id"] == run_id), None)
            if man is None:
                reply(400, {"ok": False, "error": "unknown run %r" % run_id})
                return
            scanner = (form.get("scanner", [""])[0] or "").strip()
            rule = (form.get("rule", [""])[0] or "").strip()
            status = (form.get("status", [""])[0] or "").strip()
            note = (form.get("note", [""])[0] or "").strip()
            try:
                ids = json.loads(form.get("ids", ["[]"])[0] or "[]")
            except ValueError:
                ids = None
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                reply(400, {"ok": False, "error": "ids must be a JSON list of identities"})
                return
            recorded = {f["identity"] for f in load_findings(man["_dir"])
                        if f.get("scanner") == scanner}
            unknown = sorted(set(ids) - recorded)
            if unknown:
                reply(400, {"ok": False, "error": "run %s did not record %s for %s"
                            % (run_id, ", ".join(unknown[:3]), scanner or "?")})
                return
            try:
                ev = record_decision(evidence_root, run_id, man.get("target", ""),
                                     man.get("service", ""), scanner, rule, status,
                                     ids, note=note)
            except ValueError as exc:
                reply(400, {"ok": False, "error": str(exc)})
                return
            cur = current_decisions(evidence_root, man.get("target", ""))
            state = summarize([cur.get((scanner, i)) for i in ev["identities"]])
            reply(200, {"ok": True, "event": ev, "state": state})

        def _origin_ok(self) -> bool:
            """Refuse a cross-origin POST.

            /run spawns scanner subprocesses — and with a url-scope service that
            means active DAST traffic at a target — so a page open in the same
            browser must not be able to trigger one. Loopback binding is the
            main mitigation; this closes the gap it leaves.

            A request carrying NO Origin passes on purpose. This is a
            single-user loopback tool and curl, a script or a cron caller send
            no Origin; breaking every CLI caller to stop a browser is the wrong
            trade. A browser always sends Origin on a cross-site POST, which is
            the case being refused.
            """
            origin = self.headers.get("Origin")
            if not origin:
                return True
            host = self.headers.get("Host", "")
            return origin in ("http://%s" % host, "https://%s" % host)

        def do_POST(self) -> None:
            if not self._host_ok():
                return
            if not self._origin_ok():
                LOG.warning("REFUSED cross-origin POST: path=%s origin=%s",
                            urlparse(self.path).path,
                            self.headers.get("Origin", "-"))
                self._send(page("Refused", empty_state(
                    "shield", "Cross-origin request refused",
                    "This request came from another site. Squawk runs scanners "
                    "and can send live traffic at a target, so it only accepts "
                    "writes from its own pages."), "", ""), 403)
                return
            post_path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(length).decode("utf-8"))
            if post_path == "/sync-baselines":
                gh_repo = (form.get("gh_repo", [""])[0] or "").strip() \
                    or resolve_gh_repo(None, repo)
                if not gh_repo:
                    msg = "no GitHub repo resolved — enter owner/name"
                else:
                    _ok, msg, _cache = sync_baselines(evidence_root, gh_repo)
                self.send_response(303)
                self.send_header("Location", "/baselines?msg=%s"
                                 % msg.replace(" ", "+")[:180])
                self.end_headers()
                return
            if post_path == "/decide":
                self._decide(form)
                return
            if post_path != "/run":
                self._send(page("Not found", "<h1>Not found</h1>", ""), 404)
                return
            service = SERVICES.get(form.get("service", [""])[0])
            target = _posted_target(form)
            if not service:
                self._send(page("Error", "<h1>Unknown service</h1>", ""), 400)
                return
            if service.scope == "repo":
                resolved = resolve_repo(target or repo)
                target, base = resolved or (target or ""), resolved or target
            elif service.scope == "dir":
                base = target
            elif service.scope == "host":
                # The subject is this machine, named as the CLI names it; a
                # typed target would be a lie about what was audited.
                target, base = socket.gethostname(), os.getcwd()
            else:
                base = os.getcwd()
            if not target:
                self._send(page("Error",
                                "<h1>A target is required for this service.</h1>", ""), 400)
                return
            # A rescan of a directory that no longer exists (a temp dir from an
            # earlier run, say) must be refused here, not launched. Launching it
            # ran every scanner against nothing and wrote a gap run that became
            # the target's newest, burying its real history under a phantom.
            if service.scope in ("repo", "dir") and not os.path.isdir(target):
                LOG.warning("REFUSED run: target directory missing path=%s", target)
                self._send(page("Refused", empty_state(
                    "shield", "Target directory no longer exists",
                    "%s is not on disk. It was probably a temporary directory "
                    "from an earlier run. Nothing was scanned and no run was "
                    "recorded, so this target's history is untouched." % target),
                    "scan", self._ctx()), 400)
                return
            if service.scope == "url":
                ok, reason = dast_target_ok(target)
                if ok and probes_a_named_port(service):
                    ok, reason = dast_target_live(target)
                if not ok:
                    self._send(page("Refused", empty_state(
                        "shield", "DAST target refused",
                        "%s Nothing was scanned and no run was recorded." % reason),
                        "scan", self._ctx()), 400)
                    return
            if service.scope == "aws":
                # One live estate, one reader. Two cloud reads at once double
                # the API calls against the same rate limits and each writes a
                # run whose numbers the other's calls moved (review R-15).
                busy = running_job_for_scope("aws")
                if busy is not None:
                    LOG.warning("REFUSED run: a cloud read is already running "
                                "(job %s)", busy.id)
                    self._send(page("Refused", empty_state(
                        "shield", "A cloud read is already running",
                        "Job %s started %s ago and is still reading the "
                        "account. Two reads at once double the API calls "
                        "against the same rate limits, and each would write a "
                        "run whose numbers the other moved. Nothing was read "
                        "and no run was recorded."
                        % (busy.id, human_hours(busy.elapsed() / 3600.0)),
                        "<a class='btn' href='/job/%s'>Watch job %s</a>"
                        % (busy.id, busy.id)),
                        "scan", self._ctx()), 409)
                    return
                ok, reason = cloud_target_ok()
                if not ok:
                    self._send(page("Refused", empty_state(
                        "shield", "Cloud query refused", reason), "scan",
                        self._ctx()), 400)
                    return
                ident, why = aws_identity()
                if not ident:
                    self._send(page("Refused", empty_state(
                        "shield", "No AWS identity", "The credential chain resolved "
                        "to no identity: %s. Nothing was read." % why), "scan",
                        self._ctx()), 400)
                    return
                target = ident["Account"]
                LOG.info("cloud run as %s (account %s)", ident["Arn"], target)
                state, detail = aws_identity_readonly(ident["Arn"])
                if state != "ok":
                    LOG.warning("cloud identity read-only check: %s — %s", state, detail)
            # The profile is read here, before the job exists, so a refused
            # profile is a page that says why and no run at all.
            try:
                profile = profile_for(evidence_root)
            except ProfileError as exc:
                LOG.error("REFUSED run: profile — %s", exc)
                self._send(page("Refused", empty_state(
                    "shield", "Profile refused",
                    "%s. %s Nothing was scanned and no run was recorded."
                    % (exc, PROFILE_REFUSED_NOTE)),
                    "scan", self._ctx()), 400)
                return
            job_id = start_job(service, target, evidence_root, base, profile=profile)
            self.send_response(303)
            self.send_header("Location", "/job/%s" % job_id)
            self.end_headers()

    return Handler


__all__ = [
    'CLOCK_JS',
    'CLOUD_READINGS',
    'CVE_SOURCES',
    'HEADLINE_DRILL',
    'ICONS',
    'PAGE_CSS',
    'SEV_COLORS',
    'SEV_MARKS',
    'STATE_COLOURS',
    'UTC_ALIASES',
    'WORLD_ZONES',
    '_ROLE_CARDS',
    '_SKIP_DIRS',
    '_STATUS_DOT',
    'E',
    '_budget_bar',
    '_chip',
    '_chip_link',
    '_cloud_doubt',
    '_cloud_found',
    '_cloud_reading',
    '_cmp_section',
    '_count_cell',
    '_cve_rows',
    '_cve_source_links',
    '_cve_vendor',
    '_cve_what',
    '_detail_block',
    '_feed_table',
    '_finding_rows',
    '_first_of',
    '_fmt_run_time',
    '_fmt_verify_time',
    '_headline_row',
    '_intel_chip',
    '_intel_detail',
    '_inv_tile',
    '_is_partial',
    '_isolated',
    '_isolated_pair',
    '_ledger_row',
    '_mine',
    '_named_regions',
    '_num',
    '_outside_pairs',
    '_panel',
    '_panel_failed',
    '_partial_notice',
    '_posted_target',
    '_pruned_note',
    '_read_raw',
    '_reading_header',
    '_rel_root',
    '_role_cards',
    '_run_stage_raw',
    '_server_zone',
    '_service_tile',
    '_short_target',
    '_state_pill',
    '_target_options',
    '_target_select',
    '_unavailable',
    '_unavailable_banner',
    '_under_roots',
    '_unreadable_note',
    '_why',
    '_zone_now',
    'canonical_zone',
    'clock_wall',
    'cloud_analyzer_panel',
    'cloud_change_panel',
    'cloud_containers_panel',
    'cloud_dataservices_panel',
    'cloud_edge_panel',
    'cloud_estate_banner',
    'cloud_frontdoor_panel',
    'cloud_iam_panel',
    'cloud_inventory_panel',
    'cloud_storage_panel',
    'cloud_watching_panel',
    'coverage_panel',
    'discover_repos',
    'drill_link',
    'empty_state',
    'human_hours',
    'icon',
    'integrity_block',
    'list_dir',
    'make_handler',
    'page',
    'profile_line',
    'recent_targets',
    'rel_time',
    'reload_interval',
    'rescan_form',
    'resolved_block',
    'risk_trend',
    'run_picker',
    'scan_roots',
    'sev_breakdown',
    'sev_donut',
    'sev_pill',
    'sparkline',
    'squawk_banner',
    'view_baselines',
    'view_cloud',
    'view_cloud_detail',
    'view_compare',
    'view_estate',
    'view_findings',
    'view_history',
    'view_intel',
    'view_intel_feed',
    'view_job',
    'view_overview',
    'view_priority',
    'view_scan',
    'view_triage',
]
