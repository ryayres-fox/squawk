"""Exploitability: CISA KEV and FIRST EPSS, cached with provenance, and the priority ranking."""

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from squawk.core import FEEDS_DIRNAME, LOG, SEVERITY_ORDER, _report, _rows

FEED_STALE_DAYS = 7          # KEV changes weekly or faster; EPSS is daily
EPSS_HOT = 0.10              # EPSS at or above this: likely to be exploited soon
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _fetch_feed(url: str, timeout: int = 90,
                headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[bytes], str]:
    """Fetch a public feed over verified TLS. Unlike the recon probe, which
    accepts self-signed lab certificates on purpose, a feed that ranks findings
    must come from where it claims to, so certificate checking stays on.

    `headers` carries an API key where a source offers one. It rides in a
    header and nowhere else: never on argv, which is visible in the process
    table, and never into a log line or the cache (credential rule 6)."""
    req = urllib.request.Request(url, headers={"User-Agent": "Squawk-feeds"})
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), ""
    except (OSError, ValueError) as exc:
        return None, str(exc)


def _parse_kev(blob: bytes) -> Dict[str, dict]:
    """Every KEV entry, with what the catalogue actually says about it.

    This used to keep two fields, the date and the ransomware flag, because the
    only question asked of it was "is this CVE in my estate exploited". The
    catalogue is about 1,700 entries of what is being exploited in the world,
    and reading two fields out of it makes the other 1,700 rows of general
    intelligence invisible on a machine that has already downloaded them."""
    data = _report(blob.decode("utf-8", "replace"), dict)
    out: Dict[str, dict] = {}
    for v in _rows(data.get("vulnerabilities")):
        cve = str(v.get("cveID", "")).upper()
        if cve:
            out[cve] = {
                "added": str(v.get("dateAdded", "")),
                "ransomware": str(v.get("knownRansomwareCampaignUse", ""))
                .lower() == "known",
                "vendor": str(v.get("vendorProject", "")),
                "product": str(v.get("product", "")),
                "name": str(v.get("vulnerabilityName", "")),
                "summary": str(v.get("shortDescription", ""))[:400],
                "action": str(v.get("requiredAction", ""))[:300],
                "due": str(v.get("dueDate", "")),
                # _rows keeps only dict entries, and KEV's cwes is a list of
                # strings, so routing it through _rows silently produced [].
                "cwes": [str(c) for c in (v.get("cwes") or [])
                         if isinstance(c, str) and c][:4],
            }
    return out


def _parse_epss(text: str) -> Dict[str, Tuple[float, float]]:
    import csv
    import io
    out: Dict[str, Tuple[float, float]] = {}
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            out[str(row.get("cve", "")).upper()] = (float(row["epss"]),
                                                    float(row["percentile"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def update_feeds(root: str) -> Tuple[bool, List[str]]:
    """Refresh both feeds into <evidence>/feeds/ and write a provenance record
    (when, from where, sha256, size, entry count). Returns (all_ok, lines)."""
    import gzip
    fdir = os.path.join(root, FEEDS_DIRNAME)
    try:
        os.makedirs(fdir, exist_ok=True)
        os.chmod(fdir, 0o700)
    except OSError as exc:
        return False, ["feeds: cannot create %s: %s" % (fdir, exc)]
    record: Dict[str, Any] = {"fetched_at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}
    lines: List[str] = []
    ok = True
    for name, url in (("kev", KEV_URL), ("epss", EPSS_URL)):
        blob, err = _fetch_feed(url)
        if blob is None:
            ok = False
            lines.append("  gap  %-5s fetch failed: %s" % (name, err))
            LOG.warning("GAP feed %s fetch failed: %s", name, err)
            continue
        if name == "epss":
            try:
                blob = gzip.decompress(blob)
            except (OSError, EOFError) as exc:
                ok = False
                lines.append("  gap  epss  not gzip: %s" % exc)
                continue
        entries = (len(_parse_kev(blob)) if name == "kev"
                   else len(_parse_epss(blob.decode("utf-8", "replace"))))
        if entries == 0:
            ok = False
            lines.append("  gap  %-5s fetched but parsed to 0 entries" % name)
            LOG.warning("GAP feed %s parsed to 0 entries", name)
            continue
        dest = os.path.join(fdir, "kev.json" if name == "kev" else "epss.csv")
        with open(dest, "wb") as fh:
            fh.write(blob)
        record[name] = {"url": url, "sha256": hashlib.sha256(blob).hexdigest(),
                        "bytes": len(blob), "entries": entries}
        lines.append("  ok   %-5s %d entries, %d bytes, sha256 %s" %
                     (name, entries, len(blob), record[name]["sha256"][:16]))
        LOG.info("feed %s refreshed: %d entries sha256=%s", name, entries,
                 record[name]["sha256"][:16])
    with open(os.path.join(fdir, "feeds.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    return ok, lines


def load_feeds(root: str) -> dict:
    """The cached feeds, or an honest empty: present=False means no ranking by
    exploitability is possible and every CVE reads as unknown, not as safe."""
    fdir = os.path.join(root, FEEDS_DIRNAME)
    out = {"present": False, "kev": {}, "epss": {}, "fetched_at": None}
    try:
        with open(os.path.join(fdir, "feeds.json"), encoding="utf-8") as fh:
            rec = json.load(fh)
        with open(os.path.join(fdir, "kev.json"), "rb") as fh:
            out["kev"] = _parse_kev(fh.read())
        with open(os.path.join(fdir, "epss.csv"), encoding="utf-8",
                  errors="replace") as fh:
            out["epss"] = _parse_epss(fh.read())
    except (OSError, ValueError):
        return out
    if not isinstance(rec, dict):
        # Valid JSON that is not an object — `null`, a list — parsed fine and
        # then took the Overview down with an AttributeError three pages wide.
        # A feed record the tool cannot read is a feed that was not fetched.
        LOG.warning("feeds.json is not a record; treating the feeds as absent")
        rec = {}
    out["fetched_at"] = rec.get("fetched_at")
    out["present"] = bool(out["kev"]) and bool(out["epss"])
    return out


def feed_ages(root: str) -> List[Tuple[str, Optional[int], str]]:
    """(feed, age_in_days, detail), mirroring vuln_db_ages so the doctor and
    the ranking report a missing or stale feed the same way as a stale DB."""
    feeds = load_feeds(root)
    age: Optional[int] = None
    if feeds.get("fetched_at"):
        try:
            t = time.strptime(feeds["fetched_at"], "%Y%m%dT%H%M%SZ")
            age = max(0, int((time.time() - time.mktime(t)) // 86400))
        except (ValueError, OverflowError):
            age = None
    out: List[Tuple[str, Optional[int], str]] = []
    for name in ("kev", "epss"):
        if not feeds.get(name):
            out.append((name, None, "not fetched yet"))
        else:
            out.append((name, age, "" if age is not None else "record unreadable"))
    return out


def cve_of(finding: dict) -> Optional[str]:
    head = str(finding.get("identity", "")).split(":")[0].upper()
    return head if re.match(r"^CVE-\d{4}-\d{4,}$", head) else None


def exploitability(cve: Optional[str], feeds: dict) -> dict:
    """What is known about whether this CVE is exploited. The state is
    'unknown' when there is no CVE to look up or no feed to look it up in, and
    the reason says which — never a silent severity-only fallback."""
    if not cve:
        return {"state": "n/a", "kev": False, "epss": None, "pct": None,
                "reason": "no CVE id; exploitability not assessable"}
    if not feeds.get("present"):
        return {"state": "unknown", "kev": False, "epss": None, "pct": None,
                "reason": "exploitability unknown: KEV/EPSS feeds not fetched "
                          "(run --feeds)"}
    kev = feeds["kev"].get(cve)
    ep = feeds["epss"].get(cve)
    reasons = []
    if kev:
        reasons.append("in CISA KEV, added %s%s" % (
            kev.get("added", "?"),
            " and used in ransomware" if kev.get("ransomware") else ""))
    if ep:
        reasons.append("EPSS %.2f (%dth percentile)" % (ep[0], int(ep[1] * 100)))
    if not reasons:
        reasons.append("not in KEV; no EPSS score published")
    return {"state": "known", "kev": bool(kev), "epss": ep[0] if ep else None,
            "pct": ep[1] if ep else None, "reason": "; ".join(reasons)}


PRIORITY_TIERS = (
    ("exploited", "Exploited now",
     "In CISA's Known Exploited Vulnerabilities catalog: exploitation is "
     "observed, not predicted."),
    ("likely", "Likely to be exploited",
     "EPSS at or above %.2f: a high modelled probability of exploitation "
     "within 30 days." % EPSS_HOT),
    ("severe", "Severe, exploitability unknown or low",
     "Critical or high severity that the feeds do not flag, or that has no "
     "CVE or no feed to check. Severity is a claim about impact, not "
     "likelihood."),
)


def rank_run(findings: List[dict], feeds: dict) -> dict:
    """Group findings by (scanner, rule) — the same key Findings and Triage
    use — and place each group in a tier with the reason stated. Everything
    that lands below the shortlist is counted by severity, never dropped."""
    groups: Dict[Tuple[str, str], dict] = {}
    for f in findings:
        rule = str(f.get("identity", "")).split(":")[0]
        g = groups.setdefault((f["scanner"], rule), {
            "scanner": f["scanner"], "rule": rule, "title": f["title"],
            "sev": f["severity"], "items": [], "detail": f.get("detail") or {},
            "cve": cve_of(f)})
        g["items"].append(f)
        if SEVERITY_ORDER.index(f["severity"]) < SEVERITY_ORDER.index(g["sev"]):
            g["sev"] = f["severity"]
        if not g["detail"]:
            g["detail"] = f.get("detail") or {}
    tiers: Dict[str, List[dict]] = {k: [] for k, _t, _d in PRIORITY_TIERS}
    below: Dict[str, int] = {}
    for g in groups.values():
        x = exploitability(g["cve"], feeds)
        g["why"] = x["reason"]
        g["x"] = x
        if x.get("kev"):
            tiers["exploited"].append(g)
        elif x.get("epss") is not None and x["epss"] >= EPSS_HOT:
            tiers["likely"].append(g)
        elif g["sev"] in ("critical", "high"):
            tiers["severe"].append(g)
        else:
            below[g["sev"]] = below.get(g["sev"], 0) + len(g["items"])
    for k in tiers:
        tiers[k].sort(key=lambda g: (SEVERITY_ORDER.index(g["sev"]),
                                     -(g["x"].get("epss") or 0), -len(g["items"])))
    return {"tiers": tiers, "below": below, "groups": len(groups),
            "feeds_present": bool(feeds.get("present"))}


__all__ = [
    'CWE_URL',
    'EPSS_HOT',
    'EPSS_URL',
    'FEED_STALE_DAYS',
    'INTEL_DIRNAME',
    'KEV_URL',
    'NVD_SPACING_NO_KEY',
    'NVD_SPACING_WITH_KEY',
    'NVD_URL',
    'OSV_URL',
    'PRIORITY_TIERS',
    '_CVSS_ORDER',
    '_CVSS_WORDS',
    '_fetch_feed',
    '_intel_path',
    '_parse_epss',
    '_parse_kev',
    '_parse_nvd',
    '_parse_osv',
    'cve_of',
    'cvss_words',
    'epss_top',
    'estate_cves',
    'exploitability',
    'feed_ages',
    'fetch_intel',
    'intel_dir',
    'intel_provenance',
    'kev_by_vendor',
    'kev_ransomware',
    'kev_recent',
    'load_feeds',
    'load_intel',
    'rank_run',
    'update_feeds',
]


# --------------------------------------------------------------------------- #
# Per-CVE context: what it is, how it scores, where the exploit references are.
#
# KEV and EPSS answer "is this being exploited". They do not say what the flaw
# is, and that is the half a reader needs to argue for a fix. Two public
# sources fill it, both cached with provenance and both fetched only by
# `squawk feeds --intel`, never by a page: OSV.dev for the summary, the aliases
# and the typed references, and NVD for the CVSS vector and the weakness ids.
#
# The rule the whole section is built on: a page reads the cache and says when
# it was fetched. Detail that has not been fetched is UNKNOWN and says so. It
# is never a blank, and never a zero.
# --------------------------------------------------------------------------- #

INTEL_DIRNAME = "intel"
OSV_URL = "https://api.osv.dev/v1/vulns/%s"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
# NVD asks for 6 seconds between requests without a key and 0.6 with one. The
# spacing is honoured with a sleep rather than by hoping; a fetch that is
# rate-limited returns partial data, which would look like a CVE with no detail.
NVD_SPACING_NO_KEY = 6.0
NVD_SPACING_WITH_KEY = 0.6
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"


def intel_dir(root: str) -> str:
    return os.path.join(root, FEEDS_DIRNAME, INTEL_DIRNAME)


def _intel_path(root: str, cve: str) -> str:
    # A CVE id is [A-Z0-9-] by construction, but it arrives from a scanner's
    # output, so it is not trusted to be a filename.
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve.upper())[:64]
    return os.path.join(intel_dir(root), safe + ".json")


def load_intel(root: str, cve: str) -> Optional[dict]:
    """The cached detail for one CVE, or None when it has not been fetched.
    None means unknown, and every caller has to say so rather than showing a
    blank where a description would be."""
    try:
        with open(_intel_path(root, cve), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _parse_osv(doc: dict) -> dict:
    """Summary, aliases and typed references from an OSV record."""
    refs = []
    for r in _rows(doc.get("references")):
        url = str(r.get("url", "")).strip()
        if url:
            refs.append({"type": str(r.get("type", "WEB")).upper(), "url": url})
    return {"summary": str(doc.get("summary") or doc.get("details") or "")[:1200],
            "aliases": sorted({str(a) for a in _rows(doc.get("aliases")) if a}
                              | {str(doc.get("id"))} - {""}),
            "references": refs[:40]}


def _parse_nvd(doc: dict) -> dict:
    """CVSS vector, score and CWE ids from an NVD 2.0 response."""
    vulns = _rows(doc.get("vulnerabilities"))
    if not vulns:
        return {}
    cve = (vulns[0] or {}).get("cve") or {}
    metrics = cve.get("metrics") or {}
    best = {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = _rows(metrics.get(key))
        if rows:
            data = (rows[0] or {}).get("cvssData") or {}
            best = {"version": str(data.get("version", "")),
                    "vector": str(data.get("vectorString", "")),
                    "score": data.get("baseScore"),
                    "severity": str(data.get("baseSeverity", "")).lower()}
            break
    cwes = []
    for w in _rows(cve.get("weaknesses")):
        for d in _rows(w.get("description")):
            val = str(d.get("value", ""))
            if val.upper().startswith("CWE-") and val not in cwes:
                cwes.append(val)
    published = str(cve.get("published", ""))[:10]
    return {"cvss": best, "cwe": cwes[:6], "published": published}


# The eight base-metric letters, in words. A vector nobody can read is a string
# of initials; the argument for fixing something is made in sentences.
_CVSS_WORDS = {
    "AV": {"N": "reachable over the network", "A": "reachable from the adjacent network",
           "L": "needs local access", "P": "needs physical access"},
    "AC": {"L": "low attack complexity", "H": "high attack complexity"},
    "AT": {"N": "no special conditions", "P": "needs a specific condition"},
    "PR": {"N": "no privileges needed", "L": "needs low privileges",
           "H": "needs high privileges"},
    "UI": {"N": "no user interaction", "R": "needs user interaction",
           "P": "needs passive user interaction", "A": "needs active user interaction"},
    "S": {"U": "scope unchanged", "C": "scope changed"},
    "C": {"H": "high confidentiality impact", "L": "low confidentiality impact",
          "N": "no confidentiality impact"},
    "I": {"H": "high integrity impact", "L": "low integrity impact",
          "N": "no integrity impact"},
    "A": {"H": "high availability impact", "L": "low availability impact",
          "N": "no availability impact"},
}
_CVSS_ORDER = ("AV", "AC", "AT", "PR", "UI", "S", "VC", "VI", "VA", "C", "I", "A")


def cvss_words(vector: str) -> List[str]:
    """A CVSS vector rendered as phrases, in a fixed order. Unknown metrics are
    dropped rather than guessed: a vector this does not understand produces a
    shorter list, never an invented one."""
    if not vector:
        return []
    parts = {}
    for chunk in str(vector).split("/"):
        if ":" in chunk:
            k, _sep, v = chunk.partition(":")
            parts[k.strip().upper()] = v.strip().upper()
    out = []
    for key in _CVSS_ORDER:
        # CVSS 4 names the base impact metrics VC/VI/VA; they read the same way.
        lookup = {"VC": "C", "VI": "I", "VA": "A"}.get(key, key)
        val = parts.get(key)
        if val and lookup in _CVSS_WORDS and val in _CVSS_WORDS[lookup]:
            phrase = _CVSS_WORDS[lookup][val]
            if phrase not in out:
                out.append(phrase)
    return out


def fetch_intel(root: str, cves: List[str], force: bool = False,
                api_key: Optional[str] = None,
                sleep=None) -> Tuple[bool, List[str]]:
    """Fetch and cache OSV and NVD detail for each CVE, with provenance.

    Only what is not already cached, unless forced: this walks a public API once
    per CVE and re-fetching what is on disk is rude and slow. Everything it
    writes carries where it came from and when, so a page can say how old its
    detail is instead of presenting it as timeless.

    The key, when there is one, comes from the environment and rides in a
    header. It never reaches argv, a log line or the cache (credential rule 6),
    and it is not required: without one this is slower, not unavailable."""
    fdir = intel_dir(root)
    try:
        os.makedirs(fdir, exist_ok=True)
        os.chmod(fdir, 0o700)
    except OSError as exc:
        return False, ["intel: cannot create %s: %s" % (fdir, exc)]
    napper = sleep if sleep is not None else time.sleep
    spacing = NVD_SPACING_WITH_KEY if api_key else NVD_SPACING_NO_KEY
    wanted = sorted({c.upper() for c in cves if c})
    todo = [c for c in wanted if force or load_intel(root, c) is None]
    lines = ["  %d CVE(s) in the estate, %d already cached, %d to fetch"
             % (len(wanted), len(wanted) - len(todo), len(todo))]
    if not todo:
        return True, lines
    if not api_key:
        lines.append("  no SQUAWK_NVD_API_KEY, so NVD is spaced %.0fs apart: "
                     "about %d minute(s)" % (spacing, max(1, int(len(todo) * spacing / 60))))
    ok = True
    got = 0
    for n, cve in enumerate(todo):
        doc: Dict[str, Any] = {"cve": cve, "sources": {},
                               "fetched_at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}
        blob, err = _fetch_feed(OSV_URL % cve, timeout=30)
        if blob is None:
            doc["sources"]["osv"] = {"url": OSV_URL % cve, "error": err}
        else:
            doc["sources"]["osv"] = {"url": OSV_URL % cve, "bytes": len(blob),
                                     "sha256": hashlib.sha256(blob).hexdigest()}
            doc.update(_parse_osv(_report(blob.decode("utf-8", "replace"), dict)))
        if n:
            napper(spacing)
        blob, err = _fetch_feed(
            NVD_URL % cve, timeout=45,
            headers={"apiKey": api_key} if api_key else None)
        if blob is None:
            doc["sources"]["nvd"] = {"url": NVD_URL % cve, "error": err}
            ok = False
        else:
            doc["sources"]["nvd"] = {"url": NVD_URL % cve, "bytes": len(blob),
                                     "sha256": hashlib.sha256(blob).hexdigest()}
            doc.update(_parse_nvd(_report(blob.decode("utf-8", "replace"), dict)))
        try:
            with open(_intel_path(root, cve), "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2, sort_keys=True)
            got += 1
        except OSError as exc:
            ok = False
            lines.append("  gap  %s: cannot cache: %s" % (cve, exc))
    lines.append("  ok   cached detail for %d of %d" % (got, len(todo)))
    LOG.info("intel: fetched %d of %d CVE(s)", got, len(todo))
    return ok, lines


def intel_provenance(root: str) -> List[dict]:
    """One row per source: what it is, how old, and how much of it there is.
    A source that has not been fetched is present in this list saying so, never
    absent, because a missing row reads as a source nobody needed."""
    out = []
    feeds = load_feeds(root)
    for name, label in (("kev", "CISA KEV"), ("epss", "FIRST EPSS")):
        rec: Dict[str, Any] = {}
        try:
            with open(os.path.join(root, FEEDS_DIRNAME, "feeds.json"),
                      encoding="utf-8") as fh:
                doc = json.load(fh)
                rec = (doc.get(name) or {}) if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            rec = {}
        if not isinstance(rec, dict):
            rec = {}
        age = None
        for feed, days, _detail in feed_ages(root):
            if feed == name:
                age = days
        out.append({"source": label, "state": "ok" if feeds.get("present") and rec
                                     else "not fetched",
                    "age_days": age, "entries": rec.get("entries"),
                    "url": rec.get("url", ""), "sha256": rec.get("sha256", "")})
    fdir = intel_dir(root)
    try:
        cached = [f for f in os.listdir(fdir) if f.endswith(".json")]
    except OSError:
        cached = []
    out.append({"source": "OSV + NVD per-CVE detail",
                "state": "ok" if cached else "not fetched",
                "age_days": None, "entries": len(cached) or None,
                "url": "", "sha256": ""})
    return out


def estate_cves(runs: List[dict], load) -> Dict[str, List[dict]]:
    """{CVE: [finding, ...]} across the given runs, using the caller's loader so
    this stays free of the evidence layer."""
    out: Dict[str, List[dict]] = {}
    for man in runs:
        for f in load(man["_dir"]):
            cve = cve_of(f)
            if cve:
                row = dict(f)
                row["_run"] = man.get("run_id", "")
                row["_target"] = man.get("target", "")
                out.setdefault(cve, []).append(row)
    return out


def kev_recent(feeds: dict, days: int = 30, now: Optional[float] = None) -> List[dict]:
    """KEV entries added in the last N days, newest first.

    This is the general half of threat intelligence: what is being exploited in
    the world, whether or not you run it. It is free, because the catalogue is
    already on disk after `squawk feeds`."""
    cutoff = (now if now is not None else time.time()) - days * 86400
    out = []
    for cve, entry in (feeds.get("kev") or {}).items():
        try:
            when = time.mktime(time.strptime(entry.get("added", ""), "%Y-%m-%d"))
        except (ValueError, TypeError):
            continue
        if when >= cutoff:
            out.append(dict(entry, cve=cve, _added_at=when))
    return sorted(out, key=lambda e: (-e["_added_at"], e["cve"]))


def kev_ransomware(feeds: dict, limit: int = 25) -> List[dict]:
    """The KEV subset flagged as used in ransomware campaigns, newest first."""
    rows = [dict(e, cve=c) for c, e in (feeds.get("kev") or {}).items()
            if e.get("ransomware")]
    return sorted(rows, key=lambda e: (e.get("added", ""), e["cve"]),
                  reverse=True)[:limit]


def epss_top(feeds: dict, limit: int = 25) -> List[Tuple[str, float, float]]:
    """The highest-scoring CVEs in EPSS overall, not just the estate's.

    EPSS covers hundreds of thousands of CVEs, so this walks once and keeps the
    top N rather than sorting the lot."""
    import heapq
    epss = feeds.get("epss") or {}
    top = heapq.nlargest(limit, epss.items(), key=lambda kv: (kv[1][0], kv[0]))
    return [(cve, score, pct) for cve, (score, pct) in top]


def kev_by_vendor(feeds: dict, limit: int = 12) -> List[Tuple[str, int]]:
    """Which vendors the catalogue names most often. A crude shape of where
    exploitation is concentrated, and useful mainly for recognising a vendor
    you run and have never pointed this at."""
    counts: Dict[str, int] = {}
    for entry in (feeds.get("kev") or {}).values():
        vendor = (entry.get("vendor") or "").strip()
        if vendor:
            counts[vendor] = counts.get(vendor, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
