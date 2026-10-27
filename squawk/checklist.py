"""The pre-handover checklist: a manual-review signoff a reviewer completes
before results go into a report.

The automated scanners answer "what did the tools find"; a checklist answers
"did a person look where the tools are blind, and is this ready to hand over".
It is per **engagement** (the signoff is for the review, not one finding), and
every tick is a sealed, chained ledger line — the same tamper-evident evidence
as a triage decision — so a signoff cannot be back-dated or quietly changed.

The items are a general, standards-aligned default (OWASP WSTG / ASVS coverage
plus findings-quality, evidence and report-hygiene gates). An operator who wants
their own list drops a `checklist.md` in the evidence root: `## Section` headers
and `- ` bullet items (a `- [ ]` task list works too).
"""
import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from squawk.core import append_chained
from squawk.decisions import who

#: open = not yet reviewed; pass = done / confirmed; na = not applicable to this
#: target; fail = looked and it is not ready (a blocker before handover).
CHECK_STATES = ("open", "pass", "na", "fail")
NOTE_CAP = 2000
_LEDGER_VERSION = 2

#: The file an operator drops in the evidence root to replace the default list.
CHECKLIST_FILE = "checklist.md"

#: The default pre-handover signoff. General on purpose — no target is named —
#: so it is the same list every engagement starts from.
DEFAULT_CHECKLIST: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Coverage — a person looked, not only the tools", (
        "Authentication reviewed (login, lockout, credential handling)",
        "Session management reviewed (cookie flags, fixation, lifetime)",
        "Authorization reviewed (IDOR/BOLA, privilege, header-trust)",
        "Injection and unsafe parsing reviewed (SQL, command, deserialization)",
        "SSRF and redirects reviewed",
        "Client-side reviewed (XSS, CSRF)",
        "Cryptography, secrets and tokens reviewed",
        "OAuth / SSO flows reviewed",
        "Business logic and concurrency reviewed",
        "Error handling and information disclosure reviewed",
        "Configuration, headers and container reviewed",
        "Dependencies and supply chain reviewed",
    )),
    ("Findings quality", (
        "Every finding reproduced or verified, not asserted",
        "False positives triaged with a reason",
        "Severities justified by impact and ease",
        "Residuals and out-of-scope items documented, not silently dropped",
    )),
    ("Evidence", (
        "Each finding carries evidence a reader can check",
        "Scanner gaps are flagged, never read as clean",
        "Runs are sealed and tamper-evident",
    )),
    ("Report hygiene", (
        "No secrets, credentials or PII in the report",
        "Scope and rules of engagement stated",
        "Recommendations are specific and actionable",
    )),
    ("Signoff", (
        "Reviewer confirms the results are ready to hand over",
    )),
)


def ledger_path(evidence_root: str) -> str:
    return os.path.join(evidence_root, "checklist", "ledger.jsonl")


def source_path(evidence_root: str) -> str:
    return os.path.join(evidence_root, CHECKLIST_FILE)


def _slug(text: str) -> str:
    """A stable id for an item from its text: lowercase, non-alphanumerics to
    hyphens. Reordering items keeps their ids, so a recorded tick stays with the
    item it was made against."""
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:60] or "item"


def _parse_markdown(text: str) -> List[Tuple[str, List[str]]]:
    """`## Section` headers and their `- ` / `* ` bullet items (an optional
    `[ ]` / `[x]` checkbox is stripped). A section with no items is dropped."""
    sections: List[Tuple[str, List[str]]] = []
    current: Optional[Tuple[str, List[str]]] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        head = re.match(r"^#{2,4}\s+(.*)$", line)
        if head:
            current = (head.group(1).strip(), [])
            sections.append(current)
            continue
        item = re.match(r"^\s*[-*]\s+(?:\[[ xX]\]\s+)?(.+)$", line)
        if item and current is not None:
            current[1].append(item.group(1).strip())
    return [(name, items) for name, items in sections if items]


def load_checklist(evidence_root: str) -> List[Tuple[str, List[str]]]:
    """The checklist for this evidence root: the operator's `checklist.md` when
    it is present and parses to at least one item, else the built-in default."""
    try:
        with open(source_path(evidence_root), encoding="utf-8") as fh:
            parsed = _parse_markdown(fh.read())
        if parsed:
            return parsed
    except OSError:
        pass
    return [(name, list(items)) for name, items in DEFAULT_CHECKLIST]


def checklist_items(evidence_root: str) -> List[dict]:
    """The checklist flattened to `{id, section, text}`, ids unique within the
    list (a repeated slug gets a numeric suffix)."""
    out: List[dict] = []
    seen: Dict[str, int] = {}
    for section, items in load_checklist(evidence_root):
        for text in items:
            base = _slug(text)
            n = seen.get(base, 0)
            seen[base] = n + 1
            item_id = base if n == 0 else "%s-%d" % (base, n + 1)
            out.append({"id": item_id, "section": section, "text": text})
    return out


def record_check(evidence_root: str, engagement: str, item_id: str, status: str,
                 note: str = "", by: Optional[str] = None,
                 at: Optional[str] = None) -> dict:
    """Append one checklist tick and return it. Raises ValueError rather than
    writing a line it would later explain away."""
    if status not in CHECK_STATES:
        raise ValueError("unknown check status %r (one of %s)"
                         % (status, ", ".join(CHECK_STATES)))
    if not (item_id or "").strip():
        raise ValueError("a check must name an item")
    if not (engagement or "").strip():
        raise ValueError("a check must name an engagement")
    if len(note) > NOTE_CAP:
        raise ValueError("note is longer than %d characters" % NOTE_CAP)
    event = {
        "v": _LEDGER_VERSION,
        "at": at or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        "who": by or who(),
        "engagement": engagement.strip(),
        "item": item_id.strip(),
        "status": status,
        "note": note,
    }
    append_chained(ledger_path(evidence_root), event)
    return event


def load_checks(evidence_root: str,
                problems: Optional[List[str]] = None) -> List[dict]:
    """Every recorded tick, in order. A line that does not parse or is not a
    check is skipped and reported through `problems`, never silently dropped."""
    path = ledger_path(evidence_root)
    events: List[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError as exc:
                    if problems is not None:
                        problems.append("checklist ledger line %d does not parse: %s" % (n, exc))
                    continue
                if (not isinstance(ev, dict) or ev.get("status") not in CHECK_STATES
                        or not ev.get("item") or not ev.get("engagement")):
                    if problems is not None:
                        problems.append("checklist ledger line %d is not a check" % n)
                    continue
                events.append(ev)
    except FileNotFoundError:
        return []
    except OSError as exc:
        if problems is not None:
            problems.append("cannot read the checklist ledger: %s" % exc)
    return events


def current_checks(evidence_root: str, engagement: str) -> Dict[str, dict]:
    """{item_id: latest tick} for one engagement. Later lines win, so re-ticking
    an item supersedes the earlier tick without erasing it."""
    out: Dict[str, dict] = {}
    want = (engagement or "").strip()
    for ev in load_checks(evidence_root):
        if ev.get("engagement") == want:
            out[ev["item"]] = ev
    return out


def signoff_state(evidence_root: str, engagement: str, items: List[dict]) -> dict:
    """Whether this engagement's checklist is ready to hand over: every item is
    `pass` or `na`, none `open` or `fail`. Returns the counts, the reviewer and
    time of the most recent tick, and `ready`."""
    current = current_checks(evidence_root, engagement)
    counts = {s: 0 for s in CHECK_STATES}
    for item in items:
        ev = current.get(item["id"])
        counts[ev["status"] if ev else "open"] += 1
    ticks = [current[i["id"]] for i in items if i["id"] in current]
    latest = max(ticks, key=lambda e: e.get("at", "")) if ticks else None
    ready = bool(items) and counts["open"] == 0 and counts["fail"] == 0
    return {
        "total": len(items),
        "passed": counts["pass"], "na": counts["na"],
        "failed": counts["fail"], "open": counts["open"],
        "ready": ready,
        "who": latest.get("who", "") if latest else "",
        "at": latest.get("at", "") if latest else "",
    }


#: The manual-review grep sweep — a BACKUP to the scanners, grouped to match the
#: checklist's coverage areas. High recall on purpose: a hit is a place to LOOK,
#: not a confirmed finding. Cross-language (Python, JS/TS, Java, PHP, Go, Ruby).
#: Each rule is (what to look for, regex[, exclude-regex]).
REVIEW_GREPS: tuple = (
    ("Injection — SQL / command / template", (
        ("SQL built by concatenation or format, not a bound parameter",
         r"(execute|executemany|query|cursor\.execute|\.raw)\s*\(.*"
         r"(%s|%d|['\"]\s*\+|\+\s*['\"]|\.format\(|f['\"]|\$\{|#\{)"
         r"|['\"]\s*(SELECT|INSERT|UPDATE|DELETE)\b.{0,80}['\"]\s*(%|\+|\.format)"
         r"|f['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b"),
        ("OS command with a variable or a shell",
         r"(os\.system|subprocess\.(call|run|Popen|check_output)|commands\.getoutput)"
         r"\s*\(|shell\s*=\s*True|child_process\.(exec|execSync|spawn)"
         r"|Runtime\.getRuntime\(\)\.exec|exec\.Command\(|proc_open\(|passthru\("),
    )),
    ("Unsafe parsing / deserialization", (
        ("deserialize or evaluate attacker data",
         r"\byaml\.load\s*\(|pickle\.(load|loads)|cPickle|marshal\.loads|\beval\s*\("
         r"|\bexec\s*\(|\bunserialize\s*\(|ObjectInputStream|\.readObject\s*\("
         r"|Marshal\.load|yaml\.Unmarshal|vm\.runInContext|new Function\("),
        ("XML parser (check external entities / DTD are disabled)",
         r"DocumentBuilderFactory|SAXParser|XMLReader|etree\.(parse|fromstring)"
         r"|libxml|simplexml_load|resolveEntity"),
    )),
    ("SSRF & open redirect", (
        ("server fetches a URL (is it validated / allowlisted?)",
         r"(requests\.(get|post|put|request)|urllib\.request\.urlopen|\burlopen\("
         r"|http\.(get|request)|axios|fetch\s*\(|new URL\(|HttpClient|WebClient"
         r"|file_get_contents\(|curl_exec\(|http\.Get\()"),
        ("redirect driven by user input",
         r"(redirect|sendRedirect|res\.redirect|HttpResponseRedirect)\s*\(?.*"
         r"(request|req\.|params|query|input|getParameter)"),
    )),
    ("Authentication & secrets", (
        ("hardcoded secret, key or credential",
         r"(secret|secret_key|password|passwd|pwd|api[_-]?key|access[_-]?key|token"
         r"|client[_-]?secret|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}['\"]"
         r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("weak password hashing (fast / unsalted)",
         r"hashlib\.(md5|sha1)|\bmd5\(|\bsha1\(|MessageDigest\.getInstance\(['\"]"
         r"(MD5|SHA-?1)|createHash\(['\"](md5|sha1)"),
        ("JWT with verification disabled or alg 'none'",
         r"alg(orithm)?s?\s*[:=].{0,20}none|verify\s*[:=]\s*(False|false)"
         r"|jwt\.decode\([^)]*verify\s*=\s*False"),
    )),
    ("Authorization / IDOR", (
        ("authorization from a client-settable header",
         r"X-Forwarded-For|X-Real-IP|X-Forwarded-Host|X-Originating-IP|X-Client-IP"
         r"|X-Remote-Addr|headers\.get\(['\"]x-forward"),
        ("object fetched by an id from the request — confirm an owner check",
         r"WHERE\s+id\s*=|find(ById|One)\(|get_object_or_404|params\[['\":]?id"
         r"|req\.params\.id|request\.(args|values|GET)\.get\(['\"]id",
         r"session\[['\"]?user|owner_id|current_user|\.user_id|user\.id|WHERE\s+owner"),
    )),
    ("Client-side — XSS & CSRF", (
        ("unescaped output / raw HTML sink",
         r"\|\s*safe\b|mark_safe\(|render_template_string\(|dangerouslySetInnerHTML"
         r"|v-html|innerHTML\s*=|document\.write\(|\{!!|<%=\s*raw|\.html\("),
        ("CSRF protection disabled or exempt",
         r"csrf.{0,10}exempt|@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False"
         r"|csrf.{0,12}(disable|False|off)|SameSite\s*[:=]\s*['\"]?None"),
    )),
    ("Randomness & tokens", (
        ("insecure randomness for a secret, token or id",
         r"Math\.random\(|random\.(random|randint|choice|randrange)\(|\brand\(\)"
         r"|mt_rand\(|uuid1\(|new Random\("),
        ("home-made MAC — hash(secret + data) is length-extension forgeable",
         r"(md5|sha1|sha256|sha512)\s*\(\s*\w*(secret|key)\w*\s*\+|digest\(.*\+.*secret"),
    )),
    ("Config, transport & container", (
        ("debug on, or TLS verification turned off",
         r"\bdebug\s*=\s*True|DEBUG\s*=\s*True|FLASK_ENV.{0,20}development"
         r"|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"
         r"|CURLOPT_SSL_VERIFYPEER.{0,6}(0|false)|NODE_TLS_REJECT_UNAUTHORIZED"),
        ("container as root, floating base tag, or a host mount",
         r"^\s*USER\s+root|FROM\s+\S+:latest|ADD\s+https?://|chmod\s+777"
         r"|/\.ssh|/\.aws|docker\.sock"),
    )),
    ("Error handling & information disclosure", (
        ("stack trace or internals returned to the user",
         r"printStackTrace|traceback\.(print|format)_exc|console\.(log|error)\([^)]*"
         r"(err|stack|exception)|getMessage\(\)|var_dump\(|print_r\(|dump\("
         r"|return\s+(str|repr)\(\s*e[xc]*\s*\)|=\s*(str|repr)\(\s*e[xc]*\s*\)"),
    )),
)

_GREP_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
                   "venv", "__pycache__", ".next", "target", ".tox", ".idea",
                   "site-packages", ".mypy_cache", ".pytest_cache"}
_GREP_SKIP_EXT = (".min.js", ".map", ".lock", ".svg", ".png", ".jpg", ".jpeg",
                  ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf")
_GREP_MAX_BYTES = 2_000_000


def grep_sweep(target: str, area: Optional[str] = None) -> List[Tuple[str, List[tuple]]]:
    """Run the review sweep over `target`. Returns [(area, [(label, path, line,
    text)])]. `area` limits to areas whose name contains it. Nothing here
    confirms a bug — every hit is a line to read."""
    files: List[Tuple[str, List[str]]] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in _GREP_SKIP_DIRS]
        for name in filenames:
            if name.endswith(_GREP_SKIP_EXT):
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > _GREP_MAX_BYTES:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    files.append((os.path.relpath(path, target), fh.read().splitlines()))
            except OSError:
                continue
    out: List[Tuple[str, List[tuple]]] = []
    for name, rules in REVIEW_GREPS:
        if area and area.lower() not in name.lower():
            continue
        compiled = []
        for rule in rules:
            exclude = re.compile(rule[2], re.IGNORECASE) if len(rule) > 2 else None
            compiled.append((rule[0], re.compile(rule[1], re.IGNORECASE), exclude))
        hits: List[tuple] = []
        for rel, lines in files:
            for i, line in enumerate(lines, 1):
                if len(line) > 400:
                    continue
                for label, rx, exclude in compiled:
                    if rx.search(line) and not (exclude and exclude.search(line)):
                        hits.append((label, rel, i, line.strip()[:160]))
                        break
        out.append((name, hits))
    return out


__all__ = [
    "CHECKLIST_FILE",
    "CHECK_STATES",
    "DEFAULT_CHECKLIST",
    "NOTE_CAP",
    "REVIEW_GREPS",
    "_GREP_MAX_BYTES",
    "_GREP_SKIP_DIRS",
    "_GREP_SKIP_EXT",
    "_LEDGER_VERSION",
    "_parse_markdown",
    "_slug",
    "checklist_items",
    "current_checks",
    "grep_sweep",
    "ledger_path",
    "load_checklist",
    "load_checks",
    "record_check",
    "signoff_state",
    "source_path",
]
