#!/usr/bin/env python3
"""Merge semgrep JSON (+ optional SpotBugs XML) into one deduped, severity-sorted
findings list. Emits findings.json and findings.csv.

Usage:
  python3 aggregate.py --semgrep semgrep_findings.json \
      [--spotbugs spotbugs.xml] \
      [--project /path/to/src] \
      [--out-dir /mnt/f/hermesproject/<proj>]

Severity mapping (rules of thumb; refine by reading the snippet):
  CRITICAL: RCE / command injection / deserialization / SQLi with user input / auth bypass
  HIGH:     SSRF, path traversal, XXE, SpEL/template injection, weak crypto
  MEDIUM:   hardcoded secrets/keys, insecure defaults, missing validation
  LOW:      code-quality / NPE-risk / resource-leak / deprecated API (SpotBugs)
"""
import argparse, json, csv, os, sys, re, html
from xml.etree import ElementTree as ET

# heuristic keyword -> severity
SEV_RULES = [
    (r"command|runtime|exec|processbuilder|rce|command.?inject", "CRITICAL"),
    (r"deserializ|readobject|readunshared|objectinputstream", "CRITICAL"),
    (r"sql.?inject|sql.*inject|statement.*exec|jndi|lookup", "CRITICAL"),
    (r"ssrf|path.?traversal|traversal|xxe|sax|documentbuilder|xstream|spel|template.?inject|sni|open.?redirect", "HIGH"),
    (r"weak.?crypto|md5|des |ecb|insecure.?random|insecure.?random|hardcod|secret|password|credential|apikey|api.?key", "MEDIUM"),
]
def guess_severity(text):
    t = text.lower()
    for pat, sev in SEV_RULES:
        if re.search(pat, t):
            return sev
    return "MEDIUM"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
def norm_sev(s):
    s = (s or "").upper()
    for k in SEV_ORDER:
        if k in s:
            return k
    return "MEDIUM"

def read_snippet(path, line_start, line_end, pad=1):
    """Read real source lines from the local file (registry rules redact
    extra.lines to 'requires login', so we re-read from disk)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:
        return ""
    if not line_start:
        return ""
    a = max(1, int(line_start) - pad)
    b = min(len(lines), int(line_end or line_start) + pad)
    out = []
    for i in range(a, b + 1):
        out.append((">> " if a <= i <= (line_end or line_start) else "   ") + lines[i - 1].rstrip())
    return "\n".join(out)

def load_semgrep(path, project="."):
    findings = []
    if not path or not os.path.exists(path):
        return findings
    d = json.load(open(path))
    for r in d.get("results", []):
        cid = r.get("check_id", "")
        msg = r.get("extra", {}).get("message", "")
        sev = guess_severity(cid + " " + msg)
        fpath = r.get("path", "")
        absf = fpath if os.path.isabs(fpath) else os.path.join(project, fpath)
        ls = r.get("start", {}).get("line")
        le = r.get("end", {}).get("line")
        # prefer real source lines; fall back to extra.lines
        snip = read_snippet(absf, ls, le)
        if not snip:
            snip = r.get("extra", {}).get("lines", "") or ""
        findings.append({
            "engine": "semgrep",
            "rule": cid,
            "file": fpath,
            "line_start": ls,
            "line_end": le,
            "severity": sev,
            "message": msg,
            "snippet": snip,
        })
    return findings

def load_spotbugs(path, project=".", srcroot=""):
    findings = []
    if not path or not os.path.exists(path):
        return findings
    try:
        tree = ET.parse(path)
    except Exception as e:
        print(f"[warn] could not parse spotbugs xml: {e}", file=sys.stderr)
        return findings
    root = tree.getroot()
    for bug in root.findall("BugInstance"):
        typ = bug.get("type", "")
        prio = bug.get("priority", "2")  # 1=high 2=normal 3=low
        sev = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(int(prio), "MEDIUM")
        # security types from findsecbugs are usually security-critical
        if re.search(r"SQL_|XXE|PATH_TRAVER|COMMAND_INJ|DESERIAL|SSRF|WEAK_CRYPT|HARDCODED", typ):
            sev = guess_severity(typ) or "HIGH"
        cls = bug.find(".//Class")
        # NOTE: use DIRECT child SourceLine — .//SourceLine resolves to the
        # nested one inside <Class>/<BugPattern> (always the class-decl line),
        # not the finding's actual method line.
        fm = bug.find("SourceLine")
        loc = cls.get("classname", "") if cls is not None else ""
        line = fm.get("start", "?") if fm is not None else "?"
        # map fully-qualified class name -> source file under srcroot so we can
        # inline real code (maven: srcroot=src/main/java; loose: srcroot=.)
        srcfile = ""
        if srcroot and loc:
            cand = os.path.join(srcroot, loc.replace(".", "/") + ".java")
            if os.path.exists(cand):
                srcfile = cand
        snip = ""
        if srcfile and str(line).isdigit():
            snip = read_snippet(srcfile, int(line), int(line))
        findings.append({
            "engine": "spotbugs+findsecbugs",
            "rule": typ,
            "file": srcfile or loc,
            "line_start": line,
            "line_end": line,
            "severity": sev,
            "message": bug.get("category", "") + " " + typ,
            "snippet": snip,
        })
    return findings

def dedupe(findings):
    seen = {}
    out = []
    for f in findings:
        # key on (file, line, normalized rule) — full rule, not truncated,
        # so distinct findings at the same line stay distinct.
        key = (f["file"], f["line_start"], re.sub(r"[^a-z]", "", f["rule"]).lower())
        if key not in seen:
            seen[key] = f
            out.append(f)
        else:
            # keep higher severity; merge distinct rules + engines (no dup)
            keep = seen[key]
            if SEV_ORDER.get(f["severity"], 9) < SEV_ORDER.get(keep["severity"], 9):
                keep["severity"] = f["severity"]
            if f["rule"] != keep["rule"]:
                keep["rule"] = keep["rule"] + " / " + f["rule"]
            # merge engine tokens without repetition
            merged = list(dict.fromkeys(keep["engine"].split("+") + f["engine"].split("+")))
            keep["engine"] = "+".join(merged)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep")
    ap.add_argument("--spotbugs")
    ap.add_argument("--project", default=".")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--srcroot", default="",
                    help="source root for inlining SpotBugs findings (maven: src/main/java; loose: dir containing pkg dirs)")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    findings = load_semgrep(a.semgrep, project=a.project) + load_spotbugs(a.spotbugs, project=a.project, srcroot=a.srcroot)
    findings = dedupe(findings)
    def _ln(v):
        try:
            return int(v)
        except Exception:
            return 0
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), str(f["file"]), _ln(f["line_start"])))

    # make file paths relative to project for readability
    for f in findings:
        try:
            if os.path.isabs(f["file"]) and f["file"].startswith(os.path.abspath(a.project)):
                f["file"] = os.path.relpath(f["file"], os.path.abspath(a.project))
        except Exception:
            pass

    jpath = os.path.join(a.out_dir, "findings.json")
    json.dump(findings, open(jpath, "w"), ensure_ascii=False, indent=2)

    cpath = os.path.join(a.out_dir, "findings.csv")
    with open(cpath, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["严重度", "类型/规则", "文件", "起始行", "结束行", "引擎", "描述", "代码片段"])
        for f in findings:
            w.writerow([f["severity"], f["rule"], f["file"], f["line_start"], f["line_end"],
                        f["engine"], f["message"], f["snippet"].strip()[:400]])

    # summary
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("TOTAL:", len(findings))
    for k in SEV_ORDER:
        if counts.get(k):
            print(f"  {k}: {counts[k]}")
    print("wrote:", jpath, "and", cpath)

if __name__ == "__main__":
    main()
