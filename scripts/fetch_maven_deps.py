#!/usr/bin/env python3
"""Resolve + download a Maven artifact's full runtime dependency tree from
Maven Central, assembling a classpath. Lets you run SpotBugs CLI without the
GitHub dist tarball (which 404s behind egress proxies that break github.com
asset downloads).

Correctly handles: ${property} interpolation, <parent> inheritance, and
<dependencyManagement> version pins. Skips (warns) unresolvable versions
instead of looping.

Usage: python3 fetch_maven_deps.py <groupId:artifactId:version> <outdir>
"""
import sys, os, re, urllib.request

import os as _os
BASE = _os.environ.get("MAVEN_BASE", "https://maven.aliyun.com/repository/public").rstrip("/")
jar_dir = sys.argv[2]
os.makedirs(jar_dir, exist_ok=True)

_cache, _fail = {}, set()
def http(url):
    if url in _cache:
        return _cache[url]
    if url in _fail:
        raise IOError("retry " + url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=40) as r:
            data = r.read()
        _cache[url] = data
        return data
    except Exception as e:
        _fail.add(url)
        raise

def g2p(g):
    return g.replace(".", "/")

def tag(block, name):
    m = re.search(rf"<{name}>([^<]+)</{name}>", block)
    return m.group(1).strip() if m else None

def props_of(pom, base_v):
    p = {}
    m = re.search(r"<properties>(.*?)</properties>", pom, re.S)
    if m:
        for pm in re.finditer(r"<([A-Za-z0-9._-]+)>([^<]+)</\1>", m.group(1)):
            p[pm.group(1)] = pm.group(2).strip()
    p.setdefault("project.version", base_v)
    p.setdefault("version", base_v)
    p.setdefault("project.groupId", tag(pom, "groupId") or "")
    p.setdefault("artifactId", tag(pom, "artifactId") or "")
    return p

def load(g, a, v):
    """Return (pom_xml, props) or (None, {})."""
    if not v or re.search(r"\$\{", v):
        return None, {}
    url = f"{BASE}/{g2p(g)}/{a}/{v}/{a}-{v}.pom"
    try:
        pom = http(url).decode("utf-8", "replace")
    except Exception:
        return None, {}
    return pom, props_of(pom, v)

def interpolate(val, props):
    if not val:
        return val
    for _ in range(8):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), val)
        if new == val:
            break
        val = new
    return val

def parent_block(pom):
    m = re.search(r"<parent>(.*?)</parent>", pom, re.S)
    return m.group(1) if m else None

def full_props(g, a, v, depth=0):
    """Merge parent chain properties (best effort, depth-limited)."""
    pom, props = load(g, a, v)
    if pom is None:
        return props, pom
    pb = parent_block(pom)
    if pb and depth < 5:
        pg, pa = tag(pb, "groupId"), tag(pb, "artifactId")
        pv = interpolate(tag(pb, "version"), props)
        if pg and pa and pv and not re.search(r"\$\{", pv):
            ppom, pprops = load(pg, pa, pv)
            if ppom:
                merged = dict(pprops); merged.update(props)
                merged.setdefault("project.version", v)
                gprops, _ = full_props(pg, pa, pv, depth + 1)
                base = dict(gprops); base.update(merged)
                base.setdefault("project.version", v)
                return base, pom
    return props, pom

def dep_mgmt_map(pom, props):
    """(groupId:artifactId) -> version, from <dependencyManagement>."""
    m = re.search(r"<dependencyManagement>(.*?)</dependencyManagement>", pom, re.S)
    out = {}
    if m:
        for d in re.finditer(r"<dependency>(.*?)</dependency>", m.group(1), re.S):
            b = d.group(1)
            dg, da, dv = tag(b, "groupId"), tag(b, "artifactId"), tag(b, "version")
            if dg and da:
                out[f"{dg}:{da}"] = interpolate(dv or "", props)
    return out

def dep_blocks(pom):
    pom2 = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", pom, flags=re.S)
    res = []
    for d in re.finditer(r"<dependency>(.*?)</dependency>", pom2, re.S):
        b = d.group(1)
        g, a, v = tag(b, "groupId"), tag(b, "artifactId"), tag(b, "version")
        scope = tag(b, "scope") or "compile"
        opt = (tag(b, "optional") or "false") == "true"
        if g and a and scope in ("compile", "runtime") and not opt:
            res.append((g, a, v))
    return res

seen = set()
def resolve(g, a, v, depth=0):
    if depth > 8:
        return
    key = f"{g}:{a}:{v}"
    if key in seen:
        return
    seen.add(key)
    allprops, pom = full_props(g, a, v)
    if pom is None:
        return
    # download this jar (skip if pom-only / missing)
    try:
        data = http(f"{BASE}/{g2p(g)}/{a}/{v}/{a}-{v}.jar")
        open(os.path.join(jar_dir, f"{a}-{v}.jar"), "wb").write(data)
    except Exception:
        pass
    mgmt = dep_mgmt_map(pom, allprops)
    for (dg, da, dv) in dep_blocks(pom):
        ver = dv
        if not ver:
            ver = mgmt.get(f"{dg}:{da}")
        ver = interpolate(ver or "", allprops)
        if ver and not re.search(r"\$\{", ver):
            resolve(dg, da, ver, depth + 1)
        else:
            print(f"  [skip] {dg}:{da}:{dv or mgmt.get(dg+':'+da)}", file=sys.stderr)

ga, ver = sys.argv[1].rsplit(":", 1)
g, a = ga.split(":")
print(f"Resolving {g}:{a}:{ver} ...", file=sys.stderr)
resolve(g, a, ver)

# Dedupe: same artifactId, keep HIGHEST version (Maven nearest-wins approx).
# Prevents stale transitive versions (e.g. asm-3.3.1 before asm-9.10.1) from
# shadowing the correct one on the classpath.
import re as _re
def ver_key(fn):
    m = _re.match(r"^(.*?)-(\d[^-]*?)(-[^-]*)?\.jar$", fn)
    if not m:
        return ("", 0, 0, 0, 0, 0, 0, fn)
    base, ver = m.group(1), m.group(2)
    nums = []
    for part in _re.split(r"[.\-_]", ver):
        n = ""
        for ch in part:
            if ch.isdigit():
                n += ch
            else:
                break
        nums.append(int(n) if n else 0)
    while len(nums) < 6:
        nums.append(0)
    return (base, nums[0], nums[1], nums[2], nums[3], nums[4], nums[5], fn)

alljars = sorted(f for f in os.listdir(jar_dir) if f.endswith(".jar"))
best = {}
for j in alljars:
    mk = _re.match(r"^(.*?)-\d[^-]*?(-[^-]*)?\.jar$", j)
    art = (mk.group(1) if mk else j[:-4]).lower()
    k = ver_key(j)
    if art not in best or k > best[art][0]:
        best[art] = (k, j)
kept = sorted(v[1] for v in best.values())
removed = sorted(set(alljars) - set(kept))
if removed:
    print(f"Deduped {len(removed)} older-duplicate jars: {removed}", file=sys.stderr)
cp = os.pathsep.join(os.path.join(jar_dir, j) for j in kept)
open(os.path.join(jar_dir, "classpath.txt"), "w").write(cp)
print(f"Downloaded {len(alljars)} jars; kept {len(kept)} after dedup.", file=sys.stderr)
print(cp)
