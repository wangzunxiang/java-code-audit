#!/usr/bin/env python3
"""Render findings.json / findings.csv into a self-contained Chinese Markdown
audit report. Every finding embeds its code snippet + file:line + rule + severity
+ fix hint inline (not just referenced).

Usage:
  python3 make_report.py --findings findings.json [--csv findings.csv] \
      --project /path/to/src --project-name myapp \
      --java-version "17 (Temurin)" --engines "semgrep 1.168.0; SpotBugs+findsecbugs 4.8.3" \
      [--note "SpotBugs 步骤跳过：项目无法编译"] \
      --out /mnt/f/hermesproject/<proj>/代码审计报告_<date>.md
"""
import argparse, json, os, sys, datetime, html

SEV_ZH = {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "INFO": "信息"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}

# simple fix hints keyed by keyword
FIX_HINTS = [
    (r"sql|statement|inject", "使用 PreparedStatement 参数化查询，禁止字符串拼接 SQL；对输入做白名单校验。"),
    (r"command|exec|processbuilder|rce", "避免拼接用户输入进 Runtime.exec/ProcessBuilder；如必须，用白名单参数并转义，或改用安全 API。"),
    (r"deserial|readobject|objectinputstream", "禁用不可信数据反序列化；ObjectInputFilter 白名单，或改用 JSON 等安全格式。"),
    (r"xxe|documentbuilder|sax|xml", "禁用 DTD 与外部实体：setFeature disallow-doctype-decl / external-general-entities=false。"),
    (r"path.?traversal|traversal|new file", "对文件路径做规范化并校验位于预期基目录内（canonicalPath startsWith 检查），禁止 ../。"),
    (r"ssrf", "对目标 URL 做协议白名单 + 内网地址黑名单（私有 IP/元数据 169.254.169.254），禁用重定向或校验重定向目标。"),
    (r"weak.?crypto|md5|des|ecb", "敏感数据改用 AES-GCM/SHA-256+HMAC，避免 MD5/DES/ECB；随机数用 SecureRandom。"),
    (r"hardcod|secret|password|api.?key", "移入密钥管理系统/环境变量，禁止硬编码；轮换已泄露的凭据。"),
    (r"redirect|forward|sendredirect", "对跳转目标做白名单校验，避免开放重定向。"),
]
def fix_hint(rule, msg):
    t = (rule + " " + msg).lower()
    for pat, hint in FIX_HINTS:
        import re as _re
        if _re.search(pat, t):
            return hint
    return "结合上下文人工复核并修复；参考 CWE 对应项。"

def snippet_block(f):
    snip = (f.get("snippet") or "").strip()
    if not snip:
        return "（无代码片段 — 字节码级发现，请打开文件定位）"
    return snip

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--project", default=".")
    ap.add_argument("--project-name", default="target")
    ap.add_argument("--java-version", default="未检测")
    ap.add_argument("--engines", default="semgrep")
    ap.add_argument("--note", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    findings = json.load(open(a.findings))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = []
    L.append(f"# 「{a.project_name}」Java 代码安全审计报告\n")
    L.append(f"> 生成时间：{now}  ")
    L.append(f"> 目标路径：`{os.path.abspath(a.project)}`  ")
    L.append(f"> Java 环境：{a.java_version}  ")
    L.append(f"> 扫描引擎：{a.engines}\n")
    if a.note:
        L.append(f"> ⚠️ 执行说明：{a.note}\n")

    L.append("\n## 一、结论摘要\n")
    L.append(f"共发现 **{len(findings)}** 项问题，按严重度分布：\n")
    L.append("| 严重度 | 数量 |")
    L.append("|:---:|:---:|")
    for s in SEV_ORDER:
        L.append(f"| {SEV_ICON.get(s,'')} {SEV_ZH.get(s,s)} | {counts.get(s,0)} |")
    L.append("")
    crit = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    if crit:
        L.append(f"**优先处置：{crit} 项严重/高危问题应优先修复。**\n")

    L.append("\n## 二、问题明细（按严重度分组）\n")
    for s in SEV_ORDER:
        group = [f for f in findings if f["severity"] == s]
        if not group:
            continue
        L.append(f"\n### {SEV_ICON.get(s,'')} {SEV_ZH.get(s,s)}（{len(group)} 项）\n")
        for i, f in enumerate(group, 1):
            loc = f"{f['file']}:{f['line_start']}"
            L.append(f"\n#### {SEV_ICON.get(s,'')} {s}-{i} · `{loc}`\n")
            L.append(f"- **规则**：`{f['rule']}`")
            L.append(f"- **引擎**：{f['engine']}")
            L.append(f"- **描述**：{f['message']}")
            L.append(f"- **修复建议**：{fix_hint(f['rule'], f['message'])}\n")
            L.append("```java")
            L.append(snippet_block(f).rstrip())
            L.append("```")

    L.append("\n## 三、建议修复优先级\n")
    L.append("1. 先修「严重」项（RCE / 反序列化 / SQL 注入 / 认证绕过），可在无认证下直接利用。\n")
    L.append("2. 再修「高危」项（SSRF / 路径遍历 / XXE / 弱加密）。\n")
    L.append("3. 「中危/低危」纳入迭代排期；低危多为代码质量项。\n")
    L.append("4. 修复后回归扫描确认问题清零，并补自动化门禁（CI 中跑 semgrep + spotbugs）。\n")

    L.append("\n## 四、免责声明\n")
    L.append("本工具仅辅助生成符合安全要求的审计结论，请结合本单位安全管理制度（如等保口令策略、漏洞修复时限、复测要求）使用。审计结果基于静态分析，存在漏报/误报可能，关键结论建议人工复核。\n")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out, "w", encoding="utf-8").write("\n".join(L))
    print("report written:", a.out, "findings:", len(findings))

if __name__ == "__main__":
    main()
