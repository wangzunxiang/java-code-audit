# 自测样例（含已知漏洞，仅用于验证工具）

`src/demo/Vuln.java` 故意包含 SQL 注入、命令注入、XXE、路径遍历、不安全反序列化、
弱加密、硬编码凭据、SSRF。用它做工具回归：

    semgrep scan --config p/security-audit --json . > scan.json
    python3 ../../scripts/aggregate.py --semgrep scan.json --project . --out-dir .
    python3 ../../scripts/make_report.py --findings findings.json --project . \
      --project-name vulnerable-app --out 审计报告.md

预期至少命中：SQL 注入(CRITICAL)、反序列化(CRITICAL)。
