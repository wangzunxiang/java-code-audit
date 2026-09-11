# semgrep 规则：p/security-audit 的 Java 相关项 & 自定义规则

## 获取规则
```bash
# 在线（首次需联网拉取 registry，之后本地缓存）
semgrep scan --config p/security-audit .
# 离线/气隙：导出一份本地规则
semgrep --config p/security-audit --generate-config   # 或从 registry 页面保存 yml
# 用本地规则目录
semgrep scan --config ./rules .
```

## p/security-audit 中常见 Java 规则（check_id 片段 → 漏洞）
| check_id 关键词 | 漏洞 | 默认建议严重度 |
|---|---|---|
| `...sql...` / `formatted-sql-string` / `sql-injection` | SQL 注入（字符串拼接 / String.format 进 SQL） | CRITICAL |
| `...object-deserialization...` / `deserialization` | 不可信反序列化（readObject / XStream / YAML） | CRITICAL |
| `...command-injection...` / `command_injection` | RCE（Runtime.exec / ProcessBuilder 拼接） | CRITICAL |
| `...xxe...` / `xml-external-entity` | XXE（DocumentBuilder / SAX / Transformer） | HIGH |
| `...path-traversal...` / `path-traversal-in` | 路径遍历（new File 拼接用户输入） | HIGH |
| `...ssrf...` | SSRF（URL/HttpClient 用户可控） | HIGH |
| `...weak-crypto...` / `md5` / `des` / `ecb` | 弱加密 | HIGH |
| `...hardcoded-...` / `secret` / `password` | 硬编码凭据 | MEDIUM |
| `...open-redirect...` | 开放重定向 | MEDIUM |

> 实际 check_id 以 `semgrep scan --config p/security-audit --json` 输出为准；版本迭代可能改名。

## 自定义 Java 规则示例（追加到 rules/ 目录）
```yaml
rules:
  - id: java-jdbc-string-concat-sqli
    languages: [java]
    severity: ERROR
    message: 检测到 SQL 字符串拼接，可能 SQL 注入
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021-Injection"]
    patterns:
      - pattern: |
          $ST.executeQuery("..." + $X + "...")
      - metavariable-regex:
          metavariable: $X
          regex: .+
```
运行：`semgrep scan --config rules .`

## 降噪 / 作用域
```bash
semgrep scan --config p/security-audit \
  --exclude test --exclude target --exclude generated --exclude '**/vendor/**' .
# 或用 --include 限定 src
```

## 输出与退出码
- `--json` 结构化输出（path/start.line/end.line/extra.message/extra.lines/check_id）
- 退出码：0=无发现，1=有发现（非错误），2=用法/环境错误
