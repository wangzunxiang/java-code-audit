# Java Code Audit — semgrep + SpotBugs + Find Security Bugs

可复用的 **Java 项目代码安全审计** 工作流：三引擎标准流程 + 自动聚合 + 自包含中文审计报告。

- **semgrep**：源码级快速 SAST，无需编译，覆盖 OWASP Top-10 的 Java 模式（SQL 注入、RCE、XXE、反序列化、SSRF、路径遍历、弱加密、硬编码凭据）。
- **SpotBugs + Find Security Bugs**：字节码级污点分析，跨方法数据流，输出 CWE/OWASP 编号（需编译出 `.class`）。
- **聚合 + 报告**：按 (文件,行,规则) 去重、按严重度排序，生成**证据内联**的中文 Markdown 报告（每条问题带 `文件:行` + 代码片段 + 规则 + 修复建议）。

> 本仓库同时是一个 **Hermes Agent skill**（见 `SKILL.md`）。既可作为 skill 装进 Hermes 直接说"审计这个 Java 项目"触发，也可把 `scripts/` 当独立 CLI 工具单独使用。

## 交付物

对每个被审计项目产出（默认 `F:\hermesproject\<project>/`）：

| 文件 | 说明 |
|---|---|
| `代码审计报告_<date>.md` | 自包含中文报告：结论摘要 + 按严重度分组的明细（证据内联）+ 修复优先级 + 免责声明 |
| `findings.csv` | 严重度, 类型/规则, 文件, 起始行, 结束行, 引擎, 描述, 修复建议, 代码片段 |
| `findings.json` | 结构化发现（可供 CI / 二次加工） |

## 快速开始（独立 CLI，不依赖 Hermes）

```bash
# 0) 前置：装 semgrep；SpotBugs 路径需要 JDK
pip3 install --user semgrep          # 若报 No module named 'attrs' → pip3 install --user --upgrade "attrs>=21.4"

# 1) semgrep 源码扫描（总能跑，无需编译）
semgrep scan --config p/security-audit --json --output semgrep_findings.json <项目路径>

# 2) SpotBugs + findsecbugs（需 .class，见 references/findsecbugs-setup.md / maven-integration.md）
#    产出 spotbugs.xml（无编译环境可跳过）

# 3) 聚合（去重 + 严重度排序 + 本地读真实代码片段）
python3 scripts/aggregate.py \
  --semgrep semgrep_findings.json \
  --spotbugs spotbugs.xml \
  --project <项目路径> \
  --out-dir <输出目录>

# 4) 生成自包含中文报告
python3 scripts/make_report.py \
  --findings <输出目录>/findings.json \
  --project <项目路径> --project-name 我的项目 \
  --java-version "17 (Temurin)" \
  --engines "semgrep 1.168.0; SpotBugs+findsecbugs 4.8.3" \
  --note "SpotBugs 步骤跳过：项目无法编译" \
  --out <输出目录>/代码审计报告_2026-09-11.md
```

## 作为 Hermes Agent skill 使用

把本仓库目录拷进 Hermes 的 skills 目录：

```bash
cp -r java-code-audit ~/.hermes/skills/cybersecurity/   # 或任意分类目录
```

之后在 Hermes 里直接说：
- "审计 /mnt/f/hermesproject/my-app 这个 Java 项目"
- "用 semgrep + spotbugs 扫一下这个 Spring 后端，出报告"

Hermes 会自动加载 `SKILL.md`，按标准流程执行并产出上述交付物。

## 目录结构

```
java-code-audit/
├── SKILL.md                      # Hermes skill 定义（触发条件 / 流程 / 陷阱）
├── scripts/
│   ├── aggregate.py              # semgrep JSON + spotbugs XML → 去重分级 findings (json/csv)
│   └── make_report.py            # findings → 自包含中文 Markdown 报告
├── references/
│   ├── report-template.md        # 报告结构 + 严重度判定标准 (rubric)
│   ├── maven-integration.md      # spotbugs-maven-plugin + findsecbugs POM + CI
│   ├── findsecbugs-setup.md      # 无构建系统时 SpotBugs+findsecbugs 手动安装
│   ├── semgrep-rules.md          # p/security-audit 的 Java 规则映射 + 自定义规则
│   └── tool-landscape.md         # 工具全景 TOP-10 + 选型（何时换/加引擎）
├── rules/                        # 可选：本地 semgrep 规则（离线/气隙用）
├── examples/vulnerable-app/      # 含已知漏洞的 Java 样例（自测用）
├── README.md
└── LICENSE
```

## 严重度标准

| 严重度 | 判定 | 典型 |
|:---:|------|------|
| 🔴 严重 | 未认证/低权限可直控 | RCE、不可信反序列化、用户可控 SQL 注入、认证绕过 |
| 🟠 高危 | 条件受限但危害大 | SSRF、路径遍历、XXE、SpEL 注入、弱加密 |
| 🟡 中危 | 需组合条件/间接危害 | 硬编码凭据、不安全默认、校验缺失 |
| 🟢 低危 | 代码质量/健壮性 | 潜在 NPE、资源泄漏、过时 API |

详见 `references/report-template.md`。

## 已知陷阱（务必读）

- **semgrep 别单传 `--lang`**（会报 `-e/--pattern and -l/--lang must both be specified`）；让语言自动检测，或 `--config` 搭配 `--lang java`。
- **旧版 `attrs` 会搞坏 semgrep**：症状 `No module named 'attrs'`，`pip3 install --user --upgrade "attrs>=21.4"` 修复。
- **SpotBugs 吃字节码不是源码**：没有 JDK 或项目编译不过 → 如实跳过并在报告注明，绝不编造字节码发现。
- **注册表规则把 `extra.lines` 红成 "requires login"**：`aggregate.py` 已改为按行号从本地源文件读真实代码片段。
- **代理/网络**：本类 WSL 主机出口走代理，GitHub 下载（JDK、spotbugs）慢，用 `curl -C -` 续传；首次 `p/security-audit` 需联网拉规则。

## 免责声明

本工具辅助生成符合安全要求的审计结论，请结合本单位安全管理制度（等保口令策略、漏洞修复时限、复测要求）使用。静态分析存在漏报/误报，关键结论建议人工复核。

## License

MIT
