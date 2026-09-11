---
name: java-code-audit
description: "Statically audit Java codebases for security vulnerabilities and defects using semgrep, SpotBugs + Find Security Bugs, and produce an evidence-backed Chinese Markdown report. Use when the user asks to audit/scan/assess a Java (or Spring/Struts/Dubbo/MyBatis) project for SQL injection, RCE, XXE, deserialization, SSRF, path traversal, weak crypto, and classic bugs, or wants a reusable Java SAST workflow."
version: 1.1.0
author: wangzunxiang
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [java, sast, code-audit, semgrep, spotbugs, find-sec-bugs, owasp, security, java-security, static-analysis]
    related_skills: [automated-pentest, report-generation, apk-static-analysis, cybersecurity-skills-library]
---

# Java Code Audit (semgrep + SpotBugs + Find Security Bugs)

Static security audit of Java projects with a standard three-engine workflow:

1. **semgrep** — fast pattern-based SAST, source-level, no compile needed. Catches OWASP Top-10 Java patterns (SQLi, RCE, XXE, deserialization, SSRF, path traversal, weak crypto, hardcoded secrets).
2. **SpotBugs + Find Security Bugs (findsecbugs)** — bytecode-level taint analysis. Needs compiled `.class` files. Deep cross-method dataflow, reports CWE/OWASP IDs.
3. **Evidence + Report** — per-finding code location, the rule, a snippet, and a severity, written into a self-contained Chinese Markdown report (findings embedded inline, not just referenced).

Default deliverable path: `F:\hermesproject\` → WSL `/mnt/f/hermesproject/<project-name>/`.

## Trigger examples
- "审计这个 Java 项目" / "扫一下这个 Spring 后端有没有注入漏洞"
- "用 semgrep / spotbugs 跑一遍代码审计，出报告"
- "check this Java repo for SQLi / RCE / XXE / deserialization"

## When to use / not use
- USE: source-available Java projects (Maven/Gradle or loose `.java` files). Best for CI-style batch audit + report.
- DON'T USE for: closed-source APKs (use `apk-static-analysis` / `mariana-trench`), pure dynamic/running-app testing (use `automated-pentest`), or non-Java codebases (drop to semgrep-only, `--lang` auto).

## Prerequisites (verify BEFORE scanning, never assume)

```bash
# 1) semgrep
~/.local/bin/semgrep --version || pip3 install --user semgrep
# If it dies with "No module named 'attrs'": the user site has an OLD attrs.
#   pip3 install --user --upgrade "attrs>=21.4"   (trufflehog3 pins 20.3.0 — that conflict is acceptable)

# 2) JDK (SpotBugs path needs javac + a JDK 8/11/17). No java? Install Temurin:
java -version 2>/dev/null || echo "NO_JAVA"
#   Fast source: TUNA Adoptium mirror (github.com assets 404/slow behind this proxy):
#   https://mirrors.tuna.tsinghua.edu.cn/Adoptium/17/jdk/x64/linux/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz
#   extract to ~/.local/share/android-tools/jdk17 and export JAVA_HOME. (~1 min, vs 40+ min direct)

# 3) SpotBugs + findsecbugs plugin (download the dist tarball; needs network)
ls ~/.local/share/spotbugs/spotbugs/bin/spotbugs 2>/dev/null || echo "NO_SPOTBUGS"
```

If a prerequisite is missing and **cannot** be installed in this environment, say so plainly and run the subset that IS available (semgrep always works source-only; SpotBugs only if you can produce `.class`). Never fabricate findings.

## Workflow

### Step 0 — Recon the target
```bash
cd /mnt/f/hermesproject/<project>      # or wherever the source is
# Is it a build project or loose sources?
ls pom.xml build.gradle settings.gradle 2>/dev/null
find . -name '*.java' -not -path '*/target/*' | wc -l
grep -rl "springframework\|struts\|dubbo\|mybatis" --include=*.java . | head
```
Record: build system (maven/gradle/none), Java count, frameworks detected. This determines whether the SpotBugs path is runnable (needs a successful compile to `.class`).

### Step 1 — semgrep (source-level, always run)
```bash
# One-liner, all languages auto-detected (drop --lang; passing it alone errors)
~/.local/bin/semgrep scan --config p/security-audit \
  --json --output semgrep_findings.json .
# Also grab human-readable for the report body:
~/.local/bin/semgrep scan --config p/security-audit . 2>/dev/null | tee semgrep_human.txt
```
Notes:
- `--config p/security-audit` pulls the public registry ruleset (needs network on first use; cached after). For offline/air-gapped: `--config auto` or a local `.semgrep.yml`.
- Exit code 1 = findings present (NOT an error); 0 = clean; 2 = usage error.
- Parse `semgrep_findings.json`: each finding has `check_id`, `path`, `start.line`, `end.line`, `extra.message`, `extra.lines`.

### Step 2 — SpotBugs + Find Security Bugs (bytecode, if compilable)
Only run if you have a JDK AND can produce `.class` files.

**Maven:**
```bash
export JAVA_HOME=~/.local/share/android-tools/jdk17
export PATH=$JAVA_HOME/bin:$PATH
mvn -q compile -DskipTests
# spotbugs-maven-plugin + findsecbugs (see references/maven-integration.md for the POM)
mvn -q com.github.spotbugs:spotbugs-maven-plugin:4.8.3.2:check \
  -Dspotbugs.includeFilterFile=references/findsecbugs-filter.xml \
  -Dspotbugs.excludeBugsInProgress=false
# XML report: target/spotbugsXml.xml
```

**Gradle** or **no build system (loose .java):** compile manually then run the SpotBugs CLI. The GitHub dist tarball 404s behind this host's proxy, so the proven path is to **assemble the classpath from a Maven mirror** (`scripts/fetch_maven_deps.py`) and run the main class directly — full tested commands in `references/findsecbugs-setup.md`. Short form:
```bash
# compile all sources to ./out (match package dirs, e.g. src/demo/Vuln.java -> out/demo/Vuln.class)
javac -d out $(find src -name '*.java')
# fetch deps + plugin (see reference), then:
CP="$(cat /tmp/sbjars/classpath.txt):/tmp/findsecbugs-1.14.0.jar"
$JAVA_HOME/bin/java -Xmx2g -cp "$CP" edu.umd.cs.findbugs.LaunchAppropriateUI \
  -textui -effort:max -pluginList /tmp/findsecbugs-1.14.0.jar \
  -xml:withMessages -output spotbugs.xml out
```
If the project will not compile (deps unavailable), **skip Step 2 and say so** — semgrep source findings still stand. Do not report bytecode findings you didn't actually produce.

### Step 3 — Aggregate + severity-rank
Run `scripts/aggregate.py` (see scripts/) to merge `semgrep_findings.json` (+ `spotbugs.xml` if present) into a deduped, severity-sorted list. Rules of thumb:
- **Critical**: RCE / command injection / deserialization of untrusted data / SQLi with user input / auth bypass.
- **High**: SSRF, path traversal, XXE, template/SpEL injection, weak crypto (MD5/DES/ECB for sensitive data).
- **Medium**: hardcoded secrets/keys, insecure defaults, missing validation.
- **Low/Info**: code-quality bugs from SpotBugs (NPE risk, resource leaks), deprecated APIs.
Dedupe by (file, line, vuln-type) across engines — semgrep + findsecbugs often flag the same sink twice.

### Step 4 — Write the report
Use `scripts/make_report.py` or follow `references/report-template.md`. Requirements:
- Self-contained: each finding embeds the **code snippet + file:line + rule + severity + fix suggestion** inline (do not just reference external files).
- 中文正文（技术命令/代码/规则 ID 可保留英文），按 严重度分组，顶部给汇总表（总数 + 各严重度计数 + 引擎来源）。
- 顶部注明：扫描引擎与版本、目标路径、Java 版本、扫描时间、以及**哪些步骤实际跑了**（例如 "SpotBugs 步骤跳过：项目无法编译"）。
- 末尾给「建议修复优先级」和「免责声明」（结合单位安全管理制度）。
- Save to `/mnt/f/hermesproject/<project>/代码审计报告_<date>.md`.

### Step 5 — Verify before claiming done
- Re-open the report, confirm every finding has file:line + snippet.
- If the user asked for evidence screenshots or a CSV, produce them (CSV columns: 严重度, 类型, 文件, 行号, 规则, 描述, 修复建议).
- Confirm the reported file path(s) exist and are the final artifacts.

## Pitfalls (learned the hard way — read before scanning)
- **semgrep `--lang` alone errors.** `--config` must be present; do NOT pass `--lang` by itself ("`-e/--pattern and -l/--lang must both be specified`"). Let it auto-detect, or pair `--lang java` with a `--config`.
- **stale `attrs` breaks semgrep on some hosts.** Symptom: `ModuleNotFoundError: No module named 'attrs'`. Fix: `pip3 install --user --upgrade "attrs>=21.4"`. A `trufflehog3` pin warning afterwards is harmless.
- **SpotBugs needs compiled bytecode, not source.** No JDK or a project that won't compile ⇒ skip Step 2 honestly, don't invent findings.
- **Proxy / network:** this WSL host routes egress through `127.0.0.1:3067`. GitHub *asset* downloads (JDK from adoptium's release, spotbugs `.tgz`) are slow or **404** over it. Fix: pull the JDK from a TUNA/Alibaba mirror and assemble SpotBugs from a Maven mirror (`scripts/fetch_maven_deps.py`, `MAVEN_BASE=https://maven.aliyun.com/repository/public`) — both are fast direct. api.github.com GET and repo1.maven.org / maven.aliyun.com work direct.
- **asm version conflict (路线 B killer):** the raw dependency tree pulls BOTH asm-3.3.1 and asm-9.x; if 3.3.1 lands first on the classpath you get `Unsupported class file major version 61`. `fetch_maven_deps.py` already dedupes same-artifact to the highest version — if you build the classpath by hand, delete the low asm or order it after the high one.
- **SpotBugs main class is `LaunchAppropriateUI`** (not `LauncherApp`), `-effort:max` (colon+lowercase), `-xml:withMessages` (not `withLocations`). Full tested syntax in `references/findsecbugs-setup.md`.
- **Registry vs local rules:** `p/security-audit` is fetched from semgrep.dev registry; in air-gapped envs ship a `rules/` dir with the needed `.yml` and use `--config rules/`.
- **findsecbugs version pinning:** the plugin version must match the SpotBugs version it was built against; if the plugin fails to load, check `~/.local/share/spotbugs` vs the findsecbugs jar version (see references/findsecbugs-setup.md).
- **Large repos:** semgrep on a huge monorepo can be slow; scope with `--include` / `--exclude` (e.g. skip `test/`, `generated/`, vendored libs) before a full sweep.
- **Severity is a judgment call** — a "SQLi" pattern hit on a constant query string is a false positive; read the snippet before assigning Critical. Mark suspected FPs as Info and say why.

## Files
- `scripts/fetch_maven_deps.py` — resolve + download a Maven artifact's full runtime dep tree (with `<dependencyManagement>`, `${project.version}`, parent inheritance, same-artifact dedupe) → `classpath.txt`. Used to run SpotBugs CLI when the GitHub dist 404s.
- `scripts/aggregate.py` — merge semgrep JSON + spotbugs XML → deduped ranked findings (JSON + CSV). Pass `--srcroot` (maven: `src/main/java`) so SpotBugs bytecode findings inline real source code.
- `scripts/make_report.py` — findings JSON/CSV → self-contained Chinese Markdown report.
- `references/report-template.md` — report structure + severity rubric.
- `references/maven-integration.md` — spotbugs-maven-plugin + findsecbugs POM + CI snippets.
- `references/findsecbugs-setup.md` — manual SpotBugs + findsecbugs CLI install/run (no build system); fully tested command set.
- `references/semgrep-rules.md` — which p/security-audit Java rules map to which vuln; how to add a custom rule.
