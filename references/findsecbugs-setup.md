# 无构建系统时的 SpotBugs + Find Security Bugs 手动安装与运行

适用：散落的 `.java` 源码、无 pom/gradle，或 Maven 依赖拉不下来时。
**本文全部命令已在 2026-09-11 用 SpotBugs 4.10.4 + findsecbugs 1.14.0 + Temurin 17 实测跑通**（对含 8 类漏洞的样例检出 SQL_INJECTION/XXE/PATH_TRAVERSAL/COMMAND_INJECTION/DESERIALIZATION/SSRF/DES/ECB 等 17 条字节码发现）。

> **路径选择（先读）**：SpotBugs 官方 dist 压缩包只发布在 GitHub Releases
> （资产名是 `.tgz`/`.zip`，**不是** `.tar.gz`）。在出口走代理、GitHub 资产被
> 404 破坏的环境（本机 `127.0.0.1:3067`，adoptium 之外的 github.com 资产一律 404），
> **用「Maven 镜像拼装 classpath」路线 B**，不要用路线 A。

## 路线 B：从 Maven 镜像拼装 classpath（已实测，推荐）
SpotBugs 本体 `com.github.spotbugs:spotbugs` 及全部运行时依赖都在 Maven 仓库。
`scripts/fetch_maven_deps.py` 递归解析 pom（含 `<dependencyManagement>`、`${project.version}`
属性插值、parent 继承）下载所有 jar 并去重（同 artifact 只留最高版本——关键，否则
classpath 里 asm-3.3.1 压在 asm-9.10.1 前会报 `Unsupported class file major version`），
生成 `classpath.txt`。

```bash
# 1) JDK（清华 Adoptium 镜像，~190MB 约 1 分钟；代理直下 github 要 40+ 分钟或 404）
#    https://mirrors.tuna.tsinghua.edu.cn/Adoptium/17/jdk/x64/linux/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz
#    解到 ~/.local/share/android-tools/jdk17，export JAVA_HOME 指向它

# 2) 递归拉 spotbugs 依赖 jar（国内默认阿里云镜像，~45s；放后台，勿卡前台超时）
#    海外可 MAVEN_BASE=https://repo1.maven.org/maven2
MAVEN_BASE="https://maven.aliyun.com/repository/public" \
  python3 scripts/fetch_maven_deps.py "com.github.spotbugs:spotbugs:4.10.4" /tmp/sbjars
#    → 生成 /tmp/sbjars/classpath.txt（约 42 个去重后 jar）

# 3) findsecbugs 插件 jar（Maven 镜像，秒级）
curl -sL -o /tmp/findsecbugs-1.14.0.jar \
  "https://maven.aliyun.com/repository/public/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar"

# 4) 编译源码为 .class（见下「编译」节；输出到 out/）

# 5) 跑 SpotBugs（主类名是 LaunchAppropriateUI，不是 LauncherApp！）
export JAVA_HOME=~/.local/share/android-tools/jdk17
CP="$(cat /tmp/sbjars/classpath.txt):/tmp/findsecbugs-1.14.0.jar"
$JAVA_HOME/bin/java -Xmx2g -cp "$CP" edu.umd.cs.findbugs.LaunchAppropriateUI \
  -textui -effort:max \
  -pluginList /tmp/findsecbugs-1.14.0.jar \
  -xml:withMessages -output spotbugs.xml out
# EXIT 0；spotbugs.xml 含全部 <BugInstance>
```

findsecbugs 对 spotbugs 是 `provided` 依赖（运行时由 classpath 提供），把插件 jar 追加
到 classpath 并用 `-pluginList` 指定即可，无需它自带依赖。

## 路线 A：官方 dist（网络能直连 GitHub 资产时）
```bash
# 资产名 .tgz（不是 .tar.gz）
curl -sL -o /tmp/spotbugs.tgz "https://github.com/spotbugs/spotbugs/releases/download/v4.10.4/spotbugs-4.10.4.tgz"
mkdir -p ~/.local/share/spotbugs && tar -xzf /tmp/spotbugs.tgz -C ~/.local/share/spotbugs --strip-components=1
~/.local/share/spotbugs/bin/spotbugs -version
```
> dist 自带的 `bin/spotbugs` 脚本等价于路线 B 的 `java -cp … LaunchAppropriateUI`，
> 参数语法相同。

## 参数语法（实测踩坑，别照抄网上旧文档）
- 主类：`edu.umd.cs.findbugs.LaunchAppropriateUI`（旧文档写的 `LauncherApp` 不存在）
- effort：`-effort:max`（冒号 + 小写；`-effort:Max` 会触发 usage 报错）
- 无 GUI 主机必加 `-textui`
- XML 输出：`-xml:withMessages`（**不是** `-xml:withLocations`，那个不合法会报 usage）
- 被扫描的 class 目录放在参数**末尾**
- 报错只显示 usage 无细节时：`java -cp $CP edu.umd.cs.findbugs.LaunchAppropriateUI -version`
  能干净退出(0) 说明 classpath/主类 OK，问题在扫描参数语法

## 编译
```bash
export JAVA_HOME=~/.local/share/android-tools/jdk17; export PATH=$JAVA_HOME/bin:$PATH
mkdir -p out
javac -d out $(find src -name '*.java')   # 第三方 jar 依赖加 -cp "libs/*"
```
> 项目编译不过（缺依赖）⇒ 跳过 SpotBugs 步骤并在报告「执行说明」注明，semgrep 源码
> 发现仍有效。不要编造字节码发现。

## 版本配对（2026-09 实测）
- SpotBugs **4.10.4** ↔ findsecbugs **1.14.0**（findsecbugs pom 对 spotbugs 为 provided，
  无版本硬冲突）。4.8.3 ↔ 1.13.0 亦可。
- `asm` 版本冲突是路线 B 最大坑：fetch 脚本已做「同 artifact 留最高版本」去重，
  手动拼 classpath 时务必确保 asm-9.x 在 asm-3.x 之前（或直接删掉 asm-3.x）。

## 发现类型（findsecbugs，安全为主）
`SQL_INJECTION_JDBC` / `PATH_TRAVERSAL_IN` / `XXE_DOCUMENT` / `COMMAND_INJECTION` /
`OBJECT_DESERIALIZATION` / `URLCONNECTION_SSRF_FD` / `DES_USAGE` / `ECB_MODE` /
`CIPHER_INTEGRITY` / `WEAK_TRUST_MANAGER` / `HARDCODED_KEY_MATERIAL` 等。
aggregate.py 里映射为 CRITICAL/HIGH。

## 聚合与报告
```bash
# --srcroot 用于把 spotbugs 的类名映射回源文件内联真实代码
#   maven 项目: --srcroot src/main/java ；散源码: --srcroot src
python3 scripts/aggregate.py --semgrep scan.json --spotbugs spotbugs.xml \
  --project . --srcroot src --out-dir .
python3 scripts/make_report.py --findings findings.json --project . \
  --project-name "MYPROJ" --engines "semgrep X; SpotBugs 4.10.4 + findsecbugs 1.14.0" \
  --out 代码审计报告.md
```
> 注意：SpotBugs XML 里每个 `<BugInstance>` 有**两个** SourceLine——直接子节点是真实
> 方法行号，嵌套在 `<Class>/<BugPattern>` 里的是 class 声明行（恒为 11）。必须取
> 直接子节点（`bug.find("SourceLine")`），否则所有发现塌到同一行。
