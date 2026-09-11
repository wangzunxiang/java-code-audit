# 无构建系统时的 SpotBugs + Find Security Bugs 手动安装与运行

适用：散落的 `.java` 源码、无 pom/gradle，或 Maven 依赖拉不下来时。

## 1) 安装 SpotBugs（dist 压缩包）
```bash
# 查最新版（GitHub release）
# https://github.com/spotbugs/spotbugs/releases  取 spotbugs-4.8.x.tar.gz
curl -sL -o /tmp/spotbugs.tar.gz "https://github.com/spotbugs/spotbugs/releases/download/v4.8.3/spotbugs-4.8.3.tar.gz"
mkdir -p ~/.local/share/spotbugs
tar -xzf /tmp/spotbugs.tar.gz -C ~/.local/share/spotbugs --strip-components=1
~/.local/share/spotbugs/bin/spotbugs -version     # 需 JAVA_HOME 指向 JDK
```

## 2) 安装 Find Security Bugs 插件
```bash
# 从 Maven Central 下载插件 jar（含依赖 jar 一并放入插件目录）
curl -sL -o /tmp/findsecbugs.jar \
  "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.13.0/findsecbugs-plugin-1.13.0.jar"
mkdir -p ~/.local/share/findsecbugs
cp /tmp/findsecbugs.jar ~/.local/share/findsecbugs/
# 该插件依赖 spotbugs 核心，通常无需额外 jar；若加载失败，补下载其 POM 里的依赖
```

## 3) 编译源码为 .class
```bash
export JAVA_HOME=~/.local/share/android-tools/jdk17
export PATH=$JAVA_HOME/bin:$PATH
mkdir -p out
javac -d out $(find /path/to/src -name '*.java')
# 第三方 jar 依赖需要的话加 -cp "libs/*"
```
> 项目编译不过（缺依赖）⇒ 跳过 SpotBugs 步骤并在报告「执行说明」注明，semgrep 源码发现仍然有效。不要编造字节码发现。

## 4) 运行
```bash
~/.local/share/spotbugs/spotbugs/bin/spotbugs \
  -textui -effort:Max \
  -pluginList ~/.local/share/findsecbugs/findsecbugs-plugin-1.13.0.jar \
  -xml:withLocations -output spotbugs.xml out
```
- `-textui` 无 GUI 主机必备
- 输出 `spotbugs.xml` 交给 `scripts/aggregate.py --spotbugs spotbugs.xml`

## 5) 找全发现（可选）
findsecbugs 的发现类型（type）以安全漏洞为主，例如：
`SQL_PREPARESTATEMENT_MANUAL` / `PATH_TRAVERSAL_IN` / `XXE` / `COMMAND_INJECTION` /
`DESERIALIZATION_OF_UNTRUSTED_DATA` / `WEAK_TRUST_MANAGER` / `HARDCODED_KEY_MATERIAL`。
这些在 aggregate.py 里会被映射为 HIGH/CRITICAL。

## 版本配对
spotbugs 4.8.x ↔ findsecbugs 1.13.0。加载插件报 `PluginClassLoader`/版本错误时，对齐两者版本（见 maven-integration.md 的版本配对节）。
