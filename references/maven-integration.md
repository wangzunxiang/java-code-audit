# Maven 集成：SpotBugs + Find Security Bugs

## POM（spotbugs-maven-plugin + findsecbugs 插件）
```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.github.spotbugs</groupId>
      <artifactId>spotbugs-maven-plugin</artifactId>
      <version>4.8.3.2</version>
      <configuration>
        <effort>Max</effort>
        <threshold>Low</threshold>
        <xmlOutput>true</xmlOutput>
        <xmlOutputDirectory>${project.build.directory}</xmlOutputDirectory>
        <excludeFilterFile>${project.basedir}/spotbugs-exclude.xml</excludeFilterFile>
      </configuration>
      <dependencies>
        <dependency>
          <groupId>com.h3xstream.findsecbugs</groupId>
          <artifactId>findsecbugs-plugin</artifactId>
          <version>1.13.0</version>
        </dependency>
      </dependencies>
    </plugin>
  </plugins>
</build>
```

## 运行
```bash
# 1) 编译出 .class
mvn -q compile -DskipTests
# 2) 跑 spotbugs（findsecbugs 已作为插件依赖加载）
mvn com.github.spotbugs:spotbugs-maven-plugin:4.8.3.2:check
#    生成 target/spotbugsXml.xml
```

## CI 门禁（GitHub Actions 片段）
```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: '17' }
      - run: mvn -q compile -DskipTests
      - run: mvn com.github.spotbugs:spotbugs-maven-plugin:4.8.3.2:check
      - uses: actions/upload-artifact@v4
        with: { name: spotbugs, path: target/spotbugsXml.xml }
```

## 排除规则（spotbugs-exclude.xml，降噪用）
```xml
<FindBugsFilter>
  <!-- 忽略测试代码 -->
  <Match><Class name="~.*Test.*"/></Match>
  <!-- 忽略自动生成的代码 -->
  <Match><Class name="~.*\.generated\..*"/></Match>
</FindBugsFilter>
```

## 版本配对
findsecbugs 插件必须与 SpotBugs 主版本兼容。若加载插件报错（`PluginClassLoader` / 版本不匹配），核对：
- spotbugs-maven-plugin 拉取的 spotbugs 核心版本（见 `~/.m2/repository/com/github/spotbugs/spotbugs/`）
- findsecbugs-plugin 版本（1.13.0 对应 spotbugs 4.x）
不匹配就升/降其中一个使其对齐。
