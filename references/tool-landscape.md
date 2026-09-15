# Java 代码审计工具全景（选型速查）

> 本 skill 默认走 **semgrep + SpotBugs/findsecbugs** 双引擎（见 SKILL.md，已实测）。
> 本文回答"什么时候该换/加别的引擎"。数据来源：GitHub 实时榜单（2026-09），按 star 排序、
> 已过滤非代码审计干扰项。选型以「目标形态 + 是否需要编译 + 是否需要深度污点」三问为准。

## 三问选型
1. **目标是什么形态？** 源码（Maven/Gradle/散源码）→ 本 skill 主线；APK/字节码（无源码）→ mariana-trench；
   生产平台/持续集成 → sonar-java（需 SonarQube 服务端）。
2. **能编译出 `.class` 吗？** 能 → 跑 SpotBugs/findsecbugs（深度污点，CWE/OWASP 编号）；
   不能 → 只跑 semgrep（源码级，无需编译），报告如实注明跳过字节码步骤。
3. **需要多深的数据流？** 跨方法/跨类污点 → findsecbugs；研究/自研分析器 → Tai-e / WALA / Soot。

## TOP 10（按 star，2026-09）

| # | 工具 | 定位 | 本 skill 关系 |
|:---:|------|------|------|
| 1 | **semgrep** | 多语言模式 SAST，快，Java 一等公民 | ✅ 引擎一（源码级，总跑） |
| 2 | **spotbugs** | Java 字节码缺陷分析事实标准 | ✅ 引擎二底座 |
| 3 | **find-sec-bugs** | SpotBugs 安全插件，污点分析 | ✅ 引擎二安全层（总与 spotbugs 搭配） |
| 4 | **Tai-e** | Java/Android 静态分析**框架**，研究/自研 | 需自研分析器时用；不直接出漏洞报告 |
| 5 | **mariana-trench** (Meta) | Android/APK 安全静态分析（.trench 声明源→汇） | 目标是 APK 且无源码时换用它 |
| 6 | **sonar-java** | SonarQube/Cloud 的 Java 分析器，质量+安全 | 企业 CI 平台一体化时用；非命令行一把梭 |
| 7 | **momo-code-sec-inspector** | IDEA 插件，编码期实时审计+一键修复 | 开发期 IDE 内边写边审 |
| 8 | **JavaCodeAudit** (cn-panda) | 审计**教学**案例库（非工具） | 学原理/sink 点，不可扫项目 |
| 9 | **JavaSecLab** | 漏洞代码+修复+场景练习平台（靶场） | 练手/给扫描器做基准测试 |
| 10 | **WALA** | IBM 底层静态分析**库**（指针/调用图/切片） | 自研分析器底座；门槛高 |

## 紧随其后（专项）
| 工具 | 场景 |
|------|------|
| **log4j-detector** (mergebase) | Log4Shell 暴露面专项：检测 CVE-2021-44228/45046/45105/44832，能挖多层目录深处的 Log4J 实例 |
| **Java-Deserialization-Scanner** (federicodotta) | Burp 插件，反序列化**动态**检测+利用（ysoserial）；偏渗透非静态 |
| **JavaID** (Cryin) | 正则识别源码危险函数（XXE/反序列化/SSRF/SpEL/重定向）；轻量，2019 后未更 |
| **chanzi** (Chanzi-keji，铲子) | 中文 IDE 化 Java SAST：污点分析、免编译、支持反编译扫描、自定义 cypher 规则，覆盖 Spring/Struts/Dubbo/MyBatis/JSP，可导报告。商业产品（免费/付费），扫描不上传代码 |
| **SootTutorial** (noidsirius) | Soot 框架分步教程（学习驱动 Soot） |

## 场景 → 首选 → 搭配
| 你的目标 | 首选 | 搭配 |
|---------|------|------|
| CI 快速批量审计（一行命令） | **semgrep** | `p/security-audit` 规则包 |
| Java Web 后端安全审计（深度污点） | **find-sec-bugs + spotbugs** | Maven/Gradle 插件（本 skill 主线） |
| 找经典正确性 bug + 质量 | **spotbugs** / **sonar-java** | SonarQube |
| Android / APK 安全审计 | **mariana-trench** / **Tai-e** | — |
| 研究 / 写自己的分析器 | **Tai-e** / **WALA** | SootTutorial |
| 开发者 IDE 内边写边审 | **momo-code-sec-inspector** | SonarLint |
| 学 Java 审计原理 | **JavaCodeAudit** / **JavaSecLab** | — |
| 专项：Log4Shell 暴露面 | **log4j-detector** | — |
| 专项：反序列化（动态） | **Java-Deserialization-Scanner** | ysoserial |

## 局限提示（选型时一并告知用户）
- semgrep 单文件模式匹配快，但跨过程数据流弱于 findsecbugs；深污点靠 findsecbugs。
- findsecbugs 规则以"已知 sink"为主，0day 模式覆盖有限；需编译。
- Tai-e / WALA 是框架/库，无开箱即用漏洞规则 UI，面向研究。
- mariana-trench 主战场是 Android，纯 Java 服务端 Web 非其重点，构建较重。
- sonar-java 需部署 SonarQube 服务端，高级安全规则部分付费。
- momo / JavaID 2022/2019 后未更新，规则库可能滞后。

> 本 skill 不内置上述工具的安装/运行步骤（除 spotbugs/findsecbugs 主线）；
> 若用户明确要求换用某引擎，按其官方文档操作，并在报告中注明所用引擎与版本。
