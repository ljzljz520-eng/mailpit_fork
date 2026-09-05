# 开箱即用垃圾邮件检测 - 产品需求文档

## Overview
- **Summary**: 为 Mailpit 新增一个内置的、开箱即用的垃圾邮件过滤器（spam filter）。无需任何外部服务（如 SpamAssassin），系统预置一组常见垃圾邮件/钓鱼邮件启发式规则，在邮件入库时自动评分；评分达到阈值的邮件自动打上 `spam` 标签，并在 Web UI 中提供与现有 SpamAssassin 面板风格一致的「Spam Filter」分析页（得分 + 命中规则明细）。同时支持用户通过 YAML 配置文件自定义规则、阈值、标签、黑白名单以及禁用内置规则。
- **Purpose**: Mailpit 现有 SpamAssassin 集成需要外部 SpamAssassin 服务或 Postmark API，开发/测试环境下通常不可用。用户希望零配置即可获得邮件「垃圾程度」的反馈，用于测试事务邮件模板、识别伪造/钓鱼特征，并能按自身场景扩展规则。
- **Target Users**: 使用 Mailpit 进行邮件开发与测试的开发者、QA；需要快速判断测试邮件是否会被判定为垃圾邮件的模板/活动邮件开发人员。

## Goals
- 零配置启用：默认开启，不依赖任何外部进程或网络服务。
- 预置覆盖常见垃圾/钓鱼特征的启发式规则（头部、正文、链接、附件、发件人）。
- 评分制：每条规则有分值，总分达到阈值判定为垃圾邮件（默认阈值 5.0，与 SpamAssassin 惯例一致）。
- 入库即检测：垃圾邮件自动打标签（默认 `spam`），可在标签导航与搜索中过滤；检测动作非破坏性（不拦截、不删除、不拒收 SMTP）。
- 用户可配置：YAML 文件支持自定义正则规则（目标字段：from/subject/body/header/附件名）、自定义分值、调整阈值、修改标签、禁用内置规则、白名单/黑名单。
- Web UI 提供消息级分析面板（得分环、命中规则表、帮助说明），并提供 API 端点返回结构化结果。
- 可通过 `--disable-spam-filter` 标志或 `MP_DISABLE_SPAM_FILTER` 环境变量完全关闭。

## Non-Goals
- 不做贝叶斯/机器学习训练、不做 RBL/DNS 实时黑名单查询、不做网络请求。
- 不拦截或拒收被判定为垃圾邮件的 SMTP 会话（Mailpit 是测试工具，邮件始终入库）。
- 不对升级前已入库的历史邮件回填标签（消息打开时仍可通过面板按需检测）。
- 不在 Web UI 中提供规则的在线增删改编辑界面（用户规则通过 YAML 文件配置，与 `--tags-config`、`--smtp-relay-config` 的既有模式一致）。
- 不替换或移除现有 SpamAssassin 外部集成；两者可共存（UI 中分别呈现）。
- 不修改 POP3、relay、forward 等其他子系统的行为。

## Background & Context
- 现有外部集成：[spamassassin.go](file:///Users/kkcarrot/swe-project/mailpit_fork/internal/spamassassin/spamassassin.go) 通过 spamc 或 Postmark API 返回 `Result{IsSpam, Error, Score, Rules}`；仅在配置 `--enable-spamassassin` 时注册 `/api/v1/message/{id}/sa-check` 路由，UI 面板 [SpamAssassin.vue](file:///Users/kkcarrot/swe-project/mailpit_fork/server/ui-src/components/message/SpamAssassin.vue) 按需请求。
- 入库管线：[messages.go](file:///Users/kkcarrot/swe-project/mailpit_fork/internal/storage/messages.go#L33-L211) 的 `Store()` 用 enmime 解析邮件、写库后组装 tags（X-Tags 头、plus 地址、用户名、`tagFilterMatches` 配置匹配），最终 `SetMessageTags` 并广播。新过滤器在此处加入垃圾标签最自然，且标签天然支持搜索与侧栏导航。
- 配置模式：[config.go](file:///Users/kkcarrot/swe-project/mailpit_fork/config/config.go) 集中定义配置变量与 `VerifyConfig()`；YAML 配置解析可参考 [tags.go](file:///Users/kkcarrot/swe-project/mailpit_fork/config/tags.go) 与 relay 配置；CLI 标志与环境变量在 [root.go](file:///Users/kkcarrot/swe-project/mailpit_fork/cmd/root.go) 中成对注册。
- 按需检测端点模式：[other.go](file:///Users/kkcarrot/swe-project/mailpit_fork/server/apiv1/other.go) 中 `HTMLCheck`/`LinkCheck`/`SpamAssassinCheck` 均为取原始邮件 → 运行检查 → JSON 返回；UI 配置通过 [application.go](file:///Users/kkcarrot/swe-project/mailpit_fork/server/apiv1/application.go) 的 `WebUIConfig` 下发（`SpamAssassin bool` 字段）。
- 前端面板挂载点：[MessageItem.vue](file:///Users/kkcarrot/swe-project/mailpit_fork/server/ui-src/components/message/MessageItem.vue) 中 Spam Analysis 标签页受 `mailbox.showSpamCheck && mailbox.uiConfig.SpamAssassin` 控制；显示偏好存于 [mailbox.js](file:///Users/kkcarrot/swe-project/mailpit_fork/server/ui-src/stores/mailbox.js) 的 localStorage 键；开关位于 AppSettings.vue。

## Functional Requirements
- **FR-1（内置引擎）**：新增 `internal/spamfilter` 包，提供 `Check(raw []byte)` 与基于已解析 enmime 信封的检测入口，返回 `Result{IsSpam, Score, Threshold, Rules[]}`；规则为本地启发式判断，无网络调用。
- **FR-2（预置规则）**：内置规则至少覆盖以下类别（分值可调，默认校准为：正常事务邮件 ≈ 0 分，明显垃圾/钓鱼邮件 ≥ 5 分）：
  - 头部：缺失 From、缺失 Date、缺失 Message-ID；From 显示名内嵌与实际地址域名不一致的邮箱（伪造显示名）；Reply-To 域名与 From 域名不一致；已带 `X-Spam-Flag: YES` / `X-Spam-Status: Yes` 头。
  - 主题：全大写（占比高且足够长）；连续感叹号/问号/美元符号；命中常见垃圾关键词（如 viagra、lottery、winner、free gift、nigerian prince、crypto investment 等，词边界匹配）。
  - 正文：命中垃圾关键词（按命中数量分档计分）；URL 数量过多；链接为裸 IP 地址；链接指向已知短链域名；HTML 超链接可见文本是 URL 但其域名与 href 域名不一致（链接伪装）。
  - 结构/钓鱼：HTML 含 `<form>`；HTML 含 `type="password"` 输入框；只有 HTML 无 text/plain 替代部分（低分值）。
  - 附件：可执行类型附件（exe/scr/js/vbs/bat/cmd/com/pif/jar/msi 等）；双扩展名（如 invoice.pdf.exe）。
- **FR-3（自动标签）**：邮件入库时运行检测；`IsSpam` 为真时自动追加可配置标签（默认 `spam`），标签经过现有标签清洗流程并可在侧栏/搜索中使用；标签名可配置为空字符串以关闭自动打标签。
- **FR-4（用户规则配置）**：通过 `--spam-filter-config <file>`（`MP_SPAM_FILTER_CONFIG`）加载 YAML，支持：
  - `threshold`（浮点，默认 5.0）：判定阈值；
  - `tag`（字符串，默认 `spam`）：垃圾邮件标签，空值关闭打标签；
  - `disable`（字符串列表）：按规则 ID 禁用内置规则；
  - `allowlist`（邮箱或域名列表）：命中则跳过所有规则、强制 0 分；
  - `blocklist`（邮箱或域名列表）：命中则直接判定为垃圾邮件；
  - `rules`（自定义规则列表）：每条含 `name`、`description`（可选）、`score`（浮点，可为负）、`pattern`（Go 正则表达式）、`target`（`from`/`subject`/`body`/`header`/`attachment`/`all` 之一；`header` 时需提供 `header` 头名）；正则默认大小写不敏感。
- **FR-5（配置校验）**：配置文件不存在、YAML 格式错误、正则编译失败、缺少必填字段时，`VerifyConfig()` 返回明确错误并阻止启动；规则 ID 冲突或未知禁用 ID 给出警告日志。
- **FR-6（API）**：新增 `GET /api/v1/message/{id}/spam-check`（`id` 支持 `latest`），返回 `SpamFilterResponse` JSON（IsSpam/Score/Threshold/Rules，规则含 Score/Name/Description/Builtin）；过滤器禁用时不注册该路由（与 sa-check 行为一致）。
- **FR-7（Web UI）**：消息详情页新增「Spam Filter」标签页（桌面导航 + 移动端下拉均可见），含得分环（按返回的 Threshold 渲染）、Spam/Not spam 徽章、命中规则明细表、帮助弹窗；标签页角标显示分数；AppSettings 中提供显示开关（localStorage 持久化，与 HTML Check / Link Check / Spam Analysis 开关并列）；过滤器禁用时整个标签页不出现。
- **FR-8（开关）**：`--disable-spam-filter`（`MP_DISABLE_SPAM_FILTER=true`）关闭后：不运行入库检测、不打标签、不注册 API 路由、`/api/v1/webui` 中 `SpamFilter=false`、UI 不显示面板。
- **FR-9（可观测性）**：启动时输出日志（如 `[spam-filter] enabled: 20 built-in rules, threshold 5.0`）；加载用户配置时输出规则数量；检测过程不产生致命错误（解析失败的邮件按既有 Store 逻辑处理）。

## Non-Functional Requirements
- **NFR-1（性能）**：入库检测为纯本地正则/字符串操作；对超大正文，扫描内容有上限（如正文/HTML 各截断至约 512KB 后再匹配），单封邮件检测开销不应对 SMTP 入库吞吐造成可感知影响。
- **NFR-2（安全）**：用户正则在启动时编译校验（fail-fast）；正则匹配针对有界输入；不引入任何新的出站网络请求；不新增外部依赖。
- **NFR-3（兼容性）**：不改变现有 API 响应结构（仅新增字段/端点）；SQLite/rqlite 均无需 schema 变更（复用标签体系）；与现有 SpamAssassin 集成共存互不影响。
- **NFR-4（可测试性）**：核心引擎与配置解析具备 Go 单元测试，覆盖典型垃圾邮件、正常邮件、自定义规则、黑白名单、禁用内置规则与非法配置。
- **NFR-5（一致性）**：代码风格、日志前缀（`[spam-filter]`）、swagger 注解、CLI/env 命名（`--spam-filter-*` / `MP_SPAM_FILTER_*`）与既有子系统保持一致。

## Constraints
- **Technical**: Go（后端）+ Vue 3（Options API，前端源码在 server/ui-src，esbuild 打包到 server/ui/dist）；邮件解析使用既有依赖 `github.com/jhillyerd/enmime/v2`；YAML 使用 `github.com/goccy/go-yaml`；不得引入新第三方依赖。
- **Business**: 动作非破坏性——测试工具中的邮件必须始终可投递、可查看；过滤器仅提供评分与标签。
- **Dependencies**: 无新依赖；复用 enmime、go-yaml、现有标签/配置/路由基础设施。

## Assumptions
- 默认开启自动打标签对用户是可接受的，因为标签是非破坏性的且可通过配置/标志关闭；阈值 5.0 与 SpamAssassin 惯例一致。
- 内置规则以英文垃圾邮件特征为主（SpamAssassin 规则生态本身以英文为主）；中文垃圾关键词可由用户自定义规则补充。
- 历史邮件不回填标签是可接受的（打开消息时面板按需实时检测）。
- 前端构建环境（node/npm）可用；若不可用则以 `npm run lint` 或既有构建脚本验证，Go 侧测试为必须。

## Acceptance Criteria

### AC-1: 过滤器默认开箱即用
- **Type**: `rule`
- **Given**: 不设置任何 spam filter 相关标志/环境变量/配置文件
- **When**: 启动 Mailpit 并通过 SMTP 发送一封邮件
- **Then**: 启动日志包含 `[spam-filter] enabled`；入库流程执行检测；`GET /api/v1/webui` 返回 `SpamFilter: true`；`GET /api/v1/message/{id}/spam-check` 返回 200 与结构化结果
- **Pass Condition**: 上述四项均可观察到
- **Evidence**: 启动日志输出、`/api/v1/webui` 与 `/spam-check` 的 curl/HTTP 响应

### AC-2: 明显垃圾邮件被判定并打标签，正常邮件不受影响
- **Type**: `rule`
- **Given**: 过滤器默认配置
- **When**: 分别发送 (a) 含 viagra/lottery 关键词 + 全大写主题 + HTML 表单/密码框的钓鱼邮件，(b) 带可执行附件（.exe）的邮件，(c) 链接文本域名与 href 域名不一致的邮件，(d) 一封正常事务邮件（普通 From/Date/Message-ID、纯文本或正常 multipart、无垃圾特征）
- **Then**: (a)(b)(c) 的 `/spam-check` 返回 `IsSpam=true` 且 Score ≥ 5.0、Rules 非空；这三封邮件入库后带 `spam` 标签；(d) 返回 `IsSpam=false`、Score < 5.0 且不带 `spam` 标签
- **Pass Condition**: 四类邮件判定结果全部符合
- **Evidence**: 单元测试断言 + API 响应 JSON + 消息标签列表

### AC-3: 用户自定义规则生效
- **Type**: `rule`
- **Given**: YAML 配置文件含一条自定义规则（如 `target: subject, pattern: "internal-alpha", score: 6`）并通过 `--spam-filter-config` 加载
- **When**: 发送主题含 "Internal-Alpha" 的正常邮件
- **Then**: `/spam-check` 返回该规则命中（Rules 中含自定义 name，Builtin=false）、Score ≥ 阈值、IsSpam=true 且邮件带 `spam` 标签；启动日志反映加载了 1 条自定义规则
- **Pass Condition**: 自定义规则命中并体现在评分/标签/日志中
- **Evidence**: 单元测试 + 启动日志 + API 响应

### AC-4: 白名单/黑名单/禁用内置规则/阈值与标签可配置
- **Type**: `rule`
- **Given**: YAML 中配置 allowlist（含某域名）、blocklist（含某域名）、disable（含某内置规则 ID）、`threshold: 3.0`、`tag: "junk"`
- **When**: 分别发送：来自白名单域名且含垃圾特征的邮件、来自黑名单域名的正常邮件、触发被禁用规则的邮件、评分 3.5 的邮件
- **Then**: 白名单邮件 Score=0、IsSpam=false、无标签；黑名单邮件 IsSpam=true 且带 `junk` 标签；被禁用规则不出现在 Rules 中；3.5 分邮件因阈值 3.0 被判 spam 并带 `junk` 标签
- **Pass Condition**: 四种配置行为全部符合
- **Evidence**: 单元测试断言

### AC-5: 非法配置 fail-fast
- **Type**: `rule`
- **Given**: YAML 中 `pattern` 为非法正则（如 `[a-z`），或配置文件路径不存在
- **When**: 启动 Mailpit（执行 VerifyConfig）
- **Then**: 进程返回错误并输出 `[spam-filter]` 前缀的明确错误信息，不以坏配置启动
- **Pass Condition**: 启动失败且错误信息指向具体配置问题
- **Evidence**: 单元测试（LoadConfig 返回错误）+ 手动启动错误输出

### AC-6: API 端点行为
- **Type**: `rule`
- **Given**: 过滤器启用
- **When**: 请求 `GET /api/v1/message/latest/spam-check` 与不存在消息的 `/api/v1/message/xxx/spam-check`
- **Then**: 前者返回 200 且 JSON 含 IsSpam/Score/Threshold/Rules 字段；后者返回 404；禁用过滤器时该路径返回 404（路由未注册）
- **Pass Condition**: 三种 HTTP 行为符合
- **Evidence**: HTTP 请求测试/手动 curl

### AC-7: Web UI 面板
- **Type**: `rule`
- **Given**: 过滤器启用、前端已构建
- **When**: 在浏览器中打开一封垃圾邮件和一封正常邮件
- **Then**: 消息详情出现「Spam Filter」标签页；打开后显示得分环（Spam 红色 / Not spam 绿色）、规则明细表与 Help 弹窗；标签角标显示分数；AppSettings 中可隐藏该面板（刷新后保持）；禁用过滤器时该标签页不出现
- **Pass Condition**: 上述 UI 元素与交互均可观察
- **Evidence**: 浏览器自动化截图/DOM 验证

### AC-8: 关闭开关
- **Type**: `rule`
- **Given**: 以 `--disable-spam-filter`（或 `MP_DISABLE_SPAM_FILTER=true`）启动
- **When**: 发送明显垃圾邮件
- **Then**: 邮件无 `spam` 标签；`/api/v1/webui` 返回 `SpamFilter: false`；`/spam-check` 路由 404；启动日志无 spam-filter enabled
- **Pass Condition**: 四项均成立
- **Evidence**: 启动日志 + API 响应 + 消息标签

### AC-9: 工程质量与回归
- **Type**: `rubric`
- **Dimension**: 代码与仓库一致性（包结构、命名、日志前缀、swagger 注解、测试覆盖、无新依赖）
- **Scale**: 1-5
- **Anchors**: 1 = 风格割裂、破坏现有构建/测试；3 = 功能可用但风格或测试有明显缺口；5 = 与现有子系统（spamassassin/htmlcheck/tags 配置）模式高度一致，测试齐备
- **Pass Threshold**: >= 4
- **Evidence**: `go build ./...`、`go vet ./...`、`go test ./...` 输出；前端 lint/build 输出；代码审查

## Open Questions
- 无阻塞性问题。内置规则的具体分值为默认校准值，后续可基于测试反馈微调。
