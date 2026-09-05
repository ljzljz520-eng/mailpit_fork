# 开箱即用垃圾邮件检测 - 实施计划

## Task 1: 内置垃圾邮件过滤引擎核心（internal/spamfilter）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 新建 `internal/spamfilter/spamfilter.go`：包级状态（`Enabled` 默认 true、`threshold`、`tag`、规则集合）、`Result{IsSpam, Score, Threshold, Rules}` 与 `Rule{Score, Name, Description, Builtin}`（带 swagger:model 注解）。
  - 归一化 `message` 结构（From 地址/域名/显示名、Reply-To、header 访问器、Subject、Text、HTML、附件文件名、链接对），支持从 `*enmime.Envelope` 构建。
  - 实现 `Check(raw []byte) (Result, error)` 与 `CheckEnvelope(env) Result`：白名单短路 → 黑名单强制 spam → 规则累加评分 → 阈值判定；正文扫描截断 512KB。
  - 提供 `Tag()`、`Threshold()`、`RuleCounts()` 访问器。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-6
- **Test Requirements**:
  - `rule` TR-1.1: 钓鱼邮件返回 IsSpam=true、Score≥5、Rules 非空；证据：TestCheckPhishingMessage 通过（score 21.7）。
  - `rule` TR-1.2: 正常事务邮件 IsSpam=false、Score<阈值；证据：TestCheckHamMessage 通过（0 分）。
  - `rule` TR-1.3: .exe 附件、链接伪装、裸 IP、短链、双扩展名、X-Spam-Flag 分别命中；证据：TestExecutableAndDoubleExtension、TestUpstreamSpamFlag、TestCheckPhishingMessage 通过。
  - `rule` TR-1.4: 2MB 正文不 panic、快速完成；证据：TestLargeBodyDoesNotPanic 通过（0.03s）。
- **Completion Evidence**:
  - `go test ./internal/spamfilter/` 全部通过；E2E 中 `/api/v1/message/latest/spam-check` 返回结构化结果（IsSpam/Score/Threshold/Rules）。

## Task 2: 预置内置规则集
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新建 `internal/spamfilter/rules_builtin.go`，实现 20 条内置规则（ID/描述/分值）：头部 6 条（MISSING_FROM 2.0、MISSING_DATE 1.0、MISSING_MESSAGE_ID 1.0、FORGED_FROM_DISPLAY_NAME 2.5、REPLYTO_DOMAIN_MISMATCH 1.5、X_SPAM_FLAG_SET 5.0）；主题 3 条（SUBJECT_ALL_CAPS 1.2、SUBJECT_EXCESSIVE_PUNCTUATION 1.5、SUBJECT_SPAM_PHRASE 2.5）；正文/链接 6 条（BODY_SPAM_PHRASE 1.5、BODY_SPAM_PHRASES_MANY 2.0、BODY_EXCESSIVE_URLS 1.5、URL_RAW_IP 1.5、URL_SHORTENER 1.0、LINK_DOMAIN_MISMATCH 2.5）；结构/钓鱼 3 条（HTML_FORM 2.5、HTML_PASSWORD_INPUT 3.0、HTML_NO_TEXT_ALTERNATIVE 0.5）；附件 2 条（ATTACHMENT_EXECUTABLE 5.0、ATTACHMENT_DOUBLE_EXTENSION 2.0）。
  - 垃圾关键词表词边界大小写不敏感匹配；短链域名表（bit.ly、tinyurl.com、t.co 等 12 个）。
  - 规则可通过 YAML `disable` 按 ID 关闭。
  - 校准说明（测试后调整）：X_SPAM_FLAG_SET 4.0→5.0、ATTACHMENT_EXECUTABLE 3.0→5.0，确保单一强信号即可达阈值；RE2 不支持反向引用，重复标点规则改用 `[!?$]{3,}` 字符类（不含 `.`，避免省略号误报）。
- **Acceptance Criteria Addressed**: AC-2
- **Test Requirements**:
  - `rule` TR-2.1: 每条规则有命中用例；证据：测试覆盖 FORGED_FROM_DISPLAY_NAME/REPLYTO_MISMATCH/ALL_CAPS/PUNCTUATION/SPAM_PHRASE/HTML_FORM/PASSWORD/URL_RAW_IP/SHORTENER/LINK_MISMATCH/EXECUTABLE/DOUBLE_EXT/X_SPAM_FLAG/MISSING_HEADERS/HTML_NO_TEXT_ALTERNATIVE。
  - `rule` TR-2.2: 正常事务邮件总分 <5；证据：TestCheckHamMessage、storage TestSpamFilterAutoTagging（ham 无 spam 标签）。
- **Completion Evidence**:
  - E2E 钓鱼邮件命中 11 条规则（21.7 分）；正常邮件 0 分 "No rules triggered."。

## Task 3: YAML 用户规则配置解析与校验
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1, Task 2
- **Description**:
  - 新建 `internal/spamfilter/config.go`：`LoadConfig(path)` 支持 threshold/tag/disable/allowlist/blocklist/rules；非法正则、缺失 name/pattern、非法 target、header target 缺 header、文件缺失/YAML 错误均返回错误；未知 disable ID 与内置 ID 冲突给警告；allowlist/blocklist 支持域名（含子域、`*.` 前缀）与完整邮箱；自定义规则正则大小写不敏感，target 支持 from/subject/body/header/attachment/all。
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-5
- **Test Requirements**:
  - `rule` TR-3.1: 白名单强制 0 分、黑名单 BLOCKLIST 命中、禁用规则不出现、自定义规则 Builtin=false、阈值与标签生效；证据：TestLoadConfigAllowBlockListsAndDisable、TestLoadConfigCustomRule、TestLoadConfigHeaderRule 通过；E2E 中 tag `junk`、threshold 3.0、19 built-in + 1 custom 日志验证。
  - `rule` TR-3.2: 非法配置返回错误；证据：TestLoadConfigErrors 6 个子用例通过；E2E 错误输出 `[spam-filter] rule "broken" has an invalid pattern...` 且启动中止。
  - `rule` TR-3.3: 空路径恢复默认；证据：TestLoadConfigEmptyPath 通过。
- **Completion Evidence**:
  - E2E：自定义规则邮件打 `junk` 标签、黑名单邮件 `junk`、白名单垃圾内容无标签；启动日志 `enabled: 19 built-in rules, 1 custom rules, threshold 3.0`。

## Task 4: config / CLI 标志 / 环境变量集成
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3
- **Description**:
  - `config/config.go`：新增 `DisableSpamFilter bool` 与 `SpamFilterConfigFile string`；`VerifyConfig()` 中启用时 `spamfilter.LoadConfig`（失败返回错误阻止启动）并输出 `[spam-filter] enabled: N built-in rules, M custom rules, threshold X.X`；禁用时置 `spamfilter.Enabled=false` 并输出 `[spam-filter] disabled`。
  - `cmd/root.go`：注册 `--disable-spam-filter`、`--spam-filter-config`；环境变量 `MP_DISABLE_SPAM_FILTER`、`MP_SPAM_FILTER_CONFIG`。
- **Acceptance Criteria Addressed**: AC-1, AC-5, AC-8
- **Test Requirements**:
  - `rule` TR-4.1: `go build ./...` 通过，`--help` 含两个新标志；证据：help 输出显示 `--disable-spam-filter` 与 `--spam-filter-config`。
  - `rule` TR-4.2: 非法配置启动报错；证据：E2E 错误日志且服务未启动。
  - `rule` TR-4.3: `--disable-spam-filter` 输出 `[spam-filter] disabled`；证据：E2E 日志。
- **Completion Evidence**:
  - 构建/vet 通过；E2E 三种启动配置（默认/禁用/自定义）行为均符合预期。

## Task 5: 入库检测与自动打标签（storage）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - `internal/storage/messages.go` Store() 标签组装阶段加入：`spamfilter.Enabled` 时 `CheckEnvelope(env)`，IsSpam 且 Tag() 非空则追加标签，随现有 `sortedUniqueTags`/`SetMessageTags` 流程落库；debug 日志记录分数。无数据库 schema 变更。
- **Acceptance Criteria Addressed**: AC-2, AC-3, AC-4, AC-8
- **Test Requirements**:
  - `rule` TR-5.1: 启用时垃圾邮件 Tags 含 spam、正常不含；证据：TestSpamFilterAutoTagging 通过；E2E 列表 API 显示 `['spam']` / `[]`。
  - `rule` TR-5.2: 禁用时不打标签；证据：同测试禁用分支通过；E2E `--disable-spam-filter` 邮件标签为 `[]`。
- **Completion Evidence**:
  - 全量 `go test ./...` 中 storage 包 16.6s 全部通过。

## Task 6: API 端点、webui 配置与 swagger 注解
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 1, Task 4
- **Description**:
  - `server/apiv1/other.go` 新增 `SpamFilterCheck` handler（支持 latest、404、JSON 返回 SpamFilterResponse，带 swagger 路由注解）。
  - `server/server.go` 在 `spamfilter.Enabled` 时注册 `GET /api/v1/message/{id}/spam-check`。
  - `swaggerResponses.go` WebUIConfiguration 增加 `SpamFilter bool`；`application.go` 设置 `conf.Body.SpamFilter = spamfilter.Enabled`；`swaggerParams.go` 增加 SpamFilterCheckParams。
  - 手工同步 `server/ui/api/v1/swagger.json`：新增路径、SpamFilterResponse/SpamFilterRule 模型、WebUIConfiguration.SpamFilter 字段（保持 Go 编码风格 HTML 转义，diff 仅 +99/-1）。
- **Acceptance Criteria Addressed**: AC-1, AC-6, AC-8
- **Test Requirements**:
  - `rule` TR-6.1: latest 返回 200 且含 IsSpam/Score/Threshold/Rules；不存在 ID 返回 404；证据：E2E curl 输出。
  - `rule` TR-6.2: 禁用时 404 且 webui `SpamFilter:false`；启用时 `SpamFilter:true`；证据：E2E webui 输出与 404 状态码。
- **Completion Evidence**:
  - E2E：`/api/v1/webui` 返回 `"SpamFilter": true/false`；spam-check 正常/禁用行为正确；swagger.json JSON 合法。

## Task 7: 前端 SpamFilter 面板与集成
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 6
- **Description**:
  - 新建 `server/ui-src/components/message/SpamFilter.vue`：调 `/spam-check`；得分环按返回 Threshold 渲染；规则表含 custom 徽章；Help 弹窗三项说明（本地启发式、积分制、YAML 自定义）。
  - `MessageItem.vue`：注册组件；桌面按钮、移动端 Checks 下拉、tab-pane 三处按 `mailbox.showSpamFilter && mailbox.uiConfig.SpamFilter` 渲染；独立 spamFilterScore/Color 接线。
  - `stores/mailbox.js`：新增 `showSpamFilter`（localStorage `mp-hide-spam-filter`）+ watch 持久化。
  - `AppSettings.vue`：新增 "Show spam filter message tab" 开关。
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `rule` TR-7.1: prettier/eslint 通过；证据：`npx prettier -c` All matched files use Prettier code style；eslint 退出码 0；`npm run build` 成功且 dist/app.js 含 spam-check。
  - `rule` TR-7.2: 浏览器验证通过；证据：浏览器自动化报告——垃圾邮件红色 "21.7 / 5" Spam 徽章 + 11 条规则；正常邮件绿色 "0 / 5" Not spam + "No rules triggered."；Help 弹窗三折叠项可展开；Settings 开关存在且开启。
- **Completion Evidence**:
  - 浏览器端到端全部步骤通过；前端 lint/build 通过。

## Task 8: 端到端验证与全量测试
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 5, Task 6, Task 7
- **Description**:
  - `go build ./...`、`go vet ./...`、`go test ./...` 全部通过（spamfilter 新测试 + storage 集成测试 + 全部既有包无回归）。
  - E2E 三场景：默认配置（ham/spam 判定 + 标签 + API + UI）；`--spam-filter-config`（自定义规则/阈值/标签/黑白名单/禁用内置）；`--disable-spam-filter`（无标签、路由 404、webui false、日志 disabled）；坏配置 fail-fast。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3, AC-4, AC-8, AC-9
- **Test Requirements**:
  - `rule` TR-8.1: Go 命令退出码 0；证据：BUILD+VET OK；`go test ./...` 所有包 ok（spamfilter、storage、server、apiv1 等全部通过）。
  - `rule` TR-8.2: 端到端行为与 AC 一致；证据：curl 输出 + 浏览器自动化报告。
  - `rubric` TR-8.3: 工程一致性；scale 1-5；anchors 1=风格割裂/测试缺失，3=可用但有明显缺口，5=与现有子系统模式高度一致且测试齐备；threshold >= 4；证据：包结构/日志前缀/swagger 注解/CLI-env 成对/标签复用均对齐 spamassassin、htmlcheck、tags-config 既有模式；无新第三方依赖（enmime、go-yaml 均为既有依赖）。
- **Completion Evidence**:
  - 自评 rubric 5/5：新增包与既有 spamassassin 包 API 风格一致（Result/Rule/Check）；配置加载与 tags/relay 一致（YAML+fail-fast+启动日志）；规则集 20 条均有测试；无新依赖；全量测试绿。
