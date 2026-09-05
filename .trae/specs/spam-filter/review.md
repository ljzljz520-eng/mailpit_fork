# 开箱即用垃圾邮件检测 - 独立审查

- [x] CP-R1: 过滤器默认开箱即用
  - **Type**: `rule`
  - **Covers**: AC-1
  - **Evidence**: R1 通过。审查者独立启动默认二进制：日志 `[spam-filter] enabled: 20 built-in rules, 0 custom rules, threshold 5.0`；`/api/v1/webui` 返回 `SpamFilter:true`；`spam-check` 路由 200。

- [x] CP-R2: 明显垃圾邮件判定并打标签，正常邮件不受影响
  - **Type**: `rule`
  - **Covers**: AC-2
  - **Evidence**: R1 通过（附校准建议，已修复）。审查者独立构造钓鱼堆叠邮件（Score 20.2，11 条规则，打 spam 标签）、.exe 附件（8.0，打标签）、链接伪装、Stripe/GitHub ham 邮件（0~1 分，无标签）。初版单信号链接伪装仅 2.5 分不达阈值，已将 LINK_DOMAIN_MISMATCH、HTML_PASSWORD_INPUT 调整为 5.0，新增 TestSingleSignals 锁定；修复后冒烟验证：仅含伪装链接的合法邮件 IsSpam=true（Score 5.0，LINK_DOMAIN_MISMATCH）。

- [x] CP-R3: 用户自定义规则生效（Builtin=false）
  - **Type**: `rule`
  - **Covers**: AC-3
  - **Evidence**: R1 通过。YAML 自定义规则命中，Rules 中 `6 internal-alpha Builtin=False`；Go 测试 TestLoadConfigCustomRule 覆盖。

- [x] CP-R4: 白名单/黑名单/禁用内置规则/阈值/标签可配置
  - **Type**: `rule`
  - **Covers**: AC-4
  - **Evidence**: R1 通过。allowlist 垃圾内容 Score=0 无标签；blocklist 干净邮件 BLOCKLIST 命中带 junk 标签；disable HTML_FORM 后该规则不出现；threshold 3.0/tag junk 生效；MP_SPAM_FILTER_CONFIG 环境变量同样生效；未知 disable ID 与内置重名规则有 warning。

- [x] CP-R5: 非法配置 fail-fast
  - **Type**: `rule`
  - **Covers**: AC-5
  - **Evidence**: R1 通过。坏正则与缺失文件均 exit 1，输出 `[spam-filter]` 前缀错误且端口未监听；TestLoadConfigErrors 6 子用例覆盖。

- [x] CP-R6: API 端点行为（200/404/禁用 404）
  - **Type**: `rule`
  - **Covers**: AC-6
  - **Evidence**: R1 通过。latest 返回 200 且字段 IsSpam/Rules/Score/Threshold 齐全；坏 ID 返回 404；禁用态路由 404。

- [x] CP-R7: Web UI 面板与设置开关
  - **Type**: `rule`
  - **Covers**: AC-7
  - **Evidence**: R1 通过（实时 DOM 验证由实施方浏览器自动化完成，审查者静态复核+产物核验）。浏览器自动化报告：垃圾邮件红色得分环（21.7/5）+ Spam 徽章 + 11 条规则表；正常邮件绿色 0/5 Not spam + "No rules triggered."；Help 弹窗三折叠项；Settings "Show spam filter message tab" 开关存在。审查者验证三处接线点守卫条件一致、事件名匹配、localStorage 键持久化、prettier/eslint 退出码 0、dist/app.js 含 spam-check 等全部产物字符串。

- [x] CP-R8: --disable-spam-filter / MP_DISABLE_SPAM_FILTER 完全关闭
  - **Type**: `rule`
  - **Covers**: AC-8
  - **Evidence**: R1 通过。标志与环境变量两种方式均验证：日志 `[spam-filter] disabled`、webui `SpamFilter:false`、路由 404、垃圾邮件标签为 `[]`。

- [x] CP-U1: 工程质量与仓库一致性
  - **Type**: `rubric`
  - **Covers**: AC-9
  - **Scale**: 1-5
  - **Anchors**: 1 = 风格割裂、破坏构建/测试或引入新依赖；3 = 功能可用但风格/测试有明显缺口；5 = 与既有 spamassassin/htmlcheck/tags 配置模式高度一致，测试齐备，无新依赖
  - **Pass Threshold**: >= 4
  - **Evidence**: R1 评分 4/5 → 修复后达 5/5。包结构/日志前缀/swagger 注解/CLI-env 成对注册/标签复用均对齐既有模式；go.mod/go.sum 零改动（无新依赖）；规则状态 RWMutex 保护；13 个 Go 测试函数含错误路径/大邮件/黑白名单；`go build`、`go vet`、全量 `go test ./...` 全绿；spamfilter 包 `go test -race` 干净（storage 包 race 报告为既有问题 notifications.go，与本次改动无关）。初版扣分点（链接提取未应用 512KB 截断）已修复。

## Review History

### Review R1
- **Result**: `pass`
- **Reviewer**: 独立代理（只读，全新上下文），独立构造邮件与配置冒烟，未复用实施方测试夹具。
- **Evidence**:
  - 所有 9 个 CP 通过；全量 `go test ./...` 13 包全绿、零回归；无 actionable 发现。
  - Advisory 发现 6 项，其中与本功能质量直接相关的 4 项已在同一工作流中修复：
    1. LINK_DOMAIN_MISMATCH 2.5→5.0、HTML_PASSWORD_INPUT 3.0→5.0（单信号钓鱼达阈值，严格满足 AC-2(c)）；新增 TestSingleSignals。
    2. 链接提取改用截断后的正文（extractLinks(m.html, m.text)），与 NFR-1 一致。
    3. X-Spam-Flag 判定由 `strings.Contains("yes")` 改为 `EqualFold == "yes"` 精确匹配。
    4. 移除易误报的 "work from home" 垃圾短语（常见合法 HR 用语）。
  - 未处理 advisory（不影响验收）：aria-controls/重复 id 系照抄既有 SpamAssassin 按钮标记（Bootstrap 靠 data-bs-target 工作）；storage 既有 data race 为本次改动前已存在问题。
  - 修复后复验：`go build ./...`、`go vet ./...`、全量 `go test ./...` 全绿；冒烟邮件（仅伪装链接单一信号）IsSpam=true、Score 5.0。
- **Blocked By**: 无
