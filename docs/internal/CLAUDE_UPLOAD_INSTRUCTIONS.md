# Claude Web/Claude Code 独立只读审核启动指令

请先解压本审核包并保持原目录结构，然后严格按照根目录
`CLAUDE_CODE_AUDIT_HANDOFF.md` 执行第一轮独立只读复核。

重要约束：

1. 以实际源码、数据库迁移和测试为准，不以已有报告结论为准。
2. 第一轮禁止修改、删除或格式化任何文件。
3. 禁止 `git commit`、`git push`、发布、部署以及连接任何真实资产、资金、客户或机构接口。
4. 不得把 Sandbox 证明、测试 ceremony 或 AI 复核描述为生产密码学证明或正式第三方审计。
5. 如无法运行 PostgreSQL 或 Node.js 验证，应明确标记 `NEEDS_RUNTIME_VERIFICATION`，不得以推测代替结果。
6. 对每个发现给出严重程度、文件、行号、触发条件、影响、最小复现和修复建议。
7. 最终输出格式必须遵循 `CLAUDE_CODE_AUDIT_HANDOFF.md` 第 7 节。

优先阅读：

- `CLAUDE_CODE_AUDIT_HANDOFF.md`
- `README.md`
- `PRODUCT_COMPLETION.md`
- `DELIVERY_STATUS_2026-08-29.md`
- `FINAL_AUDIT_REPORT.md`
- `CONFIDENTIAL_SETTLEMENT_API.md`
- `PRODUCTION_DEPLOYMENT.md`
- `PROOF_ADAPTER.md`

开始时请先回复：

> 已读取交接说明和仓库目录。第一轮将严格只读；我会先列出审查计划和可运行性检查结果，再进行逐项审查。

