# Claude Code 全仓复核交接说明

更新日期：2026-08-29

## 1. 工作目录

主产品目录：

```text
/Users/lixun/Documents/Codex/2026-08-19/mport-hashlib-import-hmac-import-os/product/demo
```

RWA 架构总目录：

```text
/Users/lixun/Documents/Codex/2026-08-19/mport-hashlib-import-hmac-import-os
```

开始前优先阅读：

1. `README.md`
2. `PRODUCT_COMPLETION.md`
3. `DELIVERY_STATUS_2026-08-29.md`
4. `FINAL_AUDIT_REPORT.md`
5. `CONFIDENTIAL_SETTLEMENT_API.md`
6. `PRODUCTION_DEPLOYMENT.md`
7. `PROOF_ADAPTER.md`

## 2. 当前基线

- 最新数据库迁移：`032_audit_chain_checkpoints.sql`
- 当前全量验收（2026-09-12）：190/190 通过，0 失败，0 跳过；不要把这个数字写死，以
  `./scripts/final-acceptance.sh` 的最新输出为准
- 2026-09-11 架构与安全审核的整改记录：`SECURITY_REMEDIATION_2026-09-11.md`
- 本地 PostgreSQL：`127.0.0.1:5432`
- 本地 Web 演示：`http://127.0.0.1:8766/`
- Node.js：固定使用 22.x
- 当前系统属于机构级 PoC，不是获准处理真实资产的生产金融系统

## 3. 双方分工

### Codex 主导实施

- 复现并修复确认成立的问题；
- 代码清理和测试补强；
- 压力测试与容量基线；
- PostgreSQL、Worker、Prover 和外部回调故障演练；
- 部署自动化及环境契约；
- 监控、指标、告警和运维面板；
- 最终全量验收、文档同步和脱敏交付打包。

### Claude Code 独立复核

- 第一轮严格只读，不能边审边修改；
- 独立检查业务、安全、密码学、数据库和部署论证；
- 对每项发现给出文件、行号、触发条件、影响、严重程度及复现方法；
- 区分真实漏洞、生产加固、外部依赖和文档问题；
- 对修复后的最终版本再做一次回归复核。

## 4. 第一轮复核范围

### A. 业务与账务

- 认购、转让、赎回和异常补偿的状态机是否允许跳步；
- 资产账、现金账和法定名册账是否始终守恒；
- 失败、超时、重试及并发操作是否可能产生部分提交；
- 幂等键、交易 ID、替代交易和回调重放是否可能造成重复执行。

### B. 产品与机构治理

- 机构尽调 maker/checker 是否可被同一主体、并发或权限组合绕过；
- 产品角色、租户和机构状态绑定是否完整；
- 强制证据来源、哈希、签名元数据、有效期和替换逻辑是否安全；
- 产品激活 maker/checker、退回重提及存量升级是否失败关闭；
- `DRAFT → ROLES_PENDING → READY_FOR_EVIDENCE → ACTIVATION_PENDING → ACTIVE`
  是否存在非法路径；
- 技术 ACTIVE 是否被错误描述为法律批准或资产真实性确认。

### C. 身份、权限与隐私

- Sandbox 身份是否可能进入生产模式；
- OIDC、MFA、会话、CSRF、租户成员和逐动作 permission 是否失败关闭；
- 发行人、投资者、运营、监管读模型是否发生越权披露；
- 审计导出是否包含私钥、原始身份、金额或签名敏感材料；
- AES-GCM/KMS 信封、AAD、密钥轮换与禁用路径是否正确。

### D. PostgreSQL 与异步任务

- Serializable 重试是否安全，是否可能重复外部副作用；
- 约束、触发器、只追加表和租户条件是否与服务端假设一致；
- Outbox/Inbox、租约、重试、死信、乱序回调及 Worker 停机恢复；
- 连接池、数据库重启、迁移漂移和备份恢复边界。

### E. Groth16 与隐私结算

- 13 项公开输入的顺序、授权值和 verifier 输入是否完全一致；
- artifact manifest、vkey、路径和运行模式 pin 是否可绕过；
- Merkle root、nullifier、输出承诺、request hash、recipient/relayer/fee/context
  是否完整绑定；
- `PROOF_PENDING → ROOT_PENDING → CONFIDENTIAL_NOTE_LEDGER` 是否原子且不可跳步；
- Sandbox Proof Adapter 是否可能被误认为生产证明；
- 测试 ceremony 产物是否被错误解释为生产可信设置。

### F. 部署与运维

- Docker/Compose 是否非 root、仅回环、健康检查和迁移门控；
- 生产环境变量是否会静默回退到本地密钥、Sandbox 身份或内存模式；
- Web、Outbox Worker、Prover Worker 的 readiness/liveness 与优雅停机；
- 日志、指标和错误信息是否泄露敏感字段。

## 5. 第一轮禁止事项

- 禁止 `git commit`、`git push`、发布和部署；
- 禁止连接真实资产、资金、客户或机构接口；
- 禁止修改或删除现有代码、数据库、测试向量和文档；
- 禁止重置本地 PostgreSQL 数据；
- 禁止下载或替换密码学产物；
- 禁止仅凭已有报告判定“已修复”或“已确认”；
- 禁止把 AI 复核描述成正式第三方安全审计或法律意见。

## 6. 建议只读命令

```sh
cd /Users/lixun/Documents/Codex/2026-08-19/mport-hashlib-import-hmac-import-os/product/demo
rg --files
rg -n "TODO|FIXME|unsafe|sandbox|ACTIVE|maker|checker|nullifier|groth16|tenant" .
```

需要运行验证时可使用：

```sh
./scripts/verify-local-postgres.sh
```

该命令会应用未执行迁移并运行全量测试，但不会删除数据库。重启级验收只允许在用户启动
PostgreSQL 的 Warp/Terminal 中运行：

```sh
./scripts/final-acceptance.sh
```

## 7. Claude Code 输出格式

### A. 已独立确认成立的边界

逐项列出证据，不重复报告原文。

### B. 真实可利用漏洞

每项必须包含：严重程度、文件和行号、前置条件、攻击/失败路径、影响、最小复现和修复建议。

### C. 生产加固缺口

明确说明为什么不是当前可利用漏洞，以及在何种部署条件下会升级为风险。

### D. 测试或论证问题

重点寻找“测试通过、结论可能正确，但解释机理错误”的情况。

### E. 外部依赖

单独列出必须由银行、托管、名册、KYC、KMS/HSM、身份提供方、密码学审计方或法律顾问完成的事项。

### F. 结论

给出：阻断下一阶段 / 可进入压力与故障测试 / 可进入受控机构 PoC 三选一，并说明理由。

## 8. Claude 复核后的处理流程

1. Claude 只读报告保存到本目录，不直接改代码；
2. Codex 逐条复现，标记 `CONFIRMED / NOT_REPRODUCED / DUPLICATE / EXTERNAL`；
3. 只修复 `CONFIRMED` 项，并为每项增加回归测试；
4. 运行 PostgreSQL 全量验收；
5. Codex完成压力测试、故障演练、部署自动化、监控面板和代码清理；
6. Claude 对最终版本做第二轮只读回归；
7. Codex 最终验收、更新交付说明并生成新的脱敏压缩包。

## 9. 最终完成标准

- 所有确认漏洞均有复现、修复和回归测试；
- 全量自动测试 0 失败、0 跳过；
- 压力测试给出硬件、并发、吞吐、P95/P99、错误率和数据库指标；
- 故障演练覆盖数据库、连接池、Worker、Prover、外部回调、租约和密钥不可用；
- 部署能从干净环境自动迁移、启动、检查健康并安全停止；
- 监控能识别积压、失败、过期租约、数据库不可用和证明服务异常；
- 文档明确区分技术完成、机构接入、生产安全与法律合规。

