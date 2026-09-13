# Product completion boundary

## 已由产品内部完成

- 产品、角色、凭证、证据、认购、名册转让、赎回和异常补偿状态机；
- PostgreSQL Serializable 原子事务、资产账、法定名册账、审计链、Outbox/Inbox 和幂等；
- 身份会话、CSRF、动作级权限、生产 OIDC/MFA 接口边界和角色化脱敏读模型；
- 私密载荷 AES-GCM/KMS 信封接口、密钥轮换模型和经济字段承诺；
- 机构签名回调、顺序流、对账异常、maker/checker 和死信重放；
- 固定 Groth16 产物、13 项公开输入、产品上下文、执行指令、Merkle root、nullifier
  与输出承诺的验证边界；
- 服务端准备 → 公开输入授权 → proof 验证 → 权威根/执行效果确认 → 隐私账本终局的完整 API；
- proof 回执、nullifier、输出承诺、交易状态、审计和 Outbox 的单事务提交；
- 明确区分 `REGISTERED` 与 `CONFIDENTIAL_NOTE` 两种结算轨道；
- Web/Worker 健康探针、失败关闭配置、迁移哈希和本地备份恢复脚本；
- 隔离 Prover 客户端、加密 witness 引用、持久化任务租约/重试/恢复、租户隔离与前端进度；
- Prover Worker 健康、Prometheus 指标、积压/失败/过期租约告警和优雅停机；
- 机构签名回调 HTTP 入口、Ed25519 Connector SDK 与独立 conformance 验证工具；
- 固定合成数据的一键准备与 12 步自动演示向导，覆盖角色切换、正常交易、异常补偿、资格限制、受限退出和审计收口；
- 租户化产品配置目录、五类 RWA 模板、机构准入状态、必需角色检查和草稿产品配置中心；
- 机构准入双人审批、产品强制证据清单、来源角色绑定、版本化 canonical payload、Ed25519 机构公钥验签、签名密钥轮换/撤销、有效期门控和产品激活双人审批；
- 配置版本快照、租户级审计导出及存量无证据产品的暂停迁移；
- 单元、密码学正反向量和 PostgreSQL 集成测试。
- 显式 `DEPLOYMENT_PROFILE=production` 失败关闭边界：禁止 Sandbox tenant、Memory、
  本地/原始主密钥和 Demo seed/reset；生产只校验已批准迁移；
- 可插拔生产 KMS 接口同时覆盖每密文数据密钥 wrap/unwrap 与经济字段 KMS-HMAC，
  不再要求应用进程持有生产 HMAC 主密钥；
- 生产 Outbox 必须注入外部 publisher，明确采用 at-least-once 与 event-id 对端幂等，
  不再允许生产误用模拟回调消费者。

## 可由我们继续独立替换或强化

- 容器、Kubernetes、可观测性面板和压力/故障注入；
- 根据目标客户最终字段扩展现有 connector SDK 和 conformance test kit；
- 正式电路的可复现构建、第二轮独立审计和 ceremony 操作手册。

这些工作不需要客户提供真实数据，可以用合成数据和模拟机构接口完成。

Web 隐私转让向导与 proof/ROOT_PENDING/终局进度展示已完成，包含经纪、运营经办和独立复核
三个服务器身份边界；隔离 Prover、异步任务状态、机构 Connector SDK 和运行指标也已接入。

第三阶段修复队列并发抢占导致的 40001 重试耗尽后，全量 PostgreSQL 测试为
142 项通过、0 失败、0 跳过；1,000 事件、12 worker 的压力/故障矩阵为 16/16。
这不是生产容量或跨可用区灾备认证。宿主机 stop/start 验收仍须在 Warp 完成。
第四阶段监控包的代码与真实容器/告警通知验收分别记录，不能混为已上线。
演示一键准备只作用于固定 `sandbox-hk`
租户和 `hk-liquidity-sandbox` 产品；生产模式不提供重置能力。

配置中心创建的产品固定处于 `DRAFT`，新机构固定处于 `DUE_DILIGENCE`。机构须经不同身份
的经办与复核批准；角色配齐后进入 `READY_FOR_EVIDENCE`。只有责任机构来源匹配、canonical
payload 完整绑定、机构 Ed25519 公钥验签成功、签名密钥仍有效且强制证据未过期，再经不同身份
完成产品激活复核，产品才可进入技术 `ACTIVE`。这仍不等于
牌照批准、资产真实、银行资金确认或法定登记。

## 必须由外部机构或持牌专业方完成

| 外部参与方 | 必须提供或确认 | 产品已准备的接入边界 |
|---|---|---|
| 基金发行人/管理人 | 产品条款、估值政策、暂停与赎回规则 | 产品规则、Evidence、审批与版本快照 |
| 分销/KYC 机构 | 真实投资者资格、生命周期和限制 | 签名凭证、撤销/受限退出、OIDC/RBAC |
| 过户代理/基金行政 | 法定持有人名册和最终过户确认 | 顺序回调、名册账、对账和异常补偿 |
| 银行/托管人 | 资金及资产事实、签名回单 | Evidence Envelope、Inbox、三账核对 |
| KMS/HSM 提供方 | 生产密钥、权限、轮换和恢复 | KMS provider 接口与密文信封 |
| 消息基础设施/接收方 | 持久发布、event-id 幂等和失败回执 | 外部 Outbox publisher 接口与 at-least-once 租约 |
| 电路审计/ceremony 参与方 | 正式审计报告和可信产物 | manifest/vkey 双哈希 pin 与失败关闭加载器 |
| 香港/迪拜法律合规 | 牌照边界、销售限制、隐私和数据责任 | 双轨终局、角色权限、审计证据和地域配置 |

## 不能被软件单方面完成的事项

2026-09-04 后续内部进展及未完成门槛，以 `INTERNAL_CLOSEOUT_2026-09-04.md` 为准。
当前全量回归 161/161；四地草案、供应链证据生成、本机 ZK 双重构建已新增。
非基金目录模板不等于非基金完整生命周期；内部工作和生产准入仍不能一概标为完成。

2026-09-03 监控增量：本地全量测试 155/155；Web、数据库与主机采集已接入，
34 条告警规则、26 个面板已通过原生配置与查询验证。
详情及限制见 `WEB_MONITORING_ACCEPTANCE_2026-09-03.md`。
这不代表生产部署或全部内部工程完成。

软件无法自行把一个隐私凭证变成法律上的基金权益，也不能自行证明银行资金或托管资产真实存在。
因此 proof 验证成功只会标记为 `CONFIDENTIAL_PROOF_REGISTRY / ROOT_PENDING`。只有权威树
发布方确认两个输出已进入新根、并提供 proof-bound recipient/relayer 效果引用后，才标记
`CONFIDENTIAL_NOTE_LEDGER / SETTLED`。即便如此仍返回 `legalRegisterApplied:false`，直到外部
过户代理通过受控 connector 确认法定登记。这个限制是产品可信度的一部分，不是功能缺失。
