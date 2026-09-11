# 产品最终独立复核报告

日期：2026-08-26  
范围：`product/demo` 控制面、PostgreSQL 状态与约束、身份/权限、机构回调、Outbox、
Groth16 JoinSplit 验证接线及隐私结算 API。  
结论边界：这是工程复核与自动化验收，不替代持牌法律意见、正式电路审计、可信设置审计、
渗透测试或生产基础设施认证。

## 1. 总体结论

当前代码已经达到“可交付给机构做合成数据集成和 PoC”的产品状态。内部控制面不存在已知的
未修复 Critical/High 代码缺陷；PostgreSQL 全量测试为 **100/100 通过、0 失败、0 跳过**，
生产依赖 `npm audit --omit=dev` 为 **0 个已知漏洞**。

它还不是可以直接处理真实 RWA 权益的生产系统。生产前仍必须接入权威 Merkle 根发布/执行
引擎、法定名册/银行/托管接口、生产 KMS/HSM、生产 OIDC、正式 ZK 产物及独立审计。代码会
把这些外部事实保持为显式待确认状态，不再把 proof 成功冒充资产终局。

## 2. 已验证的最终流程

```text
服务端准备
  → 冻结 13 项公开输入
  → Groth16 验证 + nullifier 原子占用
  → ROOT_PENDING（尚未终局）
  → operations maker 提交权威根/执行引用
  → 不同 principal 的 checker 批准
  → CONFIDENTIAL_NOTE_LEDGER / SETTLED
  → legalRegisterApplied=false（等待外部法定登记）
```

proof 接受事务会同时写入 proof receipt、两个 nullifier、两个输出承诺、授权消费、审计和
Outbox。最终批准事务会同时写入根发布 attestation、权威新根、最终回执、状态、审计和
Outbox。任一步失败均回滚整笔 Serializable 事务。

## 3. 本轮发现并已修复的问题

### 高风险

1. **proof 成功被过早标记为资产终局。** 原实现没有证明两个输出已进入权威 Merkle 树，
   也没有证明 fee/recipient/relayer 的外部效果已执行，却直接返回 `SETTLED`。现拆成
   `CONFIDENTIAL_PROOF_REGISTRY / ROOT_PENDING` 与权威根/效果确认后的
   `CONFIDENTIAL_NOTE_LEDGER / SETTLED` 两阶段。
2. **权威根终局曾是单人高权限操作。** 现增加不可变 finalization proposal 与数据库级
   maker/checker 分离；同一 principal 无法自提自批，checker 也不能替换 maker 提交的字段。
3. **生产 ZK API 权限没有写入生产角色表。** sandbox 角色可调用，但 OIDC production
   session 会全部拒绝。迁移 015/016 已补齐 prepare、authorize、settle、propose、approve
   权限，并由生产身份集成测试验证。
4. **运行账号兼任数据库迁移账号。** 现 OIDC production runtime 只读校验全部迁移哈希和
   最新版本；DDL 必须由独立 migrator 预先执行，运行账号不再需要改表/改 trigger 权限。

### 中风险

1. **跨租户边界不完整。** Runtime、ZK service、机构 callback 与外部 incident service
   现均固定一个 tenant；跨租户身份、callback 或 incident id 会失败关闭。
2. **输出承诺全局唯一造成跨 context 污染。** 唯一性已改为
   `(contextId, commitmentX, commitmentY)`，并强制 output context 与不可变 proof receipt
   一致。
3. **Merkle root 可被任意改写。** root 的 context/root/tree size/来源/观测时间已不可变，
   只允许 `CURRENT → HISTORICAL/REVOKED`、`HISTORICAL → REVOKED`，删除被禁止。
4. **执行指令无过期时间。** 指令现必须在未来且不超过 24 小时；authorize/accept 都会
   重新检查，过期 proof 无法进入验收。
5. **证据包形成身份旁路披露。** issuer/supervisor 的 actor、maker、checker、subject 等
   标识现递归脱敏；broker/operations 才保留受权操作标识，经济明文始终不进入证据包。
6. **OIDC 接受过弱 RSA key，生产数据库 TLS 未钉死。** RSA 低于 2048 位现被拒绝；OIDC
   生产模式强制 HTTPS origin、Secure Cookie 和 PostgreSQL `sslmode=verify-full`。
7. **内部错误可能通过 HTTP 返回。** 未分类异常现统一为 500 generic response；数据库
   错误、堆栈和 readiness 内部细节不会回给客户端。

### 防御性加固

- tenant/product/transaction/actor/reference 字段增加长度及规范化校验；
- product 暂停会在 authorize、proof preflight、proof commit、root proposal 和 finality
  approve 各阶段重新检查；
- verifier 并发上限、2 MiB 请求体上限、proof artifact/vkey/manifest/public-signal-order pin；
- 生产依赖审计为 0，测试用 `circomlibjs` 保持 dev-only；
- historical root 必须有有效期，nullifier 在 context 内唯一且 append-only。
- 新增非 root、只含生产依赖的容器镜像边界，以及 migration/Web/Outbox worker 的本机
  Compose PoC 编排、只读文件系统和独立健康检查。

## 4. 已确认成立的安全属性

- Groth16 verifier 接收并绑定全部 13 项公开输入；顺序、artifact、vkey 和 manifest 漂移均
  失败关闭。
- 两个输入 nullifier 必须不同，且数据库 `(contextId,nullifier)` 唯一约束防重放/双花。
- 产品的 contextId/assetType 与执行指令的 fee/recipient/relayer 由服务端冻结，proof 不能
  替换业务上下文。
- proof 验收与 nullifier/输出/审计/Outbox 同事务；最终根与状态/回执/审计/Outbox 同事务。
- PostgreSQL 资产账与名册账分别做 per-asset 零和检查；posted batch 与审计链 append-only。
- 幂等键、callback sequence、Outbox lease/retry/dead-letter、SSI retry 与连接恢复均有正反
  测试。
- AES-GCM/KMS envelope 绑定 tenant/transaction/product/type，密文篡改、跨交易替换和错误
  key 均失败关闭。
- 生产 session 仅保存 token/CSRF 哈希；每次认证重新检查 principal、membership、权限、
  MFA、issuer、audience、kid、算法和时效。

## 5. 仍需外部完成的生产阻断项

以下不是继续写本地业务代码可以真实完成的事项；未完成前不得接真实客户资产或对外宣称
生产可用。

1. **正式 ZK 供应链：** 固定最终电路版本、可复现构建、独立密码学审计、正式 ceremony/
   setup、生产 vkey、隔离 prover/verifier、artifact registry 与密钥轮换/停用流程。
2. **权威根与执行引擎：** 机构必须提供可验证的根发布批次和 fee/recipient/relayer 执行
   回执。目前产品接收受控双人 attestation，但不会凭空证明外部系统真的执行过。
3. **隐私存入/赎回自举：** 当前正式 ZK 轨道覆盖 2-in/2-out JoinSplit；初始 Note 铸造、
   confidential deposit/withdraw 与法定权益桥仍需目标机构规则和对应电路/connector。
4. **法定名册、现金与托管：** 过户代理、基金行政、银行和托管人的签名事实源及 SLA。
5. **生产 KMS/HSM：** 云 KMS/HSM provider、权限、双人恢复、轮换和灾备演练。仓库中的本地
   key 只允许 sandbox/开发。
6. **生产身份与网络：** 客户 OIDC tenant、MFA/ACR、证书、WAF/rate limit、私网数据库、
   secrets manager、日志/SIEM 与告警通道。
7. **法律与牌照：** 香港/迪拜实际产品结构、销售对象、数据责任、AML/KYC、托管和牌照意见。

## 6. 可以推迟但上线前应完成

- 独立渗透测试、SAST/DAST/SBOM 签名和构建 provenance；
- 峰值 proof 验证、PostgreSQL 锁竞争、Outbox backlog 的容量和故障注入测试；
- 多可用区、备份恢复时间、密钥灾备、root publisher 中断与长期 `ROOT_PENDING` 演练；
- 正式 connector SDK、机构 conformance test kit、监控面板和 runbook；
- Web 端 proof/root 双阶段进度、双人审批工作台和机构级审计导出。

## 7. 验收证据

- 数据库迁移最新版本：`018_product_configuration_catalog.sql`；
- 当前测试：111 项，111 通过，0 失败，0 跳过；
- 真实 `snarkjs@0.7.6` 本地 JoinSplit 正向 proof、公开输入重标记反例、proof 坐标篡改反例；
- PostgreSQL 实测 migration、Serializable、trigger、real Groth16、maker/checker、tenant、
  callback、Outbox 和 evidence redaction；
- 生产依赖：40 个，已知漏洞 0；
- 本轮 PostgreSQL 全量验收已完成且 100/100 通过；新备份已通过 SHA-256 校验并真实恢复到
  临时数据库，验证 17 个迁移、203 个产品记录、603 笔交易和 1220 条审计事件后自动清理。
  容器构建仍应在具备 Docker 权限的受控终端重复执行。

## 8. 最终判定

- **机构 PoC / 合成数据 / 渠道演示：通过。**
- **内部产品代码阶段：完成到外部连接边界。**
- **真实资产生产上线：不通过，等待第 5 节外部阻断项。**
- **“完全合规合法”声明：不能由代码或本报告作出，必须由目标法域持牌专业方确认。**

## 9. 2026-08-25 前端结算工作台增量验收

- 新增 JoinSplit 五阶段进度展示，以及经纪准备/授权/提交证明、运营经办终局提案、独立复核批准界面；
- 所有写操作继续复用现有 CSRF、服务器会话、动作级授权和数据库 maker/checker 约束，没有新增旁路接口；
- 当运行时未启用经固定产物验证的 Groth16 API 时，表单失败关闭，只显示不可执行状态；
- PostgreSQL 全量验收更新为 **85/85 通过、0 失败、0 跳过**；本地浏览器检查三个角色视图无控制台错误；
- 此增量不改变第 5 节生产阻断项，下一阶段为隔离 prover 服务、异步任务状态和故障恢复。

## 10. 2026-08-26 Prover、机构连接器与运维增量验收

- 隔离 Prover 仅接收 Vault/HSM/KMS 不透明引用；引用加密落库，任务具备租约、重试、恢复和
  租户隔离，远端 proof 仍必须穿过本地固定 Groth16 验收门；
- 修复 Prover Worker 曾可能领取其他租户任务，以及成功回执字段名称不一致导致任务误入
  `RETRYABLE` 的问题，并增加固定回归测试；
- Web 增加 Prover 请求与状态查询，不向浏览器要求原始 witness；Prover Worker 增加健康、
  Prometheus 指标、积压/失败告警与优雅停机；
- 新增 `POST /api/institution-callbacks` 机器接口、Ed25519 Connector SDK、严格幂等键和独立
  conformance 工具；服务端继续检查机构状态、产品角色、租户、顺序和经济上下文；
- 最终验收为 **100/100**，生产依赖已知漏洞为 **0**，本地备份恢复实测通过。
