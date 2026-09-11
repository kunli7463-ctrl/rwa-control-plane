# RWA Control Plane Sandbox

这是香港代币化基金首发产品的可运行领域内核，不是生产金融系统。

当前实现：

- 产品设立和角色授权；
- 租户化产品配置中心：基金、私募信贷、债券、Sukuk、商品/仓单五类模板，机构准入、必需角色完整性和草稿状态隔离；
- 机构尽调与产品激活双人控制：经办/复核分离、强制证据清单、版本化 canonical payload、Ed25519 机构公钥验签、密钥轮换/撤销失败关闭、有效期检查、只追加证据元数据、配置快照和带语义哈希的审计导出；
- 存量产品升级失败关闭：缺少新强制证据的历史 ACTIVE 产品自动进入 `PAUSED / SUSPENDED`，不允许被旧状态绕过；
- Ed25519 Sandbox 机构签名；
- 产品级投资者凭证、有效期和受限退出；
- NAV/托管/名册 Evidence Envelope；
- Sandbox 现金日志、资产账和法定名册（现金日志不冒充银行回单）；
- 认购、二级转让、赎回；
- NAV 时效、价格偏离、额度和资格检查；
- REQUESTED → POLICY_CHECKED → CASH_RESERVED → REGISTER_PENDING → SETTLED 状态机；
- 幂等请求、成功/拒绝只追加审计事件和异常原因码；
- 名册确认超时、现金预留释放、人工复核和关联替代交易；
- 异常处置经办/复核双人分离，重试时重新执行全部业务规则；
- 卖方与买方凭证绑定、自转账拦截、未来 NAV 隔离和凭证动态状态；
- NAV/规则策略快照哈希及不含身份和金额的交易证据包；
- 资产账/法定名册核对，以及明确标注为非银行回单的 Sandbox 现金日志确认；
- 公开回执隐藏投资者、金额和价格。
- 八个服务器身份、七类角色视图的 Web 演示界面；内置 12 步自动演示向导、角色自动切换、操作高亮与预期结果说明；
- PostgreSQL 合成数据一键准备：只允许固定 Sandbox 租户和演示产品，在单个 Serializable 事务中恢复凭证、产品、签名 NAV 和干净账本，生产身份模式失败关闭；
- PostgreSQL 生产持久化边界（迁移、事务仓储、双重记账、独立法定名册、审计链和 Transactional Outbox）；
- 数据库原生认购、转让、赎回 workflow，资产账与法定名册逐户镜像，不一致时整笔回滚；
- Memory/PostgreSQL 统一异步 workflow adapter；本机 Web 默认使用 PostgreSQL adapter，并在页面明确显示数据模式；
- 可注入的 AES-256-GCM 信封加密适配器、版本化本地测试密钥环和上下文绑定 AAD；
- PostgreSQL 交易授权读模型，可按服务端确认的角色和交易当事人范围解密，监管视图保持脱敏；
- PostgreSQL 产品聚合读模型，在同一只读快照中生成持仓、交易、证据、异常、审计和三账控制视图；
- 服务端 Sandbox 会话、CSRF 校验和逐动作授权；租户、机构、角色与投资者主体不再来自页面查询参数；
- 持久化本地开发密钥、数据库首次引导/恢复分离，以及 PostgreSQL Web 重启恢复；
- PostgreSQL 原子产品暂停/恢复、凭证限制、名册失败异常、分轮 maker-checker 审批、替代交易重试和受限退出；
- 租户隔离的可靠 Outbox 调度器、可回收工作租约、指数退避、死信、Inbox 幂等和模拟名册回调消费者；
- 独立 Outbox Worker、健康/指标端点、优雅停机，以及经办/复核分离的死信审批重放；
- Ed25519 机构签名回调协议，以及名册/现金/托管通道的严格顺序缓冲、幂等、时效和永久失败记录；
- 三类严格 callback payload schema、十进制字符串金额规范、只追加 Evidence 映射和交易外部对账视图；
- 域分离、支持密钥轮换的经济承诺，以及外部回调金额/份额核对；
- 外部对账异常自动建单、分轮 maker/checker 审批、补救引用、审计与 Outbox 原子留痕；
- 生产 OIDC 边界、MFA/ACR 校验、哈希持久化会话、动态机构成员与 permission 授权；
- KMS 式每密文数据密钥信封、上下文绑定、密钥轮换与禁用失败关闭；
- 版本化 Groth16 JoinSplit Proof Adapter 与 PostgreSQL ZK 验收门，包括不可变产品上下文、绑定 request hash 的执行指令、BN254 域检查、Merkle root、nullifier、防重复输出、上下文退役、审计和 Outbox；
- `snarkjs.groth16.verify` 生产加载边界、manifest/vkey 文件双重 SHA-256 pin、bundle 路径限制，以及 `ZK_MODE=groth16` 启动失败关闭；
- 真实本地 Groth16 正反 proof 向量、隔离 verifier 子进程、15 秒超时与输入/输出上限；有效 proof 已穿过 PostgreSQL 授权、nullifier、输出承诺、审计及 Outbox 原子验收门；
- 服务端隐私转让准备、公开输入冻结和 proof 结算 API；`PROOF_PENDING` 与 `CONFIDENTIAL_NOTE` 独立状态/轨道不与法定名册转让混用；
- Groth16 回执、nullifier、输出承诺与 `ROOT_PENDING` 单事务提交；权威根和执行效果经独立权限确认后，再将最终回执、交易 `SETTLED`、审计及 Outbox 单事务提交；
- 数据库延迟约束要求每笔已结算隐私交易都有终局记录，并始终显式标注 `legalRegisterApplied:false`；
- Web 存活/就绪探针与 2 MiB API 请求上限。
- 隔离 Prover HTTPS 客户端、加密 witness 引用、持久化租约/重试队列、租户隔离、前端进度和 Worker 健康/Prometheus 指标；
- 机构签名回调 HTTP 入口与可交付的 Ed25519 Connector SDK。
- 生产 profile 硬门控：显式非 Sandbox tenant、PostgreSQL/OIDC、KMS 信封、KMS-HMAC、
  迁移只校验、Demo seed/reset 禁止，以及必须注入的外部 Outbox publisher；

尚未实现：

- 经独立审计并完成正式 ceremony 的生产电路/验证密钥/manifest 产物，以及真实 Prover 服务；
- 真实 KYC、托管、银行、名册或 NAV 接口；
- 门限监管解密；
- 真实 KMS/HSM、客户机构 OIDC/SSO 与成员目录联调，以及生产部署；
- 生产级 maker/checker 身份认证、电子签名和权限系统；
- 香港或迪拜法律规则确认。
- 真实外部系统联调、正式 payload schema、回调到交易状态的映射及受监督部署；
- 生产 KMS/HSM 密钥提供方、真实身份提供方及客户 RBAC/ABAC 策略联调；
- 客户目标容量下的独立压力测试、跨可用区故障演练和正式灾备验收；
- 真实消息基础设施上的 Outbox 发布和客户机构消费者联调；

运行：

```sh
npm test
npm run demo
npm start
npm run worker:outbox
npm run auth:verify
```

PostgreSQL 持久化的边界、运行方法和上线前检查见 [PRODUCTION_PERSISTENCE.md](./PRODUCTION_PERSISTENCE.md)。

Web Demo 启动后访问 `http://127.0.0.1:8765/`。

首次演示直接点击页面顶部 **开始演示向导**，再点 **一键准备并从头开始**。完整中文讲稿和故障恢复方法见 [DEMO_GUIDE.md](./DEMO_GUIDE.md)。

所有金额使用整数最小单位。所有机构、数据、资产和资金均为模拟内容。

本地完整验收使用 `./scripts/final-acceptance.sh`。数据库迁移到 `021_product_evidence_signature_verification.sql`。其中包含真实 `snarkjs@0.7.6` Groth16 正反向量和 PostgreSQL 端到端验收；测试 vkey 来自单机本地 ceremony，只证明软件接线和密码学调用可工作，绝不能解释为生产可信设置、电路审计或正式部署已经完成。迁移 021 的 Ed25519 证据验签、生产 profile/KMS/Outbox 负向测试均已通过；2026-09-03 第二阶段完成后已在普通 macOS Warp 环境重新执行 PostgreSQL 全量验收，136 项通过、0 失败、0 跳过，并输出 `FINAL_ACCEPTANCE_OK`。

本地脚本不再绑定开发者用户名。macOS 默认从
`$HOME/Library/Application Support/RWADev` 发现隔离 Node 22 与 PostgreSQL 16.15，
也可通过 `RWA_RUNTIME_ROOT`、`RWA_NODE_BIN`、`RWA_PG_PREFIX`、`RWA_PG_DATA`、
`RWA_PG_HOST`、`RWA_PG_PORT`、`RWA_PG_ADMIN_USER`、`RWA_PG_APP_USER` 和
`RWA_PG_DATABASE` 覆盖。验收解析到非 Node.js 22 时失败关闭。

容器化 PoC 的可重复部署入口为 `deploy/compose/postgres-poc.yaml`，镜像以非 root 用户运行、只安装生产依赖，并为 Web 与 Outbox worker 配置独立健康检查。完整边界、启动方式和生产前置条件见 `PRODUCTION_DEPLOYMENT.md`。该 Compose 配置只允许合成数据和本机回环访问，不能用于真实资产生产环境。

生产编排模板为 `deploy/compose/production.example.yaml`。它将配置预检、
Groth16 artifact 校验、迁移、Web、Outbox 和隔离 prover 分开，并用成功依赖
阻断后续启动。该模板仍需要部署方提供真实 KMS、OIDC、PostgreSQL、消息
发布器和独立批准的密码学产物，不能单独视为可上线环境。

如果本地 PostgreSQL 曾被中断，直接在 Warp 执行 `./scripts/final-acceptance.sh`；它会安全重启实例、应用迁移并运行全部测试，不删除数据库。

隐私结算接口见 [CONFIDENTIAL_SETTLEMENT_API.md](./CONFIDENTIAL_SETTLEMENT_API.md)，产品激活证据签名规范见 [PRODUCT_EVIDENCE_SIGNATURES.md](./PRODUCT_EVIDENCE_SIGNATURES.md)，完整产品边界与外部依赖见 [PRODUCT_COMPLETION.md](./PRODUCT_COMPLETION.md)。

第三阶段留存结果：PostgreSQL 全量 142/142，压力矩阵 16/16（1,000 事件、12 worker）。
第四阶段新增监控指标接线与面板/规则配置后，本次 PostgreSQL 全量复测为 **146/146、零失败、零跳过**。
宿主进程重启仍需 Warp 执行原始最终验收脚本。监控包见 [MONITORING_RUNBOOK.md](./MONITORING_RUNBOOK.md)：
最新第四阶段：Node 专项 10/10、原生 promtool 22 条规则与 26 个场景通过；原生 Grafana
启动/API/provisioning/数据源及本机告警触发恢复链路通过。最新 PostgreSQL 全量为 **148/148**。
真实通知接收器、容器及全系统生产监控未据此宣告完成，见 [本机验收报告](./MONITORING_ACCEPTANCE_2026-09-03.md)。

批准产物到位后，先设置 `ZK_ARTIFACT_DIR` 和部署侧独立保存的 `ZK_ARTIFACT_MANIFEST_SHA256`，执行 `npm run zk:verify-artifacts`。只有该命令成功、有效/无效 proof 向量通过且 artifact 已独立审计，才可设置 `ZK_MODE=groth16`。生产依赖验收还必须执行 `npm audit --omit=dev`；当前 lockfile 结果为 0 个已知生产漏洞。
