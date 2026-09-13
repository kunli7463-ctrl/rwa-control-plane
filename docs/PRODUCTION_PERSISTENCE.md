# Production Persistence Boundary

本目录新增的是生产持久化边界，不等于系统已经上线，也不替代托管行、过户代理、银行、KYC 或法律确认。

## 已实现的控制

- PostgreSQL 事务意图表：租户级幂等键、请求哈希、状态版本和加密私有载荷；
- 显式状态历史：状态变更与原因、操作人分开记录，历史表禁止更新和删除；
- 双重记账：按资产分别守恒，数据库在批次入账时再次核对分录数量及余额；
- 独立法定名册日记账：逐户份额变化必须与资产账完全一致，否则数据库拒绝提交；
- 账本不可逆：`POSTED` 批次禁止回退，已写分录禁止修改或删除；
- 资产边界：分录资产必须与目标账户的资产一致；
- 双人审批：经办只能提出 `RETRY/CANCEL`，复核只能给出 `APPROVE/REJECT`，数据库和仓储层都禁止同一人兼任；
- 审计链：聚合对象内串联前序哈希，事务级 advisory lock 和唯一索引共同防止并发分叉；
- Transactional Outbox：业务事务内写事件，工作进程使用 `SKIP LOCKED` 并发领取；
- 可靠投递：领取按租户隔离并设置到期租约；崩溃后可重新领取，失败采用封顶指数退避，达到阈值进入死信，过期或失去所有权的工作进程不能确认；
- 消费幂等：数据库 Inbox 以 `(consumer_name,event_id)` 唯一，处理结果与模拟名册回调在同一事务提交，并复核事件载荷哈希；
- 运行控制：独立 Worker 暴露本机健康和 JSON 指标端点，收到终止信号后停止领取并等待当前批次完成；死信只能由不同 maker/checker 提出和批准重放，数据库保存错误快照、决定与重放次数；
- 机构回调：统一信封包含域分离 schema、租户、机构、产品、通道、流序列、时效、载荷及哈希，并按产品角色使用登记的 Ed25519 公钥验证；每个机构/产品/通道独立顺序推进，乱序消息缓冲，原始收据和应用效果分别留存；
- 回调对账：三类 payload 使用独立严格字段集合，经济数值必须是十进制字符串；签名回调生成独立 Evidence 记录并映射交易外部状态。当前状态名称刻意使用 `CONTEXT_MATCHED`，只表示租户、产品、币种或资产代码一致，不冒充金额/份额已核对；
- 迁移校验：已应用 SQL 以 SHA-256 固定，文件被事后修改会拒绝继续迁移。
- ZK 验收边界：版本化电路及验证密钥/manifest 哈希必须处于 ACTIVE；产品的 `contextId/assetType` 和交易的 `fee/recipient/relayer` 分别来自不可变产品上下文及绑定 request hash 的执行指令，其余 proof 状态与这五项合并冻结为 13 项授权输入；数据库触发器禁止上下文、指令或授权记录被篡改/删除。proof 验收重新锁定业务上下文，有效 root、nullifier 唯一性、输出承诺、证明回执与 `ROOT_PENDING` 在同一 Serializable 事务内落库；随后必须由独立权限确认权威输出根和 proof-bound 执行引用，才能原子进入 `SETTLED` 并生成最终回执、审计和 Outbox。

## 信任边界

`private_payload_ciphertext` 由 workflow 通过可注入的加密适配器在写库前生成；仓储层只接收密文 `Buffer`，不保管数据密钥。当前已实现 AES-256-GCM、本地版本化测试密钥环，以及绑定租户、交易、产品和交易类型的 AAD；这只是本地开发实现。生产必须替换为 HSM/KMS 支持的密钥提供方、每租户或每数据域的 DEK、可审计密钥轮换和双人恢复流程。

浏览器 Sandbox 已通过显式 `STORAGE_MODE=postgres` 接入此仓储层，页面同步显示 `POSTGRESQL`。认购、转让、赎回、产品暂停/恢复、凭证限制和名册异常处置均使用数据库原子 workflow。异常审批按轮次保存只追加的 maker/checker 决策，重试在同一 Serializable 事务的保存点内重新验证最新业务规则；失败时替代交易回滚，原异常重新开放。仅“重置全部模拟状态”仍由能力清单禁用，不能退回内存执行。

数据库原生的 Subscribe/Transfer/Redeem workflow 已实现并通过真实 PostgreSQL 端到端测试。配置 AES-GCM 适配器时，完整私有请求以密文持久化；未配置密钥时默认使用显式、不可恢复的 `RedactedPayloadCipher`，绝不退回明文。交易级授权读模型已经验证经纪角色、交易当事人、无关投资者和脱敏监管视图的边界；产品聚合读模型也已在同一只读可重复读快照中覆盖持仓、交易、凭证、证据、异常、审计和对账。

Web Sandbox 已改为服务器会话绑定租户、机构、角色和投资者主体，读 API 不再接受客户端自报身份，写 API 同时校验 CSRF 与逐动作权限。生产路径已实现 OIDC/JWKS 验签、MFA/ACR、哈希持久化会话、动态机构成员和 permission 授权，并在配置不完整时失败关闭；自动化测试使用本地测试身份数据，正式上线仍需与客户机构的真实 IdP、共享会话、成员生命周期和 RBAC/ABAC 策略联调。

ZK 验收门已接入独立 Web API workflow：服务端先创建 `CONFIDENTIAL_NOTE` 交易并进入 `PROOF_PENDING`，再冻结 13 项公开输入。验证成功后原子写入 proof 回执、nullifier、输出承诺、授权和 `ROOT_PENDING`，返回 `proofAccepted:true` 但 `settlementApplied:false`。第一名受权 operations 经办人随后提交权威输出根、树规模、根发布引用和 proof-bound 执行引用；第二名不同 principal 的 operations 复核人只能批准数据库内的不可变 proposal，不能替换字段。双人完成后系统才原子进入 `CONFIDENTIAL_NOTE_LEDGER / SETTLED`，生成最终业务回执、审计和 Outbox。全过程保持 `legalRegisterApplied:false`；它不会冒充现金或法定名册已经变化。测试 proof/vkey 来自单机测试 ceremony，只证明运行接线，不赋予生产信任。

`ZK_MODE=groth16` 的启动路径会加载 `snarkjs.groth16.verify`，并验证部署侧 pin 的 manifest 文件 SHA-256、manifest 内的 verification key 文件 SHA-256、严格字段集合、13 项信号顺序和 bundle 路径边界；任何缺失或漂移都会拒绝启动。proof 结构与大小、manifest/vkey 大小和 verifier 输出均有限制。由于 snarkjs 公开验证 API 不终止 BN254 worker，实际验证在受 15 秒超时约束的一次性子进程中运行，崩溃或超时全部失败关闭。

运行依赖已执行 `npm audit --omit=dev`，结果为 0 个已知漏洞；lockfile 将 snarkjs 兼容但 CLI-only 的 `bfj` 精确固定为不含 `jsonpath/underscore` 漏洞链的 7.0.2。完整开发树仍因 `circomlibjs → ethers` 报告低/中/高告警，因此生产镜像必须使用 `npm ci --omit=dev`，不得携带电路生成工具链。

本地 PostgreSQL 模式可在明确设置 `ALLOW_LOCAL_DEV_KEY=true` 时创建权限为 `0600` 的持久化开发密钥，从而支持服务重启后解密历史交易。该文件仅用于单机开发并被版本控制忽略；生产必须关闭此选项并由 KMS/HSM 提供密钥。

## 本地运行

需要 Node 20–22、PostgreSQL 15+，以及项目依赖：

```sh
npm install
cp .env.example .env
export DATABASE_URL='postgres://rwa_app:...@127.0.0.1:5432/rwa_control_plane'
npm run migrate
npm test
```

以上地址仅用于本机 sandbox。`AUTH_MODE=oidc` 的生产运行会强制要求 HTTPS
`PUBLIC_ORIGIN`、Secure Cookie，以及带 `sslmode=verify-full` 的 PostgreSQL URL；仅加密但
不验证数据库证书的 `sslmode=require` 会在启动时失败关闭。

生产环境必须使用独立 migrator 角色先执行 `scripts/migrate.js`；Web/Worker 运行角色不应
拥有 schema、table 或 trigger 的 DDL 权限。OIDC 生产模式不会自动迁移，只会只读核对每个
迁移文件的 SHA-256、最新版本以及是否存在未知版本，缺失或漂移即拒绝启动。

当前 Mac 已在 `~/Library/Application Support/RWADev` 隔离安装 PostgreSQL 16.15 和 Node 22.23.2；由于 Codex 沙箱不允许创建 System V IPC，首次数据库初始化必须从普通 macOS Terminal 运行：

```sh
cd <repo>
./scripts/start-local-postgres.sh
./scripts/verify-local-postgres.sh
```

本地实例仅监听 `127.0.0.1`，使用无密码开发认证；它不得用于共享、测试服务器或生产环境。远程环境必须使用 SCRAM 密码、TLS、网络白名单和独立的迁移/运行/审计角色。

只有配置 `DATABASE_URL` 时，PostgreSQL 集成测试才会执行；否则测试输出中会明确显示 `SKIP`。

## 上线前仍必须完成

1. 用独立数据库角色执行迁移；运行账户只授予最小 DML 权限，不能修改触发器和审计表；
2. 将独立 Worker 接入生产进程监管、集中指标和告警平台，并接入带签名验证的真实机构客户端；
3. 做真实 PostgreSQL 并发测试、故障注入、备份恢复、PITR 和灾备演练；
4. 接入 OIDC/机构 SSO、MFA、共享会话存储、RBAC/ABAC 和机构签名验证，并保留当前服务端身份绑定原则；
5. 用 KMS/HSM 替换本地密钥环，并完成密钥权限、轮换、吊销、恢复和审计；
6. 由香港/迪拜持牌法律与合规团队确认资金、登记、分销、隐私和跨境数据责任。
7. 固定并独立审计 JoinSplit 电路、可信设置、生产验证密钥、manifest 和隔离 verifier 运行边界；用正式产物重跑正反 proof 向量，并由持牌机构决定隐私账本终局如何桥接法定名册。
