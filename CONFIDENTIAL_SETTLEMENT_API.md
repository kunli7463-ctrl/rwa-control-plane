# Confidential JoinSplit settlement API

本接口只在 `STORAGE_MODE=postgres` 且 `ZK_MODE=groth16` 时启用。它完成的是
证明接受与账本终局是两个不同阶段。Groth16 成功后先进入
`CONFIDENTIAL_PROOF_REGISTRY / ROOT_PENDING`；只有受授权的根发布方确认两个输出已进入
权威 Merkle 树，并提供 proof 绑定的 recipient/relayer 效果引用后，交易才进入
`CONFIDENTIAL_NOTE_LEDGER / SETTLED`。这仍不代表银行现金、托管资产或法定名册已经更新。
所有写请求都必须携带服务器会话 Cookie 和该会话签发的 `x-csrf-token`。

## 治理：激活电路与创建产品上下文

`POST /api/zk/parameters/proposals`（operations，`zk.parameters.propose`）与
`POST /api/zk/parameters/proposals/:id/decision`（`zk.parameters.approve`，`{"decision":"APPROVE|REJECT","reason":"..."}`）。
经办人与复核人必须是不同 principal，所有动作写入审计链。

- `{"kind":"CIRCUIT_ACTIVATION"}`：只能激活本运行时已钉住并加载的 artifact（verification key 与 manifest 哈希
  由服务端填入），无法指向未审阅的密钥。
- `{"kind":"PRODUCT_CONTEXT","productId","contextId","assetType"}`：批准时原子写入产品上下文与空的创世票据树
  （含 frontier）。`contextId` 不可复用；产品已有有效上下文时拒绝——上下文轮换需要单独设计票据迁移，
  否则旧票据会在新上下文下以新的 nullifier 被再次花费。

## 0. 登记收款人票据公钥

`POST /api/zk/note-owner-keys`（分销机构，`confidential.owner_key.register`）

```json
{ "productId": "hk-liquidity-sandbox", "subjectRef": "investor-b",
  "credentialId": "credential-investor-b", "ownerPublicKey": "<Poseidon(ownerSecret)>" }
```

只有被分配为该产品 `distributor` 或 `credential_issuer` 的机构可以登记；凭证必须属于该投资者、
在有效期内、状态为 `ACTIVE`，且投资者类别与法域符合产品规则。同一公钥在同一产品下只能登记一次。
`POST /api/zk/note-owner-keys/revocation`（`{"productId","ownerPublicKey","reason"}`）撤销后，
尚未验收的交易也会在 authorize/accept 时失败关闭。

## 1. 准备交易

`POST /api/zk/transfers`

经纪角色提交已经协商完成的业务指令：

```json
{
  "transactionId": "client-generated-unique-id",
  "idempotencyKey": "broker-order-2026-0001",
  "productId": "hk-liquidity-sandbox",
  "fee": "0",
  "recipient": "123456789",
  "relayer": "0",
  "expiresAt": "2026-08-24T18:30:00.000Z",
  "senderInvestorId": "investor-a",
  "senderCredentialId": "credential-investor-a",
  "recipientInvestorId": "investor-b",
  "recipientCredentialId": "credential-investor-b"
}
```

自迁移 026 起必须提供付款人与收款人的投资者和凭证：两者都要满足产品的投资者类别、法域、有效期
和 `ACTIVE` 状态（`CONFIDENTIAL_PARTY_INELIGIBLE`，`details` 标明哪一方和原因），且 `recipient`
必须是已登记给该收款人凭证的有效票据公钥（`RECIPIENT_KEY_NOT_REGISTERED`）。authorize 与 accept
时会重新检查，期间凭证受限或公钥被撤销都会失败关闭。隐私轨道看不到金额，因此持仓上限无法在此检查。

注意：v2 电路没有把 `recipient` 与输出票据所有者绑定，上述检查只能约束"名义收款人"。
`zk-candidate/circuits/confidential_ledger_v3.circom` 增加了 `outputOwnerPubKey[0] === recipient`
和找零归属约束，公开信号顺序不变；正式启用需要重新审计与可信设置。

`fee`、`recipient`、`relayer` 必须为规范十进制域元素；`fee` 还必须适配 `uint64`，
`recipient` 不得为零；`expiresAt` 必须在未来且不超过 24 小时。租户、授权人、电路版本、
`contextId` 和 `assetType` 均由服务端会话、产品策略和固定产物推导，客户端不能覆盖。

成功状态为 `PROOF_PENDING`，结算轨道为 `CONFIDENTIAL_NOTE`。同一租户的幂等键重试
返回原交易；用相同幂等键提交不同请求返回 `IDEMPOTENCY_CONFLICT`。

## 2. 冻结公开输入

`POST /api/zk/transfers/{transactionId}/authorization`

```json
{
  "publicInputs": {
    "merkleRoot": "...",
    "contextId": "...",
    "assetType": "...",
    "fee": "...",
    "recipient": "...",
    "relayer": "...",
    "transactionHash": "...",
    "inputNullifier0": "...",
    "inputNullifier1": "...",
    "outputCommitmentX0": "...",
    "outputCommitmentX1": "...",
    "outputCommitmentY0": "...",
    "outputCommitmentY1": "..."
  }
}
```

服务端会把五个业务字段与不可变产品上下文、执行指令重新比较，并验证 Merkle root
处于可接受窗口。授权记录只允许一次从 `PENDING` 转为 `VERIFIED`，其他字段不可修改。

## 3. 验证并结算

`POST /api/zk/transfers/{transactionId}/settlement`

```json
{
  "proof": { "pi_a": [], "pi_b": [], "pi_c": [], "protocol": "groth16", "curve": "bn128" },
  "publicSignals": ["13 items in the pinned manifest order"]
}
```

请求体上限为 2 MiB。验证在有 15 秒超时和输入/输出上限的短生命周期子进程中执行；
默认最多同时运行两个 verifier，超限立即返回 503，不建立无界等待队列。
成功后，以下内容在同一个 Serializable PostgreSQL 事务中提交：

- Groth16 验证回执；
- 两个已消费 nullifier；
- 两个输出承诺；
- 授权状态 `VERIFIED`；
- 交易状态 `ROOT_PENDING`；
- 不可变 `zk_settlements` 证明接受记录（终局域仍为 `CONFIDENTIAL_PROOF_REGISTRY`）；
- 脱敏交易回执、审计链和 Transactional Outbox。

任何唯一键、上下文、root、验证器或数据库检查失败，以上内容全部回滚。成功响应会明确包含：

```json
{
  "verified": true,
  "proofAccepted": true,
  "settlementApplied": false,
  "transactionState": "ROOT_PENDING",
  "finalityDomain": "CONFIDENTIAL_PROOF_REGISTRY",
  "legalRegisterApplied": false
}
```

### 4. 权威根与效果确认

第一名 operations 经办人调用：

`POST /api/zk/transfers/:transactionId/finalization-proposal`

该接口只授予 `operations` 的 `transaction.zk.finalize.propose` 权限。它不是第二次 proof 验证，
而是对外部权威树发布和 proof-bound 执行效果的受控确认。

自迁移 022 起，`outputMerkleRoot` 不再是只靠双人背书的数字：服务端从该 context 的 `CURRENT`
根读取增量树 frontier，按 `output_index` 顺序追加本交易的两个输出承诺
（`Poseidon([CL2LEAF, x, y])`），自行计算新根与树大小。提交值必须与服务端计算值完全一致，
否则返回 `409 ROOT_PUBLICATION_MISMATCH`，`details` 中给出 `expectedMerkleRoot` 与
`expectedTreeSize`。提案同时钉住所扩展的 `baseMerkleRoot`/`baseTreeSize`。

```json
{
  "outputMerkleRoot": "...",
  "outputTreeSize": 1026,
  "rootSourceReference": "root-publisher:batch-2026-08-24-001",
  "executionReference": "settlement-engine:execution-001"
}
```

第二名、不同 principal 的 operations 复核人调用：

`POST /api/zk/transfers/:transactionId/finalization`

该接口使用 `transaction.zk.finalize.approve` 权限且不接受可被替换的业务字段；所有根与执行
引用只从数据库内不可变 proposal 读取。maker 与 checker 相同会失败关闭。

批准时服务端再次锁定 `CURRENT` 根并重新计算。若提案之后已有其他交易推进了票据树，提案会被
自动撤回并返回 `409 STALE_ROOT_PUBLICATION`（`details` 给出当前根和新的期望根），需要基于当前根
重新提案；这防止了"后批准的根覆盖掉前一笔交易输出"的问题。

经办人或复核人可撤回待复核提案（`transaction.zk.finalize.cancel`）：

`POST /api/zk/transfers/:transactionId/finalization-cancellation`，请求体 `{"reason":"..."}`。

撤回的提案作为历史保留，交易可重新提案。没有 frontier 的根不能成为 `CURRENT`（数据库拒绝），
因此新 context 必须从带 frontier 的创世树开始。

成功后返回 `rootPublicationAttested:true`、`externalExecutionAttested:true`、
`settlementApplied:true`、`state:"SETTLED"` 和
`finalityDomain:"CONFIDENTIAL_NOTE_LEDGER"`。数据库会原子保存根发布证明、最终回执、
审计事件与 Outbox；缺少任一外部引用都失败关闭。

## 5. 健康检查

- `GET /health/live`：进程存活；
- `GET /health/ready`：数据库可访问，并报告 ZK 与隐私结算 API 是否启用。

健康检查不包含业务数据，也不需要登录。
