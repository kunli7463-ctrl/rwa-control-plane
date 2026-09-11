# Confidential JoinSplit settlement API

本接口只在 `STORAGE_MODE=postgres` 且 `ZK_MODE=groth16` 时启用。它完成的是
证明接受与账本终局是两个不同阶段。Groth16 成功后先进入
`CONFIDENTIAL_PROOF_REGISTRY / ROOT_PENDING`；只有受授权的根发布方确认两个输出已进入
权威 Merkle 树，并提供 proof 绑定的 recipient/relayer 效果引用后，交易才进入
`CONFIDENTIAL_NOTE_LEDGER / SETTLED`。这仍不代表银行现金、托管资产或法定名册已经更新。
所有写请求都必须携带服务器会话 Cookie 和该会话签发的 `x-csrf-token`。

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
  "expiresAt": "2026-08-24T18:30:00.000Z"
}
```

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
而是对外部权威树发布和 proof-bound 执行效果的受控确认：

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

成功后返回 `rootPublicationAttested:true`、`externalExecutionAttested:true`、
`settlementApplied:true`、`state:"SETTLED"` 和
`finalityDomain:"CONFIDENTIAL_NOTE_LEDGER"`。数据库会原子保存根发布证明、最终回执、
审计事件与 Outbox；缺少任一外部引用都失败关闭。

## 5. 健康检查

- `GET /health/live`：进程存活；
- `GET /health/ready`：数据库可访问，并报告 ZK 与隐私结算 API 是否启用。

健康检查不包含业务数据，也不需要登录。
