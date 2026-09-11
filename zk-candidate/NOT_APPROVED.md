# 非生产候选快照

来源：本机 Downloads/zk_audit_cloud 的 confidential_ledger_v2.circom 与 reference_v2.js。
仅作审计输入与重建准备。不是经独立审计批准的电路，不是现有测试 verification key
对应源码的独立证明，不得自动替换生产 manifest/vkey。原始 v1 文件没有修改。

既有本地 Groth16 向量可验证，只说明应用验证器互通；不能证明这个候选源码与向量同源。
必须在明确的电路冻结、构建产物及 ceremony 记录之间建立完整哈希关系。

## v3 候选（2026-09-11，审核发现 H1）

`circuits/confidential_ledger_v3.circom` 在 v2 基础上只增加两条约束：
`outputOwnerPubKey[0] === recipient`（有价值的输出必须归属公开收款人公钥）与
`outputOwnerPubKey[1] === inputOwnerPubKey[0]`（找零归还付款人）。公开信号数量与顺序不变。

`scripts/verify-zk-v3-recipient-binding.js` 的本地证据（`evidence/v3-recipient-binding-2026-09-11.json`，
circom 2.1.6 + snarkjs 0.7.6，一次性单方测试 ceremony）表明：v2 接受"公开收款人是 A、价值却转给 B"的
witness；v3 拒绝该 witness 及"找零转给他人"的 witness；诚实的 v3 转账可生成并验证 Groth16 证明，
改写收款人公开信号后验证失败。

v3 同样不是经批准的电路。启用前仍需电路冻结、独立审计、可复现构建、多方可信设置与生产 vkey；
v2 与 v3 的 verification key 不可混用。关于"测试向量与 v2 源码是否同源"，本目录与
`test/fixtures/groth16-local-only/DO_NOT_DEPLOY.md` 的表述存在矛盾，需以源码、r1cs、zkey、vkey 的
哈希链为准重新确认。
