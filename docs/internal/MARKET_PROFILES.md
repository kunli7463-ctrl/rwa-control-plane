# 四地技术配置草案

覆盖香港 HK、新加坡 SG、马来西亚 MY、阿联酋 AE；不代表获得牌照或法律批准。
马来西亚/阿联酋作为拟设运营基地，与香港/新加坡服务市场的商业计划相互独立。
本模块不注册公司、不申请牌照、不接触真实资产、不自动建立跨国数据通道。

使用 `scripts/build-market-draft.js input.json template.json output.json`：
输入产品及租户草案、从现有产品目录导出的模板，输出权限 0600 且拒绝覆盖的草案。
脚本只写草案，不连接数据库，也不调用激活接口。

输入字段：market、regime、tenant、product、policy。tenant 与 product 的 jurisdiction
必须一致；tenant 使用 homeJurisdiction。policy 必须显式提供 allowedInvestorClasses、
allowedJurisdictions、maxPriceDeviationBps。币种也必须显式提供，不会按国家自动换汇。
本阶段限定单市场，不默认允许跨境销售。regime 是待审核的管辖制度标识，特别是 AE
不能被解释为迪拜某一特定制度或某张牌照。代码不维护法律资格类别映射。

示例（仅合成资料）：

```json
{
  "market":"MY", "regime":"pending-local-review",
  "tenant":{"id":"tenant-my","legalName":"Synthetic Draft","homeJurisdiction":"MY","dataRegion":"pending-region"},
  "product":{"id":"draft-my","name":"Synthetic Draft","jurisdiction":"MY","issuerId":"pending-issuer","currency":"USD"},
  "policy":{"allowedInvestorClasses":["synthetic-test-only"],"allowedJurisdictions":["MY"],"maxPriceDeviationBps":50}
}
```

后续流程：审查草案 → 使用现有受控产品目录创建暂停状态产品 → 完成机构准入与角色
分配 → 提交真实签名证据 → maker/checker 审批 → 部署环境及当地资格规则验收。
生成器的状态与 blockers 是交接信息，不是新增的运行时授权控制。现有证据、身份和
业务规则仍由服务端执行。dataRegion 仅是配置字段，不能单独证明数据不跨境。

重要边界：已有 BOND/PRIVATE_CREDIT/SUKUK/COMMODITY 目录模板，不等于付息、违约、
到期兑付、实物交付等完整生命周期已经开发。非基金草案会显式标注此缺口；不得向合作方
宣称四地全资产种类已具备生产交付能力。模板版本与监管规则更新仍须单独评审。
