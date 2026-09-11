# 四项内部安全收尾：执行记录

此文件是实现方记录，不是独立审核或上线批准。旧验收记录不覆盖。

## 1. 开发依赖风险

当前 circomlibjs 0.1.7 属于开发依赖，其 CommonJS 入口仍实际 require ethers。
因此不能把“业务未使用 ECDSA 签名”等同于“依赖未加载”。已检查本项目候选参考代码
使用 buildPedersenHash/buildBabyjub/buildPoseidon，没有主动调用 ethers 签名；这只是
当前代码路径范围检查，不是所有输入下的不可达性证明。elliptic 告警尚未豁免。
不修改第三方密码学算法，不通过整库降级或 npm audit 忽略规则消除告警。
运行镜像实际检查 circomlibjs/ethers/elliptic/ws 均不可解析，开发链未进入运行镜像。
仍需独立审查开发使用边界、上游修复或经验证的替代方案。

## 2. 容器扫描与已实施修复

扫描器：官方 Homebrew core 的 Trivy 0.74.0。未信任机器上无关的第三方 tap。
本次只读取本地镜像、下载公共漏洞数据库，不上传业务数据。

| 镜像阶段 | OS Low/Medium/High/Critical/Unknown | 镜像内 JS 告警数 |
| --- | --- | --- |
| 原 Node 22.19.0 / Debian 12.12 | 81 / 115 / 61 / 6 / 8 | 54 |
| Node 22.23.2 / Debian 12.15 | 72 / 86 / 52 / 4 / 8 | 19 |
| 固定系统补丁并移除运行阶段 npm CLI | 72 / 86 / 52 / 4 / 2 | 0 |

以上是包级告警条目，不是本业务真实可利用漏洞计数。原始报告分别为：
`.local/trivy-baseline-2026-09-04.json`、`.local/trivy-node22-updated-2026-09-04.json`、
`.local/trivy-hardened-2026-09-04.json`。
系统及应用组件 SBOM：`.local/container-sbom-2026-09-04.json`（组件清单，不是另一份漏洞扫描）。

Dockerfile 两阶段固定官方 Node 22.23.2 manifest 摘要；安装明确版本
`libpcre2-8-0=10.42-1+deb12u1`。仅在运行阶段移除全局 npm 和 npm/npx 入口，
构建阶段仍通过锁文件安装应用依赖，应用 node_modules 保留，宿主 npm 未改变。
最终镜像验收：`.local/container-acceptance-2Kk51Z/report.json`，正常迁移、权限、
CSRF、非 root、回环端口、重启密钥持久化、运行镜像无 npm CLI、生产配置拒绝均通过。

剩余告警不自动压制。两个典型分类问题：

- CVE-2023-45853：Debian 说明 bookworm 的 zlib 二进制未构建受影响 minizip 代码。
  来源：https://security-tracker.debian.org/tracker/CVE-2023-45853 。
- CVE-2026-8376：上游条件为 32 位 Perl 编译攻击者正则；当前镜像 Linux arm64。
  仍需复核具体二进制构建属性，不能单凭镜像架构就对所有 Perl CVE 豁免。
  来源：https://security-tracker.debian.org/tracker/CVE-2026-8376 。

`scripts/summarize-image-scan.js` 对所有等级保留计数，未修复/Unknown 也保持退出 2；
拒绝缺少 OS 结果、无有效镜像摘要或超过 48 小时的扫描记录。它不是发布审批器。
剩余 4 个 Critical 原始条目及 52 个 High 尚未逐项完成可达性评审，发布仍受阻。

## 3. ZK 跨操作系统重建及来源链

Linux 构建目录 `.local/zk-linux-fMgZzp/`，使用官方 Rust 1.85.0 固定镜像摘要、
Cargo.lock、Circom 2.1.6 源码及 circomlib 2.0.5。无用户目录挂载。
与 macOS `.local/zk-rebuild-q7MuIT/first/` 对照，三个文件 SHA-256 完全一致：

| 文件 | SHA-256 |
| --- | --- |
| R1CS | e8f49a0d5c4c6078a764dd15242aeed123b529ad76520ee5cfb5a741af768f82 |
| SYM | a1777767771cbcc94d0ab0c94324fa2c6461dfc15db5c3fed0826b7f9d3d3bfe |
| WASM | 77bf26d2f9fe5d4978a9902897cc146f653c44b8a29eacbaa7ddaf6648ec08bd |

此为同一物理 Mac 上 Linux VM 与 macOS 的跨 OS 复现，不冒充另一台独立主机。
历史 fixture 没有 proving key，无法追溯其来源，仅保留为旧回归向量。
另建 `.local/zk-provenance-icgaPN/` 测试链，绝不可用于生产。
初次使用未贡献测试 PTAU，校验报 H section does not match；失败报告保留在
`source-chain-A3vuW4/report.json`。未降低校验要求，后续重建单机贡献测试参数。
新测试链结果应以其单独 report.json 为准，不能沿用旧向量的成功结果。

后续结果：`source-chain-I6jSXv/report.json` 为
`LOCAL_SOURCE_CHAIN_VERIFIED_NOT_SECURITY_APPROVAL`。新 zkey 经 verifyFromR1cs 验证，
导出验证密钥后生成的新证明验证通过，13 个公开输入与预期一致；旧 fixture 未修改。
单机测试设置不提供生产可信性。初次失败保留；曾提前读取仍在生成的参数文件，
该次操作已取消（退出 130），不计为通过。snarkjs 出现 FileHandle GC 关闭弃用警告。

## 4. 独立复核

待冻结源码清单后交现有独立只读审核任务复核。本实现方不自行宣布独立审计通过。
检查对象应包括上述所有剩余项、测试脚本是否正确拒绝、生产配置与实际 runtime 是否一致。
不 commit/push、部署或接入真实资产，不因用户要求收尾而暗中批准安全风险。

冻结清单 `release-evidence/2026-09-04T16-58-19-901Z/` 有 171 个条目。
原「RWA 全仓独立只读安全审核」已启动复核，初检确认清单一致，随后因账户额度限制
中断，未产出最终审核报告。不能把启动或初检写成独立审核通过。
本轮最后一次全量数据库复跑也在执行前被自动审批因额度限制拒绝，未实际运行。
此前实际全量结果为 165/165；新增扫描门禁两项已独立通过，不能直接相加宣称
完整 167 项套件已经运行通过。

## 5. 后续修复与重新验收（2026-09-05 UTC）

发现并修复应用入口的跨机构签名密钥管理权限缺口：仅有机构密钥管理权限，
不能据此登记或撤销其他机构的密钥。DemoRuntime 两个入口现在要求服务端身份的
institutionId 与目标机构相同，并要求明确的匹配 tenantId；HTTP 原有权限和 CSRF
检查继续保留。新增 `test/institution-key-authorization.test.js` 四项回归，覆盖
跨机构、缺失身份属性、跨租户拒绝及合法调用的可信 actor/tenant 传递。
本修复是实现方核验结果，尚待独立审核确认服务层及全局机构键的完整安全边界。

执行记录：

- 针对性测试：12/12 通过。
- 普通沙箱内非数据库测试：152 项中 145 通过、7 失败，包含回环监听 EPERM；
  未把这次运行算作通过。
- 此前额度恢复时间已过，重新申请本地验收执行权限获准。
- `./scripts/verify-local-postgres.sh` 实际执行成功，Schema is current；
  **171/171，0 失败、0 跳过，退出码 0**，包含 PostgreSQL 集成与回环 HTTP 测试。
- 新源码冻结：`release-evidence/2026-09-05T05-21-34-916Z/`，172 个文件。
  清单验证输出 `SOURCE_INVENTORY_VERIFIED 172`，依赖门禁仍为
  `AUDIT_GATE_NOT_CLOSED`（退出 2），生产依赖审计退出 0，全依赖退出 1。
- 旧 171 文件清单只保留为历史证据，不代表本次源代码。旧容器也未包含本次权限修复，
  须重新构建和运行验收，不能借用旧镜像的成功结论。
- 已将最新冻结清单和修复范围发送给原独立只读审核任务继续复核；尚未收到最终结论。

当前仍未批准发布：开发依赖风险、容器 OS 报告处置、正式 ZK 参数/历史来源链边界、
独立审核以及最新镜像验收均不得因本次 171 项通过而自动关闭。

独立任务随后返回 systemError：平台将请求标记为可能的网络安全风险，未执行完审核、
未产生结论。这不是代码审核失败结论，也不是审核通过。未通过改写请求或切换执行路径
绕过该限制；需平台认可的安全工作访问授权或外部独立审核方才能继续此项。

## 6. 最新镜像重验（2026-09-05 05:33 UTC）

以当前 172 文件冻结源码重建既有隔离 Compose 项目 rwa-acceptance，未删除卷，
未接入真实资产或发布生产。Web 镜像摘要：
`sha256:514a35102da1ce50d8f6406372be73ec2e296a4a09bd3f3952fc5edcfa360b17`。

`scripts/verify-container-runtime.js` 退出 0，报告保存于
`.local/container-acceptance-Raw9Ko/report.json`。迁移与健康检查、非 root、只读文件系统、
回环端口、身份/CSRF 检查、开发依赖与 npm CLI 排除、重启后的持久化密钥、
缺省生产配置拒绝启动等检查均通过。仅为本地合成数据 PoC 的运行验收。

新镜像 Trivy 结果：`.local/trivy-latest-2026-09-05.json`。
Node 包报告 0；Debian 系统包 UNKNOWN 2、LOW 72、MEDIUM 86、HIGH 52、CRITICAL 4，
可用修复版本条目数为 0。`summarize-image-scan.js` 正确退出 2，REVIEW_REQUIRED。
包级告警不等于已证明可利用，也不因暂无修复版本而可自动豁免。
此前系统包 SBOM 属于历史镜像，不能代替最新镜像身份。本次另生成
`.local/container-sbom-2026-09-05.json`，为最新镜像的 CycloneDX 组件清单；
该生成命令未执行漏洞扫描，漏洞结论来自上述单独 Trivy 扫描文件。

镜像重建与运行重验此项现已完成；风险处置及独立审核仍未完成。
本轮未改变应用源码，172 文件冻结清单仍适用；新增文档记录不计入该代码清单。

## 7. 数据库驱动维护（2026-09-05 07:35 UTC）

通过 npm 官方版本元数据核对，pg 有同主版本更新。已将 pg 从 8.16.3 固定升级为
8.23.0，同步 package-lock.json，安装禁用生命周期脚本。未执行 audit fix --force。
本更新属于版本维护，不宣称修复 elliptic 开发依赖告警。

更新后的驱动提示同一个 client 上并发 query 的弃用警告。将 postgres-read-model.js
事务中的证据查询、投资者余额查询，以及 product-catalog-service.js 的事务快照查询
改为逐条 await；保持原连接及原事务隔离级别，连接池独立查询仍可并行。

调整后 `verify-local-postgres.sh` 退出 0：171 项通过、0 失败、0 跳过。
本地隔离镜像重新构建成功，`verify-container-runtime.js` 退出 0，证据目录
`.local/container-acceptance-MuQqNj/`。未重发被拦截的独立审核任务。

当前源码证据为 `release-evidence/2026-09-05T07-34-54-814Z/`，
SOURCE_INVENTORY_VERIFIED 172；生产依赖报告退出 0，全依赖退出 1，
仍为 15 个低等级告警。总门禁仍 AUDIT_GATE_NOT_CLOSED，未豁免风险。
第 6 节镜像扫描和 SBOM 为更新前镜像，不冒充本轮更新后的镜像报告。

尚未完成：开发依赖告警有依据处置、系统包告警有依据处置、独立审核。
本记录仅证明上述维护与兼容性回归已完成，不能据此宣布内部安全收尾全部完成。
