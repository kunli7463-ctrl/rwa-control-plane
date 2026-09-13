# 内部工程收尾台账

本台账替代“内部工作已全部完成”的笼统说法。通过测试不是生产安全背书。

| 阶段 | 当前证据 | 尚待完成 |
| --- | --- | --- |
| 1—3 运行时、部署合同、压力故障 | 既有本地回归、数据库并发及故障测试；宿主重启由用户报告通过 | Docker/实际基础设施验收不能用源码测试替代 |
| 4 监控 | 34 条规则、40 个场景、26 面板查询、合成告警触发恢复 | 浏览器视觉、实际隔离网络及真实通知接收方 |
| 5 四地产品配置 | HK/SG/MY/AE 草案生成器；显式单市场资格、币种、制度和数据区域；6 个新增测试通过 | 真实规则定义、合作机构证据；非基金完整生命周期另立开发范围 |
| 6 供应链 | 锁文件依赖来源/integrity 检查、CycloneDX SBOM、源码哈希清单、在线审计报告生成器 | 最近在线审计超时；许可证复核、镜像/宿主供应链和发布签批 |
| 7 ZK 构建 | Circom 2.1.6 官方标签源码本机构建成功；两次 R1CS/WASM/SYM 字节一致；候选隔离测试通过 | 跨主机验证、向量与源码同源关系、独立密码学审计/ceremony |
| 8 最终复核 | 全量 PostgreSQL 回归 161/161，零失败零跳过 | 变更冻结后的独立只读安全复核，不能由实现者自称独立审核 |

## 第五阶段边界

`MARKET_PROFILES.md` 与 `src/market-draft.js` 是技术草案工具，不自动激活，不提供法律判断。
马来西亚/阿联酋是拟运营基地，香港/新加坡是服务市场，不能把四地代码支持解释为四地牌照。
国家代码也不能替代阿联酋不同制度的选择。未知投资者规则不得默认套用香港 professional。

## 第六阶段证据

运行 `npm run release:evidence`（必须使用项目 Node 22）。输出到独立时间戳目录，
包括 CycloneDX、生产/完整 npm audit JSON、源码清单和 summary。任一在线审核失败或
存在漏洞时退出非零，但仍保留可生成的离线证据。脚本不执行 npm audit fix，不升级锁文件。
来源允许表覆盖 npm 包 tarball URL 和 integrity；不代表依赖代码没有恶意内容。
源码清单只取指定目录及文件，不递归打包 .env、本地密钥、数据库备份或工具目录。
符号链接只记录目标、不跟随，外部目标被拒绝。

## 第七阶段边界

`zk-candidate` 是未批准快照。Circom 版本要求 2.1.6，circomlib 要求 2.0.5。
`RWA_CIRCOM_BIN=/absolute/path npm run zk:rebuild` 在两处独立输出目录编译并比较
R1CS、WASM、SYM 的 SHA256。相同只代表本机工具链字节复现，不代表约束完备或可信 setup。
没有自动替换生产验证密钥，没有生成或发布新的生产 ceremony 产物。

最新重建报告：`.local/zk-rebuild-jhuGJi/report.json`，`sameHostByteIdentical=true`。
官方源码仓库 https://github.com/iden3/circom ，标签 v2.1.6，提交
`57b18f68794189753964bfb6e18e64385fed9c2c`。使用 `cargo build --release --locked`，
无系统安装；构建目录约 339 MB，源码约 4.9 MB，位于项目内且已排除版本管理。

旧来源 `run_tests_v2.js` 的部分拒绝归因不能直接采信：重复输入用例同时破坏金额守恒；
非布尔 Merkle 用例还可能因另一输入根或 transactionHash 不匹配而失败。
本轮新脚本 `verify-zk-candidate-matrix.js` 不复制其“唯一原因”的断言：重复输入重新
配平输出并重算承诺/交易哈希，通胀用例也保持承诺/哈希一致；各自移除唯一目标约束的
临时变体必须能够接受同一输入，才认为隔离对照成立。候选原文件保持不变。
这属于测试论证修正，不是已发现主电路可利用漏洞，也不是独立审计结论。

## 下一次独立只读复核入口

本地统一验收入口：`zsh scripts/verify-internal.sh`。要求 PostgreSQL 已启动；依次运行
全量数据库测试、监控规则、原生监控、双重电路构建、隔离矩阵、供应链在线核查。
任一步失败即停止，不自动重启宿主数据库、不创建生产 ceremony、不发布或部署。
本回合各项已分别执行；在线供应链查询未通过，因此不能声称统一流水线全绿。

随后已实跑统一流水线：全量 161/161、监控规则/原生通知、双重构建、8 项隔离矩阵
全部经过；最后在供应链查询处退出 2，未输出总通过标记。记录分别位于：
`.local/monitoring-runtime-fck7Yo/report.json`、`.local/zk-rebuild-q7MuIT/report.json`、
`.local/zk-rebuild-q7MuIT/first/candidate-matrix-U9gd0Y/candidate-matrix-report.json`、
`release-evidence/2026-09-04T11-23-01-868Z/summary.json`。

最终源文件刷新后的证据目录为 `release-evidence/2026-09-04T11-26-21-578Z/`，
两类在线审计仍为退出 2（网络查询未验证），SBOM 和源码清单已生成。
最终再次执行 PostgreSQL 全量回归：161/161、0 失败、0 跳过。

隔离矩阵证据：`.local/zk-rebuild-jhuGJi/first/candidate-matrix-oKZxjl/candidate-matrix-report.json`。
监控复跑：`.local/monitoring-runtime-VAL5TA/report.json`。视觉审阅窗口结束后临时凭据
已抹去且原生服务已停止；没有取得浏览器截图，因此视觉检查仍未关闭。

进一步使用应用自带 Playwright 和系统 Chrome 尝试隔离浏览器验收，Chrome 在页面
加载之前 SIGABRT 退出，记录在 `.local/monitoring-runtime-YL6Ls3/report.json`。
该运行判 FAIL，不混入先前通过数。未使用用户现有 Chrome 配置，没有截图验收结论。
可在具备 GUI/浏览器运行权限的宿主环境设置 `RWA_PLAYWRIGHT_MODULE`、`RWA_CHROME_BIN`
后重跑 `scripts/verify-monitoring-runtime.js`；脚本只向本机合成 Grafana 注入临时认证，
拦截其他 origin 请求，截图保存于本次运行目录。正常生产配置不会开放匿名访问。

请先读本台账、`CLAUDE_CODE_AUDIT_HANDOFF.md` 和近两次监控验收报告，再从代码验证断言。
重点检查本轮 Web 私网指标与统计权限、草案/授权边界、源码归档与 release evidence 的遗漏、
ZK 编译输出到验证密钥的来源链。只读复核不 commit/push/部署、不修改原始 v1、不清空数据库。
报告分别标明：真实漏洞、配置/运维约束、外部事实、测试未运行及文档问题。

## 供应链修复与最终复跑（本日后续，覆盖上述旧计数）

- `ws` 从 8.18.0 升至 8.21.0，以 package.json overrides 和锁文件精确固定；
  npm install 使用 ignore-scripts，没有自动降级 circomlibjs 或改动候选电路快照。
- 更新后 PostgreSQL 全量回归：165/165，0 失败、0 跳过，退出 0。
- 更新后候选矩阵：8 项通过；预期拒绝用例的 assertion 日志不代表矩阵失败。
  证据：`.local/zk-rebuild-q7MuIT/first/candidate-matrix-gv2gt2/candidate-matrix-report.json`。
- 当前供应链证据：`release-evidence/2026-09-04T12-00-31-522Z/`。
  生产依赖 audit 退出 0、告警 0；全部依赖 audit 退出 1，15 个 Low 条目，
  Moderate/High/Critical 均为 0。15 条是 elliptic 告警沿 ethers/circomlibjs
  依赖链传播形成的包条目，不能写成 15 个独立漏洞。
- 证据复核器实际执行：`SOURCE_INVENTORY_VERIFIED 166`，
  `AUDIT_GATE_NOT_CLOSED`，退出 2。总验收仍不为绿。

`elliptic` 的 GHSA-848j-6mx2-7j84 在查询时没有已修复版本。
当前 circomlibjs 属于开发依赖，候选参考实现使用 Pedersen/BabyJub/Poseidon，
未发现项目生产源码直接调用 ethers/elliptic ECDSA 签名；Dockerfile 的依赖安装
明确 omit=dev。以上是范围检查，不是完整可达性证明，也不能替代实际镜像扫描。
没有批准风险豁免，不对依赖源码临时打密码学补丁，不采用 audit 建议的整库降级。
后续需要有验证依据的依赖替换/上游修复，或经独立复核的书面风险处置。

公告：[ws 修复](https://github.com/websockets/ws/security/advisories/GHSA-96hv-2xvq-fx4p)、
[elliptic 未关闭项](https://github.com/advisories/GHSA-848j-6mx2-7j84)。

仍未完成：宿主浏览器视觉验收、Docker 实际构建/运行验收、开发依赖风险闭环、
跨主机 ZK 构建与验证产物来源链、变更冻结后的独立只读复核。
这些没有归入“外部机构责任”而隐去，也不能用当前测试通过替代。

## 容器与视觉收尾完成（本日最终追加，覆盖上述对应未完成状态）

- 监控代表性视觉验收已实际完成，见 `MONITORING_VISUAL_ACCEPTANCE_2026-09-04.md`。
  原生运行报告 `.local/monitoring-runtime-iVATku/report.json` 为 PASS；不是全设备测试。
- 独立 Colima 配置 `rwa-acceptance`：2 CPU、3 GiB 内存、20 GiB 稀疏数据盘；
  无用户主目录挂载，未切换默认 Docker context。仅本机合成数据，非生产部署。
- 修复 Docker 构建上下文误含开发工具目录、首次密钥卷目录权限和 PoC profile 配置。
  Docker 内部网络单独挂载时没有真正发布端口，现 Web/worker 使用前端桥接网络，
  数据库只在内部网络；实际端口绑定也纳入检查，不只读配置声明。
  前端网络允许出站，不宣称本地 PoC 具有生产 egress deny。
- 最终源码镜像重建、启动及再次验收 PASS：
  `.local/container-acceptance-OcEJi5/report.json`，保存镜像 ID。
  验证迁移成功、三服务健康、应用非 root/只读根、回环端口、数据库无宿主端口、
  HTTP 身份/权限/CSRF、开发依赖链未进入运行镜像、重启后 0600 密钥文件元信息不变、
  缺少明确 production profile 时默认生产镜像拒绝启动。
- HTTP 原失败为固定 8 月净值过期，返回 `MISSING_EVIDENCE` 是正确业务拒绝。
  容器验收仅对明确命名的隔离项目，经 issuer 身份及 CSRF 保护的 reset 路由刷新
  合成数据，再执行实际认购。未放宽净值校验，普通 HTTP 验收脚本不自动清空数据。
  原生开发数据库未被此步骤重置。演示数据过期后须重新准备，不能自动延长真实证据。
- 最终 PostgreSQL 全量 165/165、0 失败、0 跳过；压力/故障 16/16，默认 100 事件、
  6 worker；监控测试 16/16、原生 promtool 34 规则及规则用例通过。
  监控一次受 sandbox 回环监听 EPERM 拒绝，取得执行权限后原样重跑通过，未删测试。
- 源码证据清单新增完整性反向检查：新文件漏列也拒绝，包含 `.dockerignore`；
  非仅检查已列文件哈希。补充新增文件/排除 secret/重复项等回归断言。
- 最新供应链目录 `release-evidence/2026-09-04T16-25-04-685Z/`：
  清单 168 文件一致；生产 npm 告警 0，全部依赖 15 Low，其余等级 0。
  总发布门禁仍 `AUDIT_GATE_NOT_CLOSED`（退出 2）。没有风险豁免。

### 本机环境复用注意

Docker 始终显式指定 `DOCKER_HOST=unix://$HOME/.colima/rwa-acceptance/docker.sock`
及项目 `.local/docker-client` 的 DOCKER_CONFIG；Compose 项目名固定 `rwa-acceptance`。
验收端口为 127.0.0.1:18765（Web）及 18770（worker）。
本次 VM 的 `/etc/resolv.conf` 指向不存在的 `/run/systemd/resolve/stub-resolv.conf`，
仅在此隔离 VM 内修复，使用本地 `.local/acceptance-resolv.conf`；宿主 DNS 未修改。
VM 重启后临时 /run 文件可能消失，若镜像拉取解析失败需先复查，不能误判为应用问题。
不要使用 `down -v` 或删除数据卷作为排错步骤。
验收结束已执行本项目 Compose stop 及 `colima stop rwa-acceptance`，
临时 Web/worker 端口关闭；镜像与数据卷保留，原生开发 PostgreSQL 未停止。

### 仍待关闭（不能算作全部外部事项）

1. 开发密码学依赖 Low 告警的有依据处置，当前未批准豁免。
2. 容器 OS 包安全扫描、生产镜像与运行时更新治理。
3. 跨主机 ZK 可复现构建、验证密钥与源码来源链及正式 ceremony 边界。
4. 变更冻结后的独立只读安全复核；本次实现方回归不冒充独立审计。

当前结论：本机 PoC 容器与监控验收收尾通过，尚未取得生产发布或真实资产接入批准。

### 后续进度（2026-09-05 UTC，优先于以上历史状态）

完整进度及证据见 [四项安全收尾](SECURITY_CLOSEOUT_FOUR_ITEMS_2026-09-04.md) 第 5–6 节。
跨机构签名密钥管理入口已收紧；全量 PostgreSQL 验收 171/171，零失败零跳过。
最新源码清单 172 文件；最新容器重建和运行验收通过，报告为
`.local/container-acceptance-Raw9Ko/report.json`。隔离验收容器本轮已重新启动，
上述“验收结束已停止”为前次历史记录，不代表当前状态。
开发依赖风险和容器 OS 告警尚未关闭；独立审核被平台限制中止，无最终结论。
不能宣称内部安全收尾全部完成或生产可发布。

后续驱动维护：pg 已固定升级 8.23.0，事务内查询改为顺序 await 以适配新驱动。
全量回归仍 171/171；新容器运行验收 `.local/container-acceptance-MuQqNj/` 通过。
当前源码证据 `release-evidence/2026-09-05T07-34-54-814Z/`，172 文件核验通过。
风险项仍未关闭。完整边界和历史证据见四项安全收尾文档第 7 节。

### 完整内部报告

新增 [开发历程、架构作用与市场匹配完整报告](RWA_完整内部报告_开发历程_架构与市场匹配_2026-09-05.md)。
该报告汇总历史演进、当前状态、商业判断及来源，不替代独立安全审核或生产批准。
