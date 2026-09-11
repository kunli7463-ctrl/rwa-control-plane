# 第四阶段：运行监控与告警处置

## 当前交付与边界

- Prometheus 抓取配置生成器，强制显式 tenant/environment 标签；不采集交易金额、身份、witness 或密钥。
- Outbox/Prover 22 条告警，12 个指标面板及 1 个边界说明面板。
- Worker readiness 与实际健康检查同源；监控不可用返回 503，不能被显示为绿色零值。
- 队列是租户级共享指标：跨 worker 使用 max 而非 sum，避免重复计算。
- 标签/面板不是租户授权。默认只供基础设施运维使用，不能直接开放给客户。
- 不自动配置邮件、短信或 webhook；没有实测送达前，不声称具备通知闭环。
- 第四阶段未覆盖 Web 请求延迟/错误率、数据库磁盘/WAL/复制、主机资源、KMS/OIDC 外部服务指标；
  这些是后续生产监控接线与部署验收项，不因 worker 面板存在就视为全系统监控完成。

## 本地验证

运行 `./scripts/verify-monitoring.sh`：
先执行 Node 接口/配置契约测试，再使用 `RWA_PROMTOOL_BIN` 或 PATH 中的 promtool
执行规则语法和 22 条触发用例。缺少 promtool 时明确退出 2，不打印验收通过。

原生 promtool 测试不同于 Node 源码检查。本机固定版本 promtool 现已安装，22 条规则及
26 个用例通过。执行 `node scripts/verify-monitoring-runtime.js` 可重跑独立合成链路：
原生 Prometheus/Alertmanager/Grafana、dashboard API、数据源、告警触发及恢复通知。
本机临时服务测试结束自动关闭；Docker、浏览器视觉和真实接收器验收仍独立记录。
详情见 [本机验收报告](./MONITORING_ACCEPTANCE_2026-09-03.md)。

## 部署准备（不在本机自动部署）

1. 使用已审查且 digest 固定的 Prometheus/Grafana 镜像，设置
   `RWA_PROMETHEUS_IMAGE`、`RWA_GRAFANA_IMAGE`；Compose 只要求非空，
   运维必须校验完整 `@sha256:` 镜像摘要，不得用 latest。
2. 显式设置 `TENANT_ID`、`RWA_MONITORING_ENVIRONMENT`。执行：
   `node scripts/build-monitoring-config.js /approved/path/prometheus.yml`。
   文件已存在时拒绝覆盖。设置 `RWA_PROMETHEUS_CONFIG` 指向该文件。
3. 设置 `RWA_GRAFANA_PASSWORD_FILE` 指向仅部署管理员可读的强随机密码文件。
   匿名登录和自助注册关闭。不要把密码放进 Git、命令行参数或面板。
4. 先完成生产部署文件要求的全部外部配置。合并
   `deploy/compose/production.example.yaml` 和 `deploy/compose/monitoring.overlay.yaml`，
   执行 `docker compose ... config --quiet` 后再批准启动。
   overlay 将 worker 监控绑定容器接口，但不发布宿主端口。
5. Prometheus 9090、Grafana 3000 仅绑定 127.0.0.1；远程访问需受控 TLS/SSO 代理。
   不要把指标端口直接暴露互联网。网络内访问也需部署防火墙/策略控制。
6. 采集配置只有本部署固定 tenant；标签必须与实际 worker 配置完全匹配。
   跨租户客户访问使用独立监控实例或真正的数据源授权，不能依赖下拉筛选器。
7. 配置实际 Alertmanager 接收路由前，告警只在 Prometheus 中求值。
   发送合成告警到批准的内部接收方，记录触发、送达、确认、恢复时间。
8. 人工验证 Grafana 首次启动、数据源连通、重启保留、无数据状态和权限边界。
   Prometheus 7 天/2GB 本地保留不是备份或业务审计归档。

## TargetMissing

整个抓取 job 缺失。优先检查配置加载、服务发现及抓取清单；不是“业务无流量”。
此规则用于单部署固定两类 job，不保证发现同一 job 下某一个被删除的副本。
还需监控 Prometheus 本身，避免监控系统整体故障无人感知。

## ScrapeFailed

检查 endpoint、DNS、网络和数据库。监控查询失败也产生 503。
先恢复可观测性，不把无法读取指标误判为零积压。

## MetricMissing

HTTP 成功但 readiness 指标不存在，检查 exporter 版本、路径和兼容性。
禁止通过删除告警解决。

## NotReady

进程存活不代表可以服务。检查循环报错、最后成功时间、租约、数据库和依赖；
保留错误码，不在共享日志粘贴私密 payload。修复后确认 readiness 恢复。

## CycleErrors

检查近期 worker 循环失败及重试，不直接重复执行金融操作。
事件只允许使用稳定 event-id 幂等处理。

## BacklogWarning

检查输入速率、输出速率、消费者限流和重试延迟。默认阈值为 Outbox 100、Prover 20，
不是经客户批准的 SLO。

## BacklogCritical

默认 Outbox 1000、Prover 100。排查消费者不可用或容量不足；
扩容前确认数据库连接预算、租约长度及对端幂等能力。

## AgeWarning

默认 Outbox 60 秒、Prover 120 秒。检查最旧任务，区分排队、退避和外部处理时间。

## AgeCritical

默认 Outbox 300 秒、Prover 600 秒。升级处理并评估停止新任务；
不得直接修改账本来使面板恢复。

## ExpiredLeases

检查 worker 崩溃、长任务、时钟和连接中断。让受控租约机制恢复；
不得手工清除租约并同时启动重复副作用。Prover 恢复语义需专项复核。

## TerminalFailures

Outbox 死信或 Prover 终止失败。保存错误证据，走现有经办/复核审批流程；
禁止一键无限重放。确认外部回执/幂等状态后才批准补救。

## 选择启用真实通知（需运维批准，不自动执行）

设置 `RWA_ALERT_WEBHOOK_URL` 和严格匹配的 `RWA_ALERT_WEBHOOK_ALLOWED_HOST`，运行
`node scripts/build-notification-config.js /approved/path/alertmanager.yml`；此命令仅生成配置，
不发送消息。令牌在挂载 Secret 中，不写入配置。设置 `RWA_ENABLE_NOTIFICATIONS=true`
后重新生成 Prometheus 配置，并额外合并 `deploy/compose/notifications.overlay.yaml`。
准备 digest 固定的镜像、`RWA_ALERTMANAGER_CONFIG`、`RWA_ALERT_WEBHOOK_TOKEN_FILE` 后，
由部署管理员批准启动。DNS 主机匹配不是网络隔离；仍需 egress 网络策略和可信 DNS。
真实值班接收器的告警/恢复送达与确认必须单独实测，不能用本机闭环替代。

## 官方配置依据

## web-database-host

浏览器验收选项：设置绝对路径 `RWA_PLAYWRIGHT_MODULE` 与 `RWA_CHROME_BIN` 后运行
`scripts/verify-monitoring-runtime.js`，会用独立临时浏览器渲染并保存两个区域截图。
Chrome 无法启动或页面错误时运行失败，不将 API/PromQL 检查当作视觉通过。
2026-09-04 当前沙箱尝试在 Chrome 启动时 SIGABRT，尚无通过截图。

Web/数据库/主机监控补充（2026-09-03）：共 34 条规则、26 个面板。

- Web 默认不开启指标监听。设置 `WEB_METRICS_ENABLED=true` 后，默认仅监听
  `127.0.0.1:8772/metrics/prometheus`，与业务 HTTP 入口分离。
- Compose 监控 overlay 显式在容器私网绑定 `0.0.0.0`，不发布 8772 端口。
  `WEB_METRICS_ALLOW_PRIVATE_NETWORK=true` 不是防火墙；宿主或云部署必须限制网络访问。
- `RWA_MONITOR_DATABASE_URL` 可指定独立监控账户；未设置时沿用业务数据库连接串，
  但使用独立单连接、只读会话及查询超时。采集器不执行授权或数据写入。
- 数据库统计权限不足时 `rwa_database_details_visible=0`，省略锁等待和长事务指标，
  不伪装成零异常。管理员决定是否给专用账户 `pg_read_all_stats`，不要直接扩大业务账户权限。
- 数据库故障时 `rwa_database_monitor_up=0`，旧统计值不再输出；HTTP 指标端点仍可返回 200，
  以保留 Web 与主机指标。因此必须检查数据库探针告警，不能只看 Prometheus 的 up。
- 采样缓存最多 5 秒（可配置上限 15 秒），并发抓取合并。请求标签仅限方法及状态码类别，
  不记录 URL、身份、凭证、金额、请求体和交易 ID。异常响应不回显连接信息。
- CPU、内存来自 Node 所观测的操作系统，容器内不保证等于 cgroup 限额。
  可用空间仅指应用路径所在文件系统，不代表远程数据库磁盘。数据库 size 是已用大小。
- 本批没有覆盖数据库 WAL、复制延迟、远程磁盘、云账单、cgroup 配额或真实值班接收方。
  Web 延迟和错误率目前提供面板；应依据实际负载制定 SLO 告警，不能把固定阈值当业务承诺。
- 故障处置：先区分目标消失、抓取失败、数据库探针失败和统计权限不足，再查看数据库
  连接容量、锁及长事务。磁盘告警先确认对应挂载点，不自动删除业务数据或数据库文件。


- [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- [Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/)
