# 第四阶段本机验收 — 2026-09-03

## 第三阶段交接

用户已反馈 Warp 中最终验收通过。该宿主机重启步骤按用户反馈登记，
不伪称由本任务沙箱独立执行。第三阶段本地压力/故障收尾完成。

## 本轮实际执行

| 验证 | 结果 |
|---|---|
| PostgreSQL 全仓回归 | 148/148，0 失败、0 跳过 |
| 监控/通知 Node 专项 | 10/10 |
| 原生 promtool 规则检查 | 22 条规则通过 |
| 原生 promtool 用例 | 26 个场景：22 个触发、2 个健康、2 个恢复，全部通过 |
| 原生 amtool 真实通知模板检查 | 通过；未发送外部通知 |
| 原生 Prometheus、Alertmanager、Grafana | 本机隔离实例启动成功 |
| Grafana 数据源及 dashboard API | 13 个面板组件加载成功；匿名 API 访问返回 401 |
| 面板 PromQL | 所有查询由原生 Prometheus 解析成功 |
| 本机通知闭环 | readiness 失败→触发通知→恢复→恢复通知，通过 |
| 抓取故障恢复 | exporter 503→up=0→恢复 up=1，通过 |

流水线回执：
`.local/monitoring-runtime-KMqQQc/report.json`。

流水线测试使用真实 exporter 格式和原生服务，但指标输入为明确标注的合成数据，
不连接 DATABASE_URL、不消费业务队列。通知只发到随机本机回环端口，使用临时 Bearer
令牌。为加速端到端传输测试，仅其独立 fixture 将 1 分钟告警等待改为 1 秒；
生产规则本身未改，原生 promtool 用例验证原始等待时间。

Grafana 验收为服务、权限、provisioning、数据源和查询接线，不是浏览器像素级视觉验收。
时间序列出现与原生查询解析不等于真实客户容量或外部服务 SLA。

## 新增交付

- `scripts/verify-monitoring-runtime.js`：自启动原生服务，合成故障注入，保留脱敏回执，
  成功或失败后关闭自己启动的进程。
- `src/monitoring-notifications.js` / `scripts/build-notification-config.js`：
  显式批准 HTTPS hostname、无 URL 凭据/查询参数、禁止重定向、Secret 文件凭据。
- `deploy/compose/notifications.overlay.yaml`：通知链路单独选择启用，不默认向外部发送。
- `deploy/monitoring/local-tools.lock.json`：官方工具版本、下载源及已验证 SHA-256。
- `scripts/verify-monitoring.sh`：自动发现本地固定版本 promtool。

下载及解压产物在 `.local-tools/`，合计约 2.1 GB 磁盘空间；已加入 Git 忽略。
没有安装系统开机服务，没有修改 Homebrew。临时服务已全部停止。

## 尚不能算完成的事项

- Docker Compose 实际构建与启动、生产 Secret 文件访问权限和网络策略验收。
- 真实内部值班接收器、确认流程及恢复通知送达；目前只有本机接收器闭环。
- 浏览器中 Grafana 实际视觉验收。
- Web 请求延迟/错误率、数据库磁盘/WAL/复制、主机资源及 KMS/OIDC 外部服务指标。
- 告警阈值需按真实流量设定；现有阈值不是客户承诺的 SLO。

结论：第四阶段的 Worker 监控核心已完成本机原生验收，不能将其扩大解释为
“全系统生产监控全部完成”。

