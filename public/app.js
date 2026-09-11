const roleButtons = [...document.querySelectorAll("[data-principal]")];
const content = document.querySelector("#view-content");
const metrics = document.querySelector("#metrics");
const actions = document.querySelector("#actions");
const result = document.querySelector("#action-result");
const guide = document.querySelector("#demo-guide");
const catalogPanel = document.querySelector("#catalog-panel");
const catalogResult = document.querySelector("#catalog-result");
let current = { principalId: "issuer-console", role: null, actorId: null, csrfToken: null };
let performing = false;
let guideIndex = 0;
let guideActive = false;
let catalogState = null;

const titles = {
  issuer: "发行人控制台",
  distributor: "分销与资格凭证控制台",
  investor: "投资者私密账户",
  broker: "经纪与成交操作台",
  operations: "基金行政与法定名册",
  supervisor: "监管与审计证据视图",
};

const guideSteps = [
  {
    principalId: "issuer-console", title: "发行人与总览",
    script: "先说明：这不是交易所，而是持牌机构之间的 RWA 控制与结算层。发行人负责产品与规则，但不应看到投资者个人余额。",
    expectation: "产品为 ACTIVE；资产账和法定名册一致；责任机构、规则版本和有效 NAV 来源清晰。",
  },
  {
    principalId: "distributor-console", title: "资格凭证与最小披露",
    script: "KYC 机构继续负责身份判断，平台只验证签名、产品范围、有效期和限制状态，不保存完整证件与银行流水。",
    expectation: "投资者 A、B 的产品级凭证均为 ACTIVE，同时页面不展示真实姓名、证件或住址。",
  },
  {
    principalId: "investor-a-console", action: "subscribe", title: "投资者 A 认购",
    script: "点击右侧高亮按钮。系统会同时检查资格、NAV、现金和持仓上限，再以原子事务写入资产、现金、名册和审计记录。",
    expectation: "认购成功后 A 的私密持仓增加 100 份；发行人只能看到总份额变化。",
  },
  {
    principalId: "broker-console", action: "transfer", title: "已协商成交的受控转让",
    script: "平台不公开撮合。点击高亮按钮，模拟持牌经纪录入 A 向 B 转让 25 份的已协商成交。",
    expectation: "系统验证买卖双方资格、余额、NAV 偏离和模拟现金，成功后资产账与名册同步。",
  },
  {
    principalId: "investor-b-console", action: "redeem", title: "投资者 B 受控赎回",
    script: "点击赎回 5 份。强调每个投资者只看到自己的持仓与现金，不知道其他投资者的交易金额。",
    expectation: "B 的份额减少 5，模拟现金增加，资产账与法定名册继续一致。",
  },
  {
    principalId: "operations-console", action: "simulate-register-failure", title: "外部名册超时",
    script: "点击模拟名册确认超时。真正严谨的系统不能用链上成功掩盖链下失败，所以这里必须安全停止。",
    expectation: "产生异常案件，但资产与现金余额不改变，预留被释放，并保留失败证据。",
  },
  {
    principalId: "operations-console", action: "propose-exception-retry", title: "经办人提出重试",
    script: "经办人只能提交处置方案，不能自己完成终局批准。点击高亮按钮提交新的替代交易方案。",
    expectation: "异常进入 PENDING_APPROVAL；此时仍没有资金或份额变化。",
  },
  {
    principalId: "operations-checker-console", action: "approve-exception-retry", title: "独立复核人批准",
    script: "切换到不同的复核身份后点击批准。系统重新执行全部资格、价格、余额与外部状态检查。",
    expectation: "原异常与替代交易完整关联；同一经办人不能绕过双人控制。",
  },
  {
    principalId: "distributor-console", action: "revoke-b", title: "资格变化即时生效",
    script: "点击限制投资者 B。这里演示资格不是一次性布尔值，而是整个生命周期持续变化的产品级凭证。",
    expectation: "B 进入 RESTRICTED_EXIT：不能新增持仓，但允许赎回，避免资产永久锁死。",
  },
  {
    principalId: "broker-console", action: "transfer", expectedFailure: true, title: "失败不改变余额",
    script: "再次尝试 A 向 B 转让。预期这一步被拒绝；拒绝本身就是要展示的正确结果。",
    expectation: "页面显示资格限制错误，交易不会入账，资产、现金和名册余额保持不变。",
  },
  {
    principalId: "investor-b-console", action: "redeem", title: "受限投资者仍可退出",
    script: "B 虽不能继续买入，但仍可赎回。点击高亮按钮展示合规限制不会把客户资产永久锁死。",
    expectation: "赎回成功；B 的受限状态保持，份额下降，现金增加。",
  },
  {
    principalId: "supervisor-console", title: "监管与审计收口",
    script: "最后展示只追加审计事件、规则决策和异常闭环。监管能验证发生了什么，但不需要看到所有投资者金额和身份明文。",
    expectation: "成功、失败、资格变化和双人复核均有事件；视图只披露必要元数据。",
  },
];

const escapeHtml = (value) => String(value ?? "—")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;");

const pill = (value) => `<span class="pill ${["REVOKED", "RESTRICTED_EXIT", "REQUIRES_REVIEW", "PENDING_APPROVAL", "ATTENTION_REQUIRED", "RECONCILIATION_EXCEPTION", "FROZEN", "EXPIRED", "PAUSED", "REJECTED", "EXCEPTION", "CANCELLED"].includes(value) ? "revoked" : ""}">${escapeHtml(value)}</span>`;
const metric = (name, value, detail = "") => `<article class="metric"><div class="name">${escapeHtml(name)}</div><div class="value">${escapeHtml(value)}</div><div class="detail">${escapeHtml(detail)}</div></article>`;

function table(columns, rows) {
  if (!rows.length) return `<div class="empty">暂无记录</div>`;
  return `<table><thead><tr>${columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map((c) => `<td>${c.render ? c.render(row[c.key], row) : escapeHtml(row[c.key])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

const roleLabels = {
  issuer: "发行人", distributor: "分销机构", credential_issuer: "资格凭证机构",
  fund_administrator: "资产/基金行政", custodian: "托管机构",
  transfer_agent: "法定名册/过户代理", cash_provider: "现金机构",
};

async function catalogRequest(path, { method = "GET", body = null } = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(method === "GET" ? {} : { "x-csrf-token": current.csrfToken }),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`[${data.code ?? response.status}] ${data.error ?? "请求失败"}`);
  return data;
}

function institutionOptions(selected = "") {
  return (catalogState?.institutions ?? [])
    .filter((item) => item.status === "ACTIVE" && item.onboardingStatus === "APPROVED")
    .map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === selected ? "selected" : ""}>${escapeHtml(item.legalName)} · ${escapeHtml(item.jurisdiction)}</option>`)
    .join("");
}

function pendingApproval(items = []) {
  const rounds = [...new Set(items.map((item) => item.round))].sort((a, b) => b - a);
  for (const round of rounds) {
    const records = items.filter((item) => item.round === round);
    const maker = records.find((item) => item.role === "MAKER");
    const checker = records.find((item) => item.role === "CHECKER");
    if (maker && !checker) return maker;
  }
  return null;
}

function institutionGovernanceCard(item, isMaker, isChecker) {
  const pending = pendingApproval(item.reviews);
  const history = item.reviews.length
    ? `${Math.max(...item.reviews.map((review) => review.round))} 轮审批记录`
    : "尚无审批记录";
  const proposal = isMaker && item.onboardingStatus === "DUE_DILIGENCE" && !pending
    ? `<form class="governance-form institution-review-proposal" data-institution-id="${escapeHtml(item.id)}">
        <select name="decision"><option value="APPROVE">建议批准</option><option value="REJECT">建议拒绝</option></select>
        <input name="reason" minlength="3" maxlength="1000" placeholder="经办理由" required />
        <button type="submit">提交经办意见</button>
      </form>` : "";
  const decision = isChecker && pending
    ? `<form class="governance-form institution-review-decision" data-institution-id="${escapeHtml(item.id)}">
        <select name="decision"><option value="APPROVE">批准经办意见</option><option value="REJECT">退回重审</option></select>
        <input name="reason" minlength="3" maxlength="1000" placeholder="独立复核理由" required />
        <button type="submit">完成独立复核</button>
      </form>` : "";
  return `<article class="catalog-product">
    <div class="catalog-product-head"><div><strong>${escapeHtml(item.legalName)}</strong><br/><small>${escapeHtml(item.id)} · ${escapeHtml(item.jurisdiction)} · ${escapeHtml(history)}</small></div>${pill(item.onboardingStatus)}</div>
    ${pending ? `<div class="catalog-roles"><span class="catalog-role pending">待复核：第 ${escapeHtml(pending.round)} 轮 · ${escapeHtml(pending.decision)} · ${escapeHtml(pending.actorRef)}</span></div>` : ""}
    ${proposal}${decision}
  </article>`;
}

function evidenceForm(product, requirement) {
  const sourceInstitutionId = product.roles[requirement.responsibleRole];
  if (!sourceInstitutionId) return "";
  return `<details><summary>登记 ${escapeHtml(requirement.code)} 的哈希证据</summary>
    <form class="governance-form evidence activation-evidence" data-product-id="${escapeHtml(product.id)}">
      <input type="hidden" name="requirementCode" value="${escapeHtml(requirement.code)}" />
      <input type="hidden" name="sourceInstitutionId" value="${escapeHtml(sourceInstitutionId)}" />
      <input name="id" pattern="[a-z0-9][a-z0-9-]{2,99}" placeholder="证据 ID" required />
      <input type="hidden" name="envelopeVersion" value="rwa.product-activation-evidence.v1" />
      <input type="hidden" name="signatureAlgorithm" value="Ed25519" />
      <input name="keyId" maxlength="128" value="primary-v1" placeholder="机构签名密钥 ID" required />
      <input name="schemaVersion" maxlength="40" value="1.0" placeholder="Schema 版本" required />
      <input class="wide" name="contentHash" pattern="[0-9a-f]{64}" placeholder="文档 SHA-256（64 位小写十六进制）" required />
      <input class="wide" name="signature" minlength="88" placeholder="机构 Ed25519 签名（Base64）" required />
      <input name="issuedAt" type="datetime-local" required />
      <input name="expiresAt" type="datetime-local" required />
      <button type="submit">登记只追加证据</button>
    </form></details>`;
}

function renderCatalog() {
  const { tenant, templates, institutions, products } = catalogState;
  const isIssuer = current.principalId === "issuer-console";
  const isMaker = current.principalId === "operations-console";
  const isChecker = current.principalId === "operations-checker-console";
  const canAudit = isMaker || isChecker || current.principalId === "supervisor-console";
  document.querySelector("#catalog-tenant").textContent = `${tenant.legalName} · ${tenant.id} · 数据区域 ${tenant.dataRegion}`;
  document.querySelector("#catalog-summary").innerHTML = [
    ["租户状态", tenant.status], ["已登记机构", institutions.length], ["产品配置", products.length],
  ].map(([label, value]) => `<div><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`).join("");
  const templateSelect = document.querySelector('#catalog-product-form [name="templateId"]');
  templateSelect.innerHTML = `<option value="" selected disabled>请选择产品模板</option>${templates.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.displayName)} · ${escapeHtml(item.assetClass)} v${escapeHtml(item.version)}</option>`).join("")}`;
  const approvedInstitutions = institutions.filter((item) => item.status === "ACTIVE" && item.onboardingStatus === "APPROVED");
  const preferredIssuer = approvedInstitutions.some((item) => item.id === "demo-issuer") ? "demo-issuer" : "";
  document.querySelector('#catalog-product-form [name="issuerId"]').innerHTML = `${preferredIssuer ? "" : '<option value="" selected disabled>请选择发行机构</option>'}${institutionOptions(preferredIssuer)}`;
  document.querySelector("#catalog-product-form").closest(".catalog-section").hidden = !isIssuer;
  document.querySelector("#catalog-institution-form").closest("details").hidden = !isIssuer;
  document.querySelector("#catalog-audit-export").hidden = !canAudit;
  document.querySelector("#catalog-institutions").innerHTML = institutions.length
    ? institutions.map((item) => institutionGovernanceCard(item, isMaker, isChecker)).join("")
    : `<div class="empty compact">当前租户尚无登记机构</div>`;
  document.querySelector("#catalog-products").innerHTML = products.length ? products.map((product) => {
    const template = templates.find((item) => item.id === product.templateId);
    const required = template?.requiredRoles ?? [];
    const missing = required.filter((role) => !product.roles[role]);
    const requirements = product.evidenceRequirements ?? [];
    const mandatoryComplete = requirements.filter((item) => item.mandatory)
      .every((item) => item.status === "SATISFIED" && new Date(item.expiresAt) > new Date());
    const pendingActivation = pendingApproval(product.activationApprovals);
    return `<article class="catalog-product">
      <div class="catalog-product-head"><div><strong>${escapeHtml(product.name)}</strong><br/><small>${escapeHtml(product.id)} · ${escapeHtml(product.templateId)} · ${escapeHtml(product.jurisdiction)} / ${escapeHtml(product.currency)}</small></div>${pill(product.configurationStatus)}</div>
      <div class="catalog-roles">${required.map((role) => `<span class="catalog-role ${product.roles[role] ? "ready" : ""}">${escapeHtml(roleLabels[role] ?? role)}：${escapeHtml(product.roles[role] ?? "待配置")}</span>`).join("")}</div>
      ${isIssuer && product.status === "DRAFT" && missing.length ? `<form class="role-assignment" data-product-id="${escapeHtml(product.id)}">
        <select name="role">${missing.map((role) => `<option value="${escapeHtml(role)}">${escapeHtml(roleLabels[role] ?? role)}</option>`).join("")}</select>
        <select name="institutionId">${institutionOptions()}</select>
        <button type="submit">分配角色</button>
      </form>` : ""}
      <div class="catalog-evidence">${requirements.map((item) => `<div class="catalog-evidence-row"><span><strong>${escapeHtml(item.code)}</strong><br/>${escapeHtml(roleLabels[item.responsibleRole] ?? item.responsibleRole)} · ${escapeHtml(item.description)}</span><span>${pill(item.status)}${item.expiresAt ? `<br/>到期 ${escapeHtml(new Date(item.expiresAt).toLocaleDateString())}` : ""}</span></div>`).join("")}</div>
      ${isMaker && product.status === "DRAFT" ? requirements.filter((item) => item.status !== "SATISFIED").map((item) => evidenceForm(product, item)).join("") : ""}
      ${isMaker && product.status === "DRAFT" && product.configurationStatus === "READY_FOR_EVIDENCE" && mandatoryComplete && !pendingActivation
        ? `<form class="governance-form activation-proposal" data-product-id="${escapeHtml(product.id)}"><input name="reason" minlength="3" maxlength="1000" placeholder="激活经办理由" required/><button type="submit">提交激活申请</button></form>` : ""}
      ${isChecker && pendingActivation
        ? `<form class="governance-form activation-decision" data-product-id="${escapeHtml(product.id)}"><select name="decision"><option value="APPROVE">批准激活</option><option value="REJECT">退回补充</option></select><input name="reason" minlength="3" maxlength="1000" placeholder="独立复核理由" required/><button type="submit">完成激活复核</button></form>` : ""}
    </article>`;
  }).join("") : `<div class="empty compact">当前租户尚无产品配置</div>`;
}

async function loadCatalog() {
  const data = await catalogRequest("/api/catalog");
  catalogState = data.catalog;
  renderCatalog();
}

async function openCatalog() {
  const allowed = new Set(["issuer-console", "operations-console", "operations-checker-console", "supervisor-console"]);
  if (!allowed.has(current.principalId)) await switchPrincipal("issuer-console");
  catalogPanel.hidden = false;
  catalogResult.className = "result muted";
  catalogResult.textContent = "正在读取受租户约束的产品目录…";
  await loadCatalog();
  catalogResult.textContent = "配置操作会记录只追加审计事件。";
}

function renderIssuer(data) {
  metrics.innerHTML = [
    metric("账本份额", data.reconciliation.confidentialAssetUnits, "机密资产账"),
    metric("法定份额", data.reconciliation.legalRegisterUnits, "转让代理名册"),
    metric("资产/名册", data.reconciliation.assetRegisterMatched ? "MATCHED" : "CONFLICT", "两套份额记录"),
    metric("现金确认", `${data.reconciliation.cashConfirmedCount}/${data.reconciliation.cashExpectedCount}`, "模拟日志，非银行回单"),
  ].join("");
  const assignments = Object.entries(data.roleAssignments).map(([role, institution]) => ({ role, institution }));
  content.innerHTML = `<div class="section-title">责任机构</div>${table([
    { key: "role", label: "角色" }, { key: "institution", label: "模拟机构" },
  ], assignments)}<div class="section-title">资产证据</div>${evidenceTable(data.evidence)}<div class="privacy-note">发行人看到供应量、责任机构和规则执行结果，但本视图不展示单个投资者余额。</div>`;
}

function evidenceTable(rows) {
  return table([
    { key: "id", label: "证据" },
    { key: "dataType", label: "类型" },
    { key: "sourceInstitutionId", label: "签署来源" },
    { key: "trustTier", label: "等级", render: (v) => `<span class="pill info">TIER ${escapeHtml(v)}</span>` },
    { key: "expiresAt", label: "到期" },
    { key: "status", label: "状态", render: pill },
  ], rows);
}

function renderDistributor(data) {
  const active = data.credentials.filter((x) => x.status === "ACTIVE").length;
  metrics.innerHTML = [metric("有效凭证", active), metric("受限/冻结", data.credentials.length - active), metric("产品范围", "1", "基金级资格"), metric("完整PII共享", "0", "最小披露")].join("");
  content.innerHTML = `<div class="section-title">产品级资格凭证</div>${table([
    { key: "id", label: "凭证" }, { key: "subjectId", label: "主体假名" },
    { key: "investorClass", label: "类别" }, { key: "jurisdiction", label: "地区" },
    { key: "maxUnits", label: "上限" }, { key: "validUntil", label: "有效期" },
    { key: "status", label: "状态", render: pill },
    { key: "restriction", label: "允许路径", render: (v) => v?.status === "RESTRICTED_EXIT" ? "仅受控退出" : "标准交易" },
  ], data.credentials)}<div class="privacy-note">此处展示的是模拟产品属性，不保存证件、住址或银行流水。资格受限后禁止新增持仓，但允许赎回退出，避免资产被永久锁死。</div>`;
}

function renderInvestor(data) {
  metrics.innerHTML = [metric("私密持仓", data.positionUnits, "基金份额"), metric("模拟现金", formatMoney(data.cashBalance), data.product.rules.currency), metric("资格状态", data.credential?.status ?? "NONE"), metric("我的交易", data.ownTransactions.length)].join("");
  content.innerHTML = `<div class="section-title">我的交易</div>${table([
    { key: "id", label: "交易" }, { key: "type", label: "类型" }, { key: "units", label: "份额" },
    { key: "cashAmount", label: "现金", render: (v) => formatMoney(v) }, { key: "fee", label: "费用", render: (v) => formatMoney(v) },
    { key: "state", label: "状态", render: pill }, { key: "settlementMode", label: "处理路径" }, { key: "settledAt", label: "结算时间" },
  ], data.ownTransactions)}<div class="privacy-note">投资者能看到自己的金额和持仓；其他投资者和公共回执看不到这些字段。</div>`;
}

function renderBroker(data) {
  metrics.innerHTML = [metric("成交记录", data.transactions.length), metric("允许偏离", `${data.product.rules.maxPriceDeviationBps} bps`, "相对当前NAV"), metric("结算模式", "DvP", "Sandbox cash"), metric("公开订单簿", "关闭", "只录入已协商成交")].join("");
  content.innerHTML = `${renderZkWorkspace(data)}<div class="section-title">已录入成交</div>${table([
    { key: "id", label: "交易" }, { key: "type", label: "类型" }, { key: "sellerId", label: "卖方" },
    { key: "buyerId", label: "买方" }, { key: "units", label: "份额" }, { key: "pricePerUnit", label: "单价", render: (v) => v ? formatMoney(v) : "—" },
    { key: "fee", label: "费用", render: (v) => formatMoney(v) }, { key: "state", label: "状态", render: pill },
    { key: "settlementRail", label: "结算轨道" }, { key: "finalityStatus", label: "隐私终局", render: (v) => v ? pill(v) : "—" },
    { key: "navEvidenceId", label: "NAV证据" }, { key: "ruleVersion", label: "规则版本", render: (v) => `v${escapeHtml(v)}` },
    { key: "policySnapshotHash", label: "策略快照", render: (v) => v ? `<code>${escapeHtml(v.slice(0, 12))}…</code>` : "—" },
  ], data.transactions)}<div class="section-title">最近一笔结算状态机</div>${renderLifecycle(data.transactions.at(-1)?.lifecycle ?? [])}<div class="privacy-note">平台不提供公开撮合；经纪视图仅用于模拟持牌机构录入已协商成交。</div>`;
}

function renderOperations(data) {
  const openExceptions = data.exceptions.filter((item) => !item.status.startsWith("RESOLVED_")).length;
  metrics.innerHTML = [metric("资产/名册", data.reconciliation.assetRegisterMatched ? "MATCHED" : "CONFLICT", `${data.reconciliation.confidentialAssetUnits}/${data.reconciliation.legalRegisterUnits}`), metric("现金确认", `${data.reconciliation.cashConfirmedCount}/${data.reconciliation.cashExpectedCount}`, "模拟日志，非银行回单"), metric("待处理异常", openExceptions), metric("整体控制", data.reconciliation.overallStatus)].join("");
  content.innerHTML = `${renderZkWorkspace(data)}<div class="section-title">异常处理队列</div>${table([
    { key: "id", label: "案件" }, { key: "transactionId", label: "原交易" }, { key: "failureStage", label: "失败阶段" },
    { key: "reasonCode", label: "原因" }, { key: "status", label: "状态", render: pill }, { key: "proposedDecision", label: "拟议处置" },
    { key: "proposedBy", label: "经办人" }, { key: "checkedBy", label: "复核人" }, { key: "replacementTransactionId", label: "替代交易" },
  ], data.exceptions)}<div class="section-title">NAV、托管和名册证据</div>${evidenceTable(data.evidence)}<div class="section-title">结算摘要</div>${table([
    { key: "id", label: "交易" }, { key: "type", label: "类型" }, { key: "state", label: "状态", render: pill }, { key: "settlementRail", label: "结算轨道" },
    { key: "finalityStatus", label: "隐私终局", render: (v) => v ? pill(v) : "—" }, { key: "settlementMode", label: "处理路径" },
    { key: "evidencePackageHash", label: "证据包", render: (v) => v ? `<code>${escapeHtml(v.slice(0, 12))}…</code>` : "—" }, { key: "settledAt", label: "时间" },
  ], data.transactionSummary)}<div class="privacy-note">失败交易不更新资产账或法定名册；现金预留会释放。人工复核后以新的替代交易重试，保留完整关联链。</div>`;
}

function renderSupervisor(data) {
  metrics.innerHTML = [metric("审计事件", data.auditEvents.length), metric("披露模式", "METADATA", "Sandbox only"), metric("整体控制", data.reconciliation.overallStatus, "含模拟现金确认"), metric("监管万能钥匙", "不存在", "未来采用受控授权")].join("");
  content.innerHTML = `<div class="section-title">只追加审计事件</div>${table([
    { key: "sequence", label: "序号" }, { key: "type", label: "事件" }, { key: "at", label: "时间" },
    { key: "productId", label: "产品" }, { key: "transactionId", label: "交易" }, { key: "state", label: "状态", render: (v) => v ? pill(v) : "—" },
    { key: "reasonCode", label: "拒绝原因" },
  ], data.auditEvents.slice().reverse())}<div class="privacy-note">成功和拒绝的决策都进入只追加审计流；当前只显示元数据，尚未实现门限监管解密。</div>`;
}

function renderLifecycle(rows) {
  if (!rows.length) return `<div class="empty">暂无状态记录</div>`;
  return `<div class="lifecycle">${rows.map((item, index) => `<div class="lifecycle-step"><span>${index + 1}</span><strong>${escapeHtml(item.state)}</strong><small>${escapeHtml(item.at)}</small></div>`).join("")}</div>`;
}

function confidentialTransactions(data) {
  const rows = data.transactions ?? data.transactionSummary ?? [];
  return rows.filter((row) => row.settlementRail === "CONFIDENTIAL_NOTE");
}

function zkStage(row) {
  if (row.state === "SETTLED" && row.finalityStatus === "SETTLED") return 5;
  if (row.state === "ROOT_PENDING") return 4;
  if (row.state === "PROOF_PENDING" && row.proverJobState) return 3;
  if (row.state === "PROOF_PENDING") return 2;
  return 1;
}

function renderZkPipeline(row) {
  const stages = ["交易准备", "公开输入授权", "Groth16 验证", "权威根待确认", "隐私账本终局"];
  const active = zkStage(row);
  const prover = row.proverJobState
    ? `<div class="zk-boundary">隔离 Prover：${escapeHtml(row.proverJobState)}${row.proverErrorCode ? ` · ${escapeHtml(row.proverErrorCode)}` : ""}</div>`
    : "";
  return `<article class="zk-case"><div class="zk-case-head"><div><strong>${escapeHtml(row.id)}</strong><small>${escapeHtml(row.finalityDomain ?? "CONFIDENTIAL_NOTE")}</small></div>${pill(row.state)}</div><div class="zk-pipeline">${stages.map((label, index) => `<div class="zk-stage ${index + 1 < active ? "done" : index + 1 === active ? "current" : ""}"><span>${index + 1}</span><small>${label}</small></div>`).join("")}</div>${prover}<div class="zk-boundary">法定名册：${row.legalRegisterApplied ? "已确认" : "等待外部过户代理"}</div></article>`;
}

function renderZkWorkspace(data) {
  const enabled = data.runtime?.confidentialTransferApi;
  const rows = confidentialTransactions(data);
  const status = enabled
    ? `<span class="pill">GROTH16 VERIFIED</span>`
    : `<span class="pill revoked">当前运行未启用</span>`;
  let controls = "";
  if (enabled && current.role === "broker") {
    const proofControls = data.runtime?.isolatedProver
      ? `<details><summary>3. 请求隔离 Prover 生成证明</summary><form data-zk-form="prover-request" class="zk-form stacked">
          <label>交易 ID<input name="transactionId" required /></label>
          <label>Witness 安全引用<input name="witnessReference" placeholder="vault://rwa/witness/…" required /></label>
          <div class="privacy-note">这里只提交 Vault/HSM/KMS 中的不透明引用；浏览器、数据库和日志均不得接收原始 witness。</div>
          <button type="submit">进入持久化证明队列</button>
        </form></details>
        <details><summary>查询 Prover 任务状态</summary><form data-zk-form="prover-status" class="zk-form stacked">
          <label>交易 ID<input name="transactionId" required /></label>
          <button type="submit">刷新任务状态</button>
        </form></details>`
      : `<details><summary>3. 提交机构证明包</summary><form data-zk-form="settle" class="zk-form stacked">
          <label>交易 ID<input name="transactionId" required /></label>
          <label>Proof JSON<textarea name="proof" rows="7" required></textarea></label>
          <label>13 项 Public Signals 数组<textarea name="publicSignals" rows="5" required></textarea></label>
          <button type="submit">执行密码学验证</button>
        </form></details>`;
    controls = `<div class="zk-controls">
      <details open><summary>1. 准备隐私转让</summary><form data-zk-form="prepare" class="zk-form">
        <label>产品 ID<input name="productId" value="${escapeHtml(data.product.id)}" required /></label>
        <label>费用（整数）<input name="fee" value="0" inputmode="numeric" required /></label>
        <label>付款投资者<input name="senderInvestorId" value="investor-a" required /></label>
        <label>付款人资格凭证<input name="senderCredentialId" value="credential-investor-a" required /></label>
        <label>收款投资者<input name="recipientInvestorId" value="investor-b" required /></label>
        <label>收款人资格凭证<input name="recipientCredentialId" value="credential-investor-b" required /></label>
        <label>收款人票据公钥（须由分销机构预先登记）<input name="recipient" inputmode="numeric" required /></label>
        <label>中继方字段元素<input name="relayer" value="0" inputmode="numeric" required /></label>
        <button type="submit">冻结执行指令</button>
      </form></details>
      <details><summary>2. 授权 13 项公开输入</summary><form data-zk-form="authorize" class="zk-form stacked">
        <label>交易 ID<input name="transactionId" required /></label>
        <label>公开输入 JSON<textarea name="publicInputs" rows="8" placeholder='{"merkleRoot":"…","contextId":"…"}' required></textarea></label>
        <button type="submit">写入不可变授权</button>
      </form></details>
      ${proofControls}
    </div>`;
  }
  if (enabled && current.role === "operations" && current.principalId === "operations-console") {
    controls = `<div class="zk-controls"><details open><summary>4. 经办人提交权威终局提案</summary><form data-zk-form="propose" class="zk-form">
      <label>交易 ID<input name="transactionId" required /></label>
      <label>输出 Merkle Root<input name="outputMerkleRoot" inputmode="numeric" required /></label>
      <label>输出树大小<input name="outputTreeSize" type="number" min="2" required /></label>
      <label>根发布引用<input name="rootSourceReference" required /></label>
      <label>外部执行引用<input name="executionReference" required /></label>
      <div class="privacy-note">服务端会用当前隐私票据树和本交易的两个输出重新计算新根；外部发布的根必须与之完全一致。</div>
      <button type="submit">提交待复核提案</button>
    </form></details>
    <details><summary>撤回待复核提案</summary><form data-zk-form="cancel-finality" class="zk-form">
      <label>交易 ID<input name="transactionId" required /></label>
      <label>撤回理由<input name="reason" minlength="3" maxlength="1000" required /></label>
      <button type="submit">撤回提案</button>
    </form></details></div>`;
  }
  if (enabled && current.role === "operations" && current.principalId === "operations-checker-console") {
    controls = `<div class="zk-controls"><details open><summary>5. 独立复核人批准终局</summary><form data-zk-form="approve" class="zk-form stacked">
      <label>交易 ID<input name="transactionId" required /></label>
      <div class="privacy-note">批准前必须在机构系统核验根发布批次和外部执行引用。复核人与经办人由服务端和数据库强制分离。</div>
      <button type="submit">批准并写入隐私账本终局</button>
    </form></details></div>`;
  }
  return `<section class="zk-workspace"><div class="zk-title"><div><p class="label">CONFIDENTIAL SETTLEMENT</p><h4>JoinSplit 隐私结算工作台</h4></div>${status}</div>${rows.length ? rows.map(renderZkPipeline).join("") : `<div class="empty compact">暂无隐私结算交易</div>`}${controls}<div class="privacy-note">证明通过只进入 ROOT_PENDING；权威根及外部执行经双人确认后才进入 CONFIDENTIAL_NOTE_LEDGER。法定名册仍由外部机构确认。</div></section>`;
}

function parseJsonField(form, name) {
  const value = new FormData(form).get(name);
  try { return JSON.parse(String(value)); }
  catch { throw new Error(`${name} 必须是合法 JSON`); }
}

async function zkRequest(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": current.csrfToken },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    const details = data.details ? ` ${JSON.stringify(data.details)}` : "";
    throw new Error(`[${data.code ?? response.status}] ${data.error ?? "请求被拒绝"}${details}`);
  }
  return data.result;
}

async function zkGet(path) {
  const response = await fetch(path);
  const data = await response.json();
  if (!response.ok) throw new Error(`[${data.code ?? response.status}] ${data.error ?? "请求被拒绝"}`);
  return data.result;
}

function bindZkControls() {
  document.querySelectorAll("[data-zk-form]").forEach((form) => form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (performing) return;
    performing = true;
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    result.className = "result muted";
    result.textContent = "正在执行隐私结算安全检查…";
    try {
      const values = Object.fromEntries(new FormData(form));
      let response;
      if (form.dataset.zkForm === "prepare") {
        const suffix = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
        response = await zkRequest("/api/zk/transfers", {
          transactionId: `ui-zk-transfer-${suffix}`, idempotencyKey: `ui-zk-transfer-${suffix}`,
          productId: values.productId, fee: values.fee, recipient: values.recipient, relayer: values.relayer,
          senderInvestorId: values.senderInvestorId, senderCredentialId: values.senderCredentialId,
          recipientInvestorId: values.recipientInvestorId, recipientCredentialId: values.recipientCredentialId,
          expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        });
      } else if (form.dataset.zkForm === "authorize") {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/authorization`, { publicInputs: parseJsonField(form, "publicInputs") });
      } else if (form.dataset.zkForm === "settle") {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/settlement`, { proof: parseJsonField(form, "proof"), publicSignals: parseJsonField(form, "publicSignals") });
      } else if (form.dataset.zkForm === "prover-request") {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/prover-job`, { witnessReference: values.witnessReference });
      } else if (form.dataset.zkForm === "prover-status") {
        response = await zkGet(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/prover-job`);
      } else if (form.dataset.zkForm === "propose") {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/finalization-proposal`, {
          outputMerkleRoot: values.outputMerkleRoot, outputTreeSize: Number(values.outputTreeSize),
          rootSourceReference: values.rootSourceReference, executionReference: values.executionReference,
        });
      } else if (form.dataset.zkForm === "cancel-finality") {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/finalization-cancellation`, { reason: values.reason });
      } else {
        response = await zkRequest(`/api/zk/transfers/${encodeURIComponent(values.transactionId)}/finalization`, {});
      }
      result.className = "result success";
      result.textContent = `成功：${JSON.stringify(response)}`;
      await loadView();
    } catch (error) {
      result.className = "result error";
      result.textContent = `拒绝：${error.message}`;
    } finally {
      performing = false;
      if (submit.isConnected) submit.disabled = false;
    }
  }));
}

function formatMoney(value) {
  if (value === null || value === undefined) return "—";
  return `HK$ ${(Number(value) / 100).toLocaleString("zh-HK", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function renderActions(role, actorId, data) {
  const buttons = [];
  const productActive = data.product.status === "ACTIVE";
  if (role === "issuer") {
    if (data.product.status === "ACTIVE") buttons.push(["pause", "暂停产品", "阻止新增认购、转让和赎回", true]);
    if (data.product.status === "PAUSED") buttons.push(["resume", "恢复产品", "重新允许产品工作流", false]);
  }
  if (role === "distributor" && data.credentials.find((item) => item.subjectId === "investor-b")?.status === "ACTIVE") {
    buttons.push(["revoke-b", "限制投资者 B 资格", "禁止新增持仓，但保留受控退出", true]);
  }
  if (role === "investor" && actorId === "investor-a" && productActive) buttons.push(["subscribe", "投资者 A 认购 100 份", "按当前NAV锁定模拟现金", false]);
  if (role === "investor" && actorId === "investor-b" && Number(data.positionUnits) >= 5 && productActive) {
    buttons.push(["redeem", "投资者 B 赎回 5 份", "ACTIVE 或 RESTRICTED_EXIT 均可执行", false]);
  }
  if (role === "broker" && productActive) buttons.push(["transfer", "A 向 B 转让 25 份", "验证买方资格、NAV和模拟DvP", false]);
  if (role === "operations") {
    if (productActive) buttons.push(["simulate-register-failure", "模拟名册确认超时", "创建异常，但不改变资产或现金余额", true]);
    if (data.exceptions.some((item) => item.status === "OPEN")) {
      buttons.push(["propose-exception-retry", "经办人提交重试方案", "只提交方案，不执行资金或份额变化", false]);
    }
    if (productActive && data.exceptions.some((item) => item.status === "PENDING_APPROVAL")) {
      buttons.push(["approve-exception-retry", "复核人批准并重新发起", "必须与经办人不同；重新执行全部检查", false]);
    }
  }
  const permittedButtons = buttons.filter(([action]) => data.runtime.capabilities[action]);
  if (!permittedButtons.length) actions.innerHTML = `<div class="muted">此角色在当前数据模式下为只读视图。</div>`;
  else actions.innerHTML = permittedButtons.map(([action, label, note, danger]) => `<button data-action="${action}" class="${danger ? "danger" : ""}">${label}<small>${note}</small></button>`).join("");
  actions.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => perform(button.dataset.action)));
  updateGuideHighlight();
}

async function loadView() {
  const response = await fetch("/api/view", { cache: "no-store" });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  document.querySelector("#product-name").textContent = data.product.name;
  document.querySelector("#product-id").textContent = data.product.id;
  document.querySelector("#jurisdiction").textContent = data.product.jurisdiction;
  document.querySelector("#rule-version").textContent = `RULE v${data.product.ruleVersion}`;
  document.querySelector("#runtime-mode").textContent = data.runtime.storageMode;
  const status = document.querySelector("#product-status");
  status.textContent = data.product.status;
  status.className = `status ${data.product.status === "PAUSED" ? "paused" : ""}`;
  document.querySelector("#view-title").textContent = titles[current.role];
  document.querySelector("#generated-at").textContent = data.generatedAt;
  const resetButton = document.querySelector("#reset");
  resetButton.disabled = current.role !== "issuer" || !data.runtime.capabilities.reset;
  resetButton.title = data.runtime.capabilities.reset
    ? (current.role === "issuer" ? "重置 Sandbox 状态" : "仅发行人演示身份可重置")
    : "当前数据模式禁止重置";
  ({ issuer: renderIssuer, distributor: renderDistributor, investor: renderInvestor, broker: renderBroker, operations: renderOperations, supervisor: renderSupervisor })[current.role](data);
  renderActions(current.role, current.actorId, data);
  bindZkControls();
}

async function establishSession(principalId) {
  const response = await fetch("/api/sandbox/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ principalId }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  current = {
    principalId,
    role: data.identity.role,
    actorId: data.identity.actorRef,
    csrfToken: data.csrfToken,
  };
}

async function switchPrincipal(principalId) {
  const button = roleButtons.find((item) => item.dataset.principal === principalId);
  if (!button) throw new Error("演示角色不存在");
  await establishSession(principalId);
  roleButtons.forEach((item) => item.classList.remove("active"));
  button.classList.add("active");
  await loadView();
}

function updateGuideHighlight() {
  actions.querySelectorAll(".guide-target").forEach((button) => button.classList.remove("guide-target"));
  if (!guideActive) return;
  const step = guideSteps[guideIndex];
  if (!step?.action) return;
  const target = actions.querySelector(`[data-action="${step.action}"]`);
  if (target) {
    target.classList.add("guide-target");
    document.querySelector("#guide-action-note").textContent = step.expectedFailure
      ? "请点击右侧高亮按钮；本步应被安全拒绝。"
      : "请点击右侧高亮按钮执行本步，然后讲解结果。";
  } else {
    document.querySelector("#guide-action-note").textContent = "当前状态尚未出现本步按钮，请先完成上一操作，或点击下方重新准备演示数据。";
  }
}

async function showGuideStep(index) {
  guideIndex = Math.max(0, Math.min(index, guideSteps.length - 1));
  guideActive = true;
  guide.hidden = false;
  const step = guideSteps[guideIndex];
  document.querySelector("#guide-step-count").textContent = `步骤 ${guideIndex + 1} / ${guideSteps.length}`;
  document.querySelector("#guide-progress-bar").style.width = `${((guideIndex + 1) / guideSteps.length) * 100}%`;
  document.querySelector("#guide-title").textContent = step.title;
  document.querySelector("#guide-script").textContent = step.script;
  document.querySelector("#guide-expectation").textContent = step.expectation;
  document.querySelector("#guide-action-note").textContent = step.action ? "正在切换到本步角色…" : "本步只需讲解页面，无需执行操作。";
  document.querySelector("#guide-prev").disabled = guideIndex === 0;
  document.querySelector("#guide-next").textContent = guideIndex === guideSteps.length - 1 ? "完成演示" : "下一步";
  await switchPrincipal(step.principalId);
  updateGuideHighlight();
}

function guideActionOutcome(action, ok, data) {
  if (!guideActive) return;
  const step = guideSteps[guideIndex];
  if (step?.action !== action) return;
  const expected = step.expectedFailure ? !ok : ok;
  document.querySelector("#guide-action-note").textContent = expected
    ? (step.expectedFailure ? `符合预期：请求被安全拒绝 [${data.code ?? "REJECTED"}]。讲解后点击下一步。` : "本步执行成功。讲解结果后点击下一步。")
    : (step.expectedFailure ? "本步本应被拒绝但却成功，请停止演示并检查状态。" : `本步未成功 [${data.code ?? "REQUEST_FAILED"}]，请检查结果后重试。`);
}

async function perform(action) {
  if (performing) return;
  performing = true;
  actions.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  result.className = "result muted";
  result.textContent = "正在执行状态检查…";
  try {
    const response = await fetch("/api/action", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": current.csrfToken },
      body: JSON.stringify({ action }),
    });
    const data = await response.json();
    result.className = `result ${response.ok ? "success" : "error"}`;
    result.textContent = response.ok ? `成功：${JSON.stringify(data.result)}` : `拒绝 [${data.code}]：${data.error}`;
    await loadView();
    guideActionOutcome(action, response.ok, data);
  } catch (error) {
    result.className = "result error";
    result.textContent = `请求失败：${error.message}`;
    guideActionOutcome(action, false, { code: "NETWORK_OR_RUNTIME_ERROR" });
  } finally {
    performing = false;
    actions.querySelectorAll("button").forEach((button) => { button.disabled = false; });
  }
}

roleButtons.forEach((button) => button.addEventListener("click", async () => {
  try {
    await switchPrincipal(button.dataset.principal);
  } catch (error) {
    result.className = "result error";
    result.textContent = `身份切换失败：${error.message}`;
  }
}));

async function prepareDemoData() {
  if (performing) return;
  performing = true;
  result.className = "result muted";
  result.textContent = "正在原子重建合成演示数据…";
  await switchPrincipal("issuer-console");
  const response = await fetch("/api/reset", {
    method: "POST",
    headers: { "x-csrf-token": current.csrfToken },
  });
  const data = await response.json();
  if (!response.ok) {
    result.className = "result error";
    result.textContent = `拒绝 [${data.code}]：${data.error}`;
    performing = false;
    return;
  }
  result.className = "result success";
  result.textContent = `演示数据已准备：产品 ACTIVE、凭证 ACTIVE、NAV 有效至 ${data.result.navExpiresAt}。`;
  await loadView();
  performing = false;
  await showGuideStep(0);
}

document.querySelector("#reset").addEventListener("click", () => prepareDemoData().catch((error) => {
  performing = false;
  result.className = "result error";
  result.textContent = `准备失败：${error.message}`;
}));

document.querySelector("#guide-start").addEventListener("click", () => showGuideStep(0).catch((error) => {
  result.className = "result error";
  result.textContent = `向导启动失败：${error.message}`;
}));
document.querySelector("#guide-close").addEventListener("click", () => {
  guideActive = false;
  guide.hidden = true;
  updateGuideHighlight();
});
document.querySelector("#guide-prev").addEventListener("click", () => showGuideStep(guideIndex - 1));
document.querySelector("#guide-next").addEventListener("click", () => {
  if (guideIndex === guideSteps.length - 1) {
    guideActive = false;
    guide.hidden = true;
    updateGuideHighlight();
    result.className = "result success";
    result.textContent = "演示向导已完成。现在请询问合作方：哪一步与真实流程不一致，谁拥有否决权？";
    return;
  }
  showGuideStep(guideIndex + 1).catch((error) => {
    result.className = "result error";
    result.textContent = `向导切换失败：${error.message}`;
  });
});
document.querySelector("#guide-prepare").addEventListener("click", () => prepareDemoData().catch((error) => {
  performing = false;
  result.className = "result error";
  result.textContent = `准备失败：${error.message}`;
}));

document.querySelector("#catalog-open").addEventListener("click", () => openCatalog().catch((error) => {
  catalogPanel.hidden = false;
  catalogResult.className = "result error";
  catalogResult.textContent = `配置中心加载失败：${error.message}`;
}));
document.querySelector("#catalog-close").addEventListener("click", () => { catalogPanel.hidden = true; });

document.querySelector("#catalog-product-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  catalogResult.className = "result muted";
  catalogResult.textContent = "正在创建受租户约束的产品草案…";
  try {
    const data = await catalogRequest("/api/catalog/products", { method: "POST", body: values });
    catalogResult.className = "result success";
    catalogResult.textContent = `已创建 ${data.product.id}；状态为 DRAFT，尚不能交易。请继续分配机构角色。`;
    form.reset();
    await loadCatalog();
  } catch (error) {
    catalogResult.className = "result error";
    catalogResult.textContent = `创建失败：${error.message}`;
  }
});

document.querySelector("#catalog-institution-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  if (!values.externalReference) delete values.externalReference;
  catalogResult.className = "result muted";
  catalogResult.textContent = "正在登记机构公钥与尽调状态…";
  try {
    const data = await catalogRequest("/api/catalog/institutions", { method: "POST", body: values });
    catalogResult.className = "result success";
    catalogResult.textContent = `机构 ${data.institution.id} 已登记为 DUE_DILIGENCE；批准前不能承担产品角色。`;
    form.reset();
    await loadCatalog();
  } catch (error) {
    catalogResult.className = "result error";
    catalogResult.textContent = `登记失败：${error.message}`;
  }
});

document.querySelector("#catalog-institutions").addEventListener("submit", async (event) => {
  const form = event.target.closest("form");
  if (!form) return;
  event.preventDefault();
  const body = Object.fromEntries(new FormData(form));
  const proposal = form.classList.contains("institution-review-proposal");
  const path = `/api/catalog/institutions/${encodeURIComponent(form.dataset.institutionId)}/${proposal ? "review-proposal" : "review-decision"}`;
  catalogResult.className = "result muted";
  catalogResult.textContent = proposal ? "正在提交机构尽调经办意见…" : "正在执行独立机构复核…";
  try {
    const data = await catalogRequest(path, { method: "POST", body });
    catalogResult.className = "result success";
    catalogResult.textContent = `机构审批已记录；当前状态：${data.review.state}，轮次：${data.review.round}。`;
    await loadCatalog();
  } catch (error) {
    catalogResult.className = "result error";
    catalogResult.textContent = `机构审批失败：${error.message}`;
  }
});

document.querySelector("#catalog-products").addEventListener("submit", async (event) => {
  const form = event.target.closest("form");
  if (!form) return;
  event.preventDefault();
  const values = Object.fromEntries(new FormData(form));
  const productId = encodeURIComponent(form.dataset.productId);
  let path;
  let waiting;
  if (form.classList.contains("role-assignment")) {
    path = `/api/catalog/products/${productId}/roles`;
    waiting = "正在校验机构租户、尽调状态与模板角色…";
  } else if (form.classList.contains("activation-evidence")) {
    path = `/api/catalog/products/${productId}/activation-evidence`;
    waiting = "正在校验证据责任机构、规范载荷、机构公钥签名、密钥状态和有效期…";
  } else if (form.classList.contains("activation-proposal")) {
    path = `/api/catalog/products/${productId}/activation-proposal`;
    waiting = "正在执行角色与强制证据完整性检查…";
  } else if (form.classList.contains("activation-decision")) {
    path = `/api/catalog/products/${productId}/activation-decision`;
    waiting = "正在执行独立激活复核…";
  } else return;
  catalogResult.className = "result muted";
  catalogResult.textContent = waiting;
  try {
    const data = await catalogRequest(path, { method: "POST", body: values });
    catalogResult.className = "result success";
    const outcome = data.assignment?.configurationStatus
      ?? data.evidence?.state ?? data.activation?.state ?? "RECORDED";
    catalogResult.textContent = `治理操作已原子记录；当前结果：${outcome}。`;
    await loadCatalog();
  } catch (error) {
    catalogResult.className = "result error";
    catalogResult.textContent = `治理操作失败：${error.message}`;
  }
});

document.querySelector("#catalog-audit-export").addEventListener("click", async () => {
  catalogResult.className = "result muted";
  catalogResult.textContent = "正在生成租户隔离、带哈希的审计导出…";
  try {
    const data = await catalogRequest("/api/catalog/audit-export");
    const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `rwa-catalog-audit-${data.report.tenant.id}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    catalogResult.className = "result success";
    catalogResult.textContent = `审计导出完成；SHA-256 语义哈希：${data.report.exportHash}。`;
  } catch (error) {
    catalogResult.className = "result error";
    catalogResult.textContent = `审计导出失败：${error.message}`;
  }
});

establishSession(current.principalId).then(loadView).catch((error) => {
  content.innerHTML = `<div class="empty">加载失败：${escapeHtml(error.message)}</div>`;
});
