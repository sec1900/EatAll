/* EatAll dashboard 前端：5 页签 + 3s 轮询 */
"use strict";

const state = {
  tab: "overview",
  sess: { offset: 0, limit: 50, src: "", proto: "", kw: "" },
  poc: { offset: 0, limit: 200, search: "", severity: "" },
  ports: { offset: 0, limit: 100, search: "" },
  flow: { offset: 0, limit: 50, search: "" },
  scanFilter: "",
  detail: { mode: "parsed" },
};

const $ = (sel) => document.querySelector(sel);

/* 过滤输入焦点保护：轮询重渲染时保留正在输入的值，避免打字被打断 */
function keepTyping(ids) {
  const kept = {};
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el && el === document.activeElement) kept[id] = el.value;
  }
  return kept;
}
function restoreTyping(ids, kept) {
  for (const id of ids) {
    if (kept[id] !== undefined) {
      const el = document.getElementById(id);
      el.value = kept[id];
      el.focus();  // 恢复焦点 + 光标到末尾，跨轮询持续打字
      const len = el.value.length;
      try { el.setSelectionRange(len, len); } catch (e) { /* 非输入类元素忽略 */ }
    }
  }
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (ms) => (ms ? new Date(ms).toLocaleString("zh-CN", { hour12: false }) : "-");
const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : (n ?? 0) + " B");

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}

const sevBadge = (s) => `<span class="badge ${esc(s)}">${esc(s)}</span>`;

const EXPLOIT_LABELS = {
  rce: "🔥 RCE", sql_injection: "SQLi", deserialization: "反序列化",
  expression: "表达式", traversal: "遍历", xss: "XSS", ssrf: "SSRF",
  brute: "弱口令", obfuscation: "混淆", unknown: "❓可疑", probe: "探测",
};
function exploitBadge(t) {
  const cls = { rce: "critical", deserialization: "critical", expression: "critical",
    unknown: "high", sql_injection: "high", ssrf: "high", traversal: "high",
    xss: "high", brute: "high", obfuscation: "medium", probe: "info" }[t] || "info";
  return `<span class="badge ${cls}">${EXPLOIT_LABELS[t] || t}</span>`;
}

/* ---------- 总览 ---------- */
async function renderOverview() {
  const d = await api("/api/overview");
  // 实时吸收面板（独立 DOM，避免整体重渲染）
  renderAbsorb();
  const protoTotal = d.protocols.reduce((a, p) => a + p.n, 0) || 1;
  const colors = ["#4cc2ff", "#3ecf8e", "#ffd166", "#ff6b6b", "#b48cff", "#ff9d5c", "#7fd4c1"];
  $("#view").innerHTML = `
    <div id="absorb-panel"></div>
    <div class="cards">
      <div class="card"><div class="num">${d.session_total}</div><div class="lbl">会话总数</div></div>
      <div class="card"><div class="num">${d.session_today}</div><div class="lbl">今日会话（24h）</div></div>
      <div class="card"><div class="num">${d.flow_count}</div><div class="lbl">扫描器指纹</div></div>
      <div class="card"><div class="num">${d.scan_count}</div><div class="lbl">扫描事件</div></div>
      <div class="card"><div class="num">${d.poc_count}</div><div class="lbl">吸收的 POC</div><div class="extra">库版本 ${esc(d.lib_hash || "-")}</div></div>
    </div>
    <div class="panel"><h3>最近活动</h3>
      <table><thead><tr><th>时间</th><th>来源 IP</th><th>端口</th><th>协议</th><th>Banner</th><th>解析</th><th>字节 收/发</th><th>关闭原因</th></tr></thead>
      <tbody>${d.recent.map((s) => `
        <tr class="clickable" onclick="openSession('${esc(s.session_id)}')">
          <td>${fmtTime(s.ts_start)}</td><td class="mono">${esc(s.src_ip)}:${s.src_port}</td>
          <td>${s.dst_port}</td><td>${esc(s.proto)}</td>
          <td class="mono" title="${esc(s.banner || "")}">${esc((s.banner || "-").slice(0, 40))}</td>
          <td><span class="badge ${esc(s.parse_status)}">${esc(s.parse_status)}</span></td>
          <td>${fmtSize(s.client_len)} / ${fmtSize(s.server_len)}</td><td class="dim">${esc(s.close_reason)}</td>
        </tr>`).join("") || `<tr><td colspan="8" class="empty">暂无捕获——等一个漏扫来扫你 🍽️</td></tr>`}</tbody></table>
    </div>
    <div class="panel"><div class="row2">
      <div><h3>协议分布</h3>
        <div class="bar">${d.protocols.map((p, i) => `<div style="width:${(p.n / protoTotal * 100).toFixed(1)}%;background:${colors[i % colors.length]}" title="${esc(p.proto)}: ${p.n}"></div>`).join("")}</div>
        <div class="legend">${d.protocols.map((p, i) => `<span><i style="background:${colors[i % colors.length]}"></i>${esc(p.proto)} (${p.n})</span>`).join("")}</div>
      </div>
      <div><h3>来源 IP TOP</h3>
        <table><thead><tr><th>IP</th><th>会话数</th></tr></thead>
        <tbody>${d.top_srcs.map((s) => `<tr><td class="mono">${esc(s.src_ip)}</td><td>${s.n}</td></tr>`).join("") || `<tr><td colspan="2" class="empty">-</td></tr>`}</tbody></table>
      </div>
    </div></div>`;
}

/* ---------- 实时吸收面板（被扫描 → POC 吸收流） ---------- */
async function renderAbsorb() {
  const a = await api("/api/absorb");
  const wrap = $("#absorb-panel");
  if (!wrap) return;
  const activeScan = a.active_scan ? `${esc(a.active_scan.src_ip)} · ${a.active_scan.conn_count} 连接 · ${fmtTime(a.active_scan.ts_start)}` : "暂无";
  const recentHtml = a.recent_pocs.length ? a.recent_pocs.map((p) => `
    <tr><td>${exploitBadge(p.exploit_type)}</td>
    <td>${sevBadge(p.severity)}</td>
    <td class="mono" style="font-size:11px">${esc(p.file.slice(0, 50))}</td>
    <td class="dim" style="font-size:11px">${fmtTime(p.last_seen)}</td></tr>`).join("") : '<tr><td colspan="4" class="empty">5 分钟内无新吸收</td></tr>';
  const beingScanned = a.active_sources.length > 0;
  wrap.innerHTML = `
    <div class="panel" style="${beingScanned ? "border-color:var(--red)" : ""}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
        <h3 style="margin:0">${beingScanned ? "🚨 对方正在扫描你" : "🛡️ 等待扫描"}</h3>
        <span class="dim" style="font-size:12px">
          ${beingScanned
            ? `活跃来源: <b style="color:var(--red)">${a.active_sources.map(s => `${esc(s.src_ip)}(${s.conns}连/${Math.round((Date.now() - s.last_ts) / 1000)}s前)`).join(" ")}</b>`
            : "把本机 IP 丢给漏扫，它扫到的东西都会出现在这里"}</span>
      </div>
      <div class="scan-metrics" style="margin-bottom:8px">
        <span>今日新增 POC <b class="n">+${a.new_today}</b></span>
        <span>最近扫描事件: <span class="dim">${activeScan}</span></span>
      </div>
      <div style="font-size:12px;margin-bottom:6px" class="dim">最近吸收的 POC：</div>
      <table style="font-size:12px"><thead><tr><th>类型</th><th>级别</th><th>模板</th><th>时间</th></tr></thead>
      <tbody>${recentHtml}</tbody></table>
    </div>`;
}

/* ---------- 会话 ---------- */
async function renderSessions() {
  const q = new URLSearchParams({ limit: state.sess.limit, offset: state.sess.offset });
  if (state.sess.src) q.set("src", state.sess.src);
  if (state.sess.proto) q.set("proto", state.sess.proto);
  if (state.sess.kw) q.set("q", state.sess.kw);
  const d = await api("/api/sessions?" + q);
  const typing = keepTyping(["f-src", "f-proto", "f-kw"]);
  $("#view").innerHTML = `
    <div class="filters">
      <input id="f-src" placeholder="来源 IP" value="${esc(state.sess.src)}">
      <input id="f-proto" placeholder="协议 (http/ssh/...)" value="${esc(state.sess.proto)}">
      <input id="f-kw" placeholder="关键词 (banner/请求内容)" value="${esc(state.sess.kw)}">
      <button onclick="applySessFilter()">过滤</button>
      <span class="dim" style="align-self:center">共 ${d.total} 条</span>
    </div>
    <div class="panel"><div class="table-scroll"><table><thead><tr><th>时间</th><th>来源</th><th>端口</th><th>协议</th><th>Banner</th><th>解析</th><th>字节</th></tr></thead>
      <tbody>${d.items.map((s) => `
        <tr class="clickable" onclick="openSession('${esc(s.session_id)}')">
          <td>${fmtTime(s.ts_start)}</td><td class="mono">${esc(s.src_ip)}:${s.src_port}</td>
          <td>${s.dst_port}</td><td>${esc(s.proto)}</td>
          <td class="mono" title="${esc(s.banner || "")}">${esc((s.banner || "-").slice(0, 40))}</td>
          <td><span class="badge ${esc(s.parse_status)}">${esc(s.parse_status)}</span></td>
          <td>${fmtSize(s.client_len)} / ${fmtSize(s.server_len)}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">无会话</td></tr>`}</tbody></table></div>
      <div class="pager">
        <button onclick="pageSess(-1)" ${state.sess.offset === 0 ? "disabled" : ""}>上一页</button>
        <span>${state.sess.offset / state.sess.limit + 1} / ${Math.max(1, Math.ceil(d.total / state.sess.limit))}</span>
        <button onclick="pageSess(1)" ${state.sess.offset + state.sess.limit >= d.total ? "disabled" : ""}>下一页</button>
      </div>
    </div>`;
  restoreTyping(["f-src", "f-proto", "f-kw"], typing);
}
function applySessFilter() {
  state.sess.src = $("#f-src").value.trim();
  state.sess.proto = $("#f-proto").value.trim();
  state.sess.kw = $("#f-kw").value.trim();
  state.sess.offset = 0;
  renderSessions();
}
function pageSess(d) { state.sess.offset = Math.max(0, state.sess.offset + d * state.sess.limit); }

/* ---------- 扫描器 ---------- */
async function renderFlows() {
  const q = new URLSearchParams({ limit: state.flow.limit, offset: state.flow.offset });
  if (state.flow.search) q.set("search", state.flow.search);
  const d = await api("/api/flows?" + q);
  const typing = keepTyping(["f-flow-search"]);
  $("#view").innerHTML = `
    <div class="filters">
      <input id="f-flow-search" placeholder="搜索 IP / 工具 / 端口" value="${esc(state.flow.search)}">
      <button onclick="applyFlowFilter()">过滤</button>
      <span class="dim" style="align-self:center">共 ${d.total} 条</span>
    </div>
    <div class="panel"><h3>扫描器指纹（流量聚合）</h3>
    <div class="table-scroll"><table><thead><tr><th>开始</th><th>来源 IP</th><th>工具</th><th>置信度</th><th>端口</th><th>连接数</th><th>行为</th></tr></thead>
    <tbody>${d.items.map((f) => `
      <tr><td>${fmtTime(f.ts_start)}</td><td class="mono">${esc(f.src_ip)}</td>
      <td>${f.tool_guess ? `<span class="tag">${esc(f.tool_guess)}</span>` : '<span class="dim">未知</span>'}</td>
      <td>${f.tool_conf != null ? (f.tool_conf * 100).toFixed(0) + "%" : "-"}</td>
      <td class="mono">${esc((f.ports_hit || []).join(", "))}</td><td>${f.conn_count}</td>
      <td>${(f.behaviors || []).map((b) => `<span class="badge info">${esc(b)}</span>`).join(" ") || "-"}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">暂无指纹</td></tr>`}</tbody></table></div>
    <div class="pager">
      <button onclick="pageFlow(-1)" ${state.flow.offset === 0 ? "disabled" : ""}>上一页</button>
      <span>${state.flow.offset / state.flow.limit + 1} / ${Math.max(1, Math.ceil(d.total / state.flow.limit))}</span>
      <button onclick="pageFlow(1)" ${state.flow.offset + state.flow.limit >= d.total ? "disabled" : ""}>下一页</button>
    </div></div>`;
  restoreTyping(["f-flow-search"], typing);
}
function applyFlowFilter() { state.flow.search = $("#f-flow-search").value.trim(); state.flow.offset = 0; renderFlows(); }
function pageFlow(d) { state.flow.offset = Math.max(0, state.flow.offset + d * state.flow.limit); }

/* ---------- POC 库 ---------- */
async function renderPocs() {
  const q = new URLSearchParams({ limit: state.poc.limit, offset: state.poc.offset });
  if (state.poc.search) q.set("search", state.poc.search);
  if (state.poc.severity) q.set("severity", state.poc.severity);
  if (state.poc.exploit) q.set("exploit", state.poc.exploit);
  const d = await api("/api/pocs?" + q);
  const typing = keepTyping(["p-search", "p-sev", "p-exploit"]);
  $("#view").innerHTML = `
    <div class="filters">
      <input id="p-search" placeholder="搜索路径/名称/tags" value="${esc(state.poc.search)}">
      <select id="p-sev">
        ${["", "critical", "high", "medium", "low", "info", "unknown"].map((s) => `<option value="${s}" ${state.poc.severity === s ? "selected" : ""}>${s || "全部级别"}</option>`).join("")}
      </select>
      <select id="p-exploit">
        ${["", "rce", "sql_injection", "deserialization", "expression", "traversal", "xss", "ssrf", "brute", "obfuscation", "unknown", "probe"].map((s) => `<option value="${s}" ${state.poc.exploit === s ? "selected" : ""}>${({ rce: "🔥 RCE/命令执行", sql_injection: "SQL注入", deserialization: "反序列化", expression: "表达式注入", traversal: "路径遍历", xss: "XSS", ssrf: "SSRF", brute: "弱口令/认证", obfuscation: "混淆/编码", unknown: "❓ 可疑未分类", probe: "探测型" })[s] || "全部利用类型"}</option>`).join("")}
      </select>
      <button onclick="applyPocFilter()">过滤</button>
      <span class="dim" style="align-self:center">共 ${d.total} 条</span>
    </div>
    <div class="panel"><div class="table-scroll"><table><thead><tr><th>模板</th><th>利用类型</th><th>名称</th><th>级别</th><th>状态</th><th>命中</th><th>最后发现</th></tr></thead>
      <tbody>${d.items.map((p) => `
        <tr class="clickable" onclick="openPoc('${esc(p.filename)}')">
          <td class="mono">${esc(p.filename)}</td>
          <td>${exploitBadge(p.exploit_type)}</td>
          <td>${esc((p.name || "").slice(0, 60))}</td>
          <td>${sevBadge(p.severity)}</td><td>${esc(p.status)}</td>
          <td>${p.hit_count}</td><td>${fmtTime(p.last_seen)}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">无 POC</td></tr>`}</tbody></table></div>
      <div class="pager">
        <button onclick="pagePoc(-1)" ${state.poc.offset === 0 ? "disabled" : ""}>上一页</button>
        <span>${state.poc.offset / state.poc.limit + 1} / ${Math.max(1, Math.ceil(d.total / state.poc.limit))}</span>
        <button onclick="pagePoc(1)" ${state.poc.offset + state.poc.limit >= d.total ? "disabled" : ""}>下一页</button>
      </div>
    </div>`;
  restoreTyping(["p-search", "p-sev", "p-exploit"], typing);
}
function applyPocFilter() {
  state.poc.search = $("#p-search").value.trim();
  state.poc.severity = $("#p-sev").value;
  state.poc.exploit = $("#p-exploit").value;
  state.poc.offset = 0;
  renderPocs();
}
function pagePoc(d) { state.poc.offset = Math.max(0, state.poc.offset + d * state.poc.limit); }

/* ---------- 端口矩阵 ---------- */
async function renderPorts() {
  const q = new URLSearchParams({ limit: state.ports.limit, offset: state.ports.offset });
  if (state.ports.search) q.set("search", state.ports.search);
  const d = await api("/api/ports?" + q);
  const typing = keepTyping(["pt-search"]);
  $("#view").innerHTML = `
    <div class="filters">
      <input id="pt-search" placeholder="搜索端口 / 协议 / banner" value="${esc(state.ports.search)}">
      <button onclick="applyPortFilter()">过滤</button>
      <span class="dim" style="align-self:center">共 ${d.total} 条</span>
    </div>
    <div class="panel"><h3>端口探测矩阵（蜜罐监听范围内被扫过的端口）</h3>
      <div class="dim" style="margin-bottom:10px;font-size:12px">说明：漏扫只对判定为"开放"的端口做服务识别与 POC 攻击——本表即对方探测过的端口。closed 端口的 SYN 探测应用层不可见。</div>
      <div class="table-scroll"><table><thead><tr><th>端口</th><th>协议</th><th>Banner（伪装服务）</th><th>会话数</th><th>最近探测</th></tr></thead>
      <tbody>${d.items.map((p) => `
        <tr class="clickable" onclick="openPort(${p.dst_port})">
          <td class="mono">${p.dst_port}</td><td>${esc(p.proto)}</td>
          <td class="mono" title="${esc(p.banner || "")}">${esc((p.banner || "-").slice(0, 50))}</td>
          <td>${p.n}</td><td>${fmtTime(p.last_ts)}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">暂无端口探测</td></tr>`}</tbody></table></div>
      <div class="pager">
        <button onclick="pagePorts(-1)" ${state.ports.offset === 0 ? "disabled" : ""}>上一页</button>
        <span>${state.ports.offset / state.ports.limit + 1} / ${Math.max(1, Math.ceil(d.total / state.ports.limit))}</span>
        <button onclick="pagePorts(1)" ${state.ports.offset + state.ports.limit >= d.total ? "disabled" : ""}>下一页</button>
      </div>
    </div>`;
  restoreTyping(["pt-search"], typing);
}
function applyPortFilter() { state.ports.search = $("#pt-search").value.trim(); state.ports.offset = 0; renderPorts(); }
function pagePorts(d) { state.ports.offset = Math.max(0, state.ports.offset + d * state.ports.limit); }
async function openPort(port) {
  const d = await api("/api/ports/" + port);
  if (!d) return;
  $("#drawer-title").textContent = `端口 ${port} — ${esc(d.proto || "")} ${esc(d.banner || "")}`;
  const sample = (s) => {
    const p = s.parsed || {};
    if (d.proto === "http" || d.proto === "tls-http") return `${p.method || ""} ${p.path || ""}`;
    if (d.proto === "ssh") return p.client_id || "";
    if (d.proto === "mysql") return "user: " + (p.login?.username || "-");
    if (d.proto === "redis") return (p.commands || []).map((c) => c.join(" ")).join(" | ");
    if (d.proto === "ftp") return (p.commands || []).map((c) => c.cmd + " " + (c.arg || "")).join(" | ");
    if (d.proto === "dns") return (p.queries || []).map((q) => q.qname + " " + q.qtype).join(", ");
    if (d.proto === "smb") return "dialects: " + (p.dialects || []).join(",");
    return "";
  };
  $("#drawer-body").innerHTML = `
    <dl class="kv">
      <dt>端口</dt><dd class="mono">${port}</dd>
      <dt>服务</dt><dd>${esc(d.proto)} · <span class="mono">${esc(d.banner || "-")}</span></dd>
      <dt>会话数</dt><dd>${d.session_count}</dd>
    </dl>
    <h3 style="font-size:13px">探测明细（最近 ${d.sessions.length} 条）</h3>
    <table><thead><tr><th>时间</th><th>来源</th><th>探测内容</th><th>状态</th></tr></thead>
      <tbody>${d.sessions.map((s) => `
        <tr class="clickable" onclick="openSession('${esc(s.session_id)}')">
          <td>${fmtTime(s.ts_start)}</td><td class="mono">${esc(s.src_ip)}</td>
          <td class="mono">${esc(sample(s).slice(0, 80))}</td>
          <td><span class="badge ${esc(s.parse_status)}">${esc(s.parse_status)}</span></td></tr>`).join("") || `<tr><td colspan="4" class="empty">无</td></tr>`}</tbody></table>
    ${d.pocs.length ? `<h3 style="font-size:13px;margin-top:12px">该端口触发的 POC 模板（${d.pocs.length}）</h3>
      <table><thead><tr><th>模板</th><th>类型</th><th>级别</th><th>名称</th></tr></thead>
      <tbody>${d.pocs.map((p) => `<tr class="clickable" onclick="openPoc('${esc(p.file)}')">
        <td class="mono">${esc(p.file)}</td><td>${esc(p.type)}</td>
        <td>${sevBadge(p.severity)}</td><td>${esc((p.name || "").slice(0, 60))}</td></tr>`).join("")}</tbody></table>` : ""}
  `;
  showLayer($("#drawer"));
}

/* ---------- 版本（同一扫描器每次扫描 = 一个版本） ---------- */
const isLoopbackIp = (ip) => ip === "::1" || ip === "127.0.0.1" || String(ip || "").startsWith("127.");
async function renderScans() {
  const [sc, lib] = await Promise.all([api("/api/scans"), api("/api/lib")]);
  const q = state.scanFilter.trim().toLowerCase();
  // 版本只统计外部扫描器：回环（127.0.0.1 自测）不参与
  const ext = sc.items.filter((s) => !isLoopbackIp(s.src_ip));
  const items = q
    ? ext.filter((s) => `${s.src_ip} ${s.tool_guess || ""} ${s.new_count} ${s.removed_count}`.toLowerCase().includes(q))
    : ext;
  // 按 (扫描器 IP, 工具) 分组，组内按时间升序编号 V1/V2/...（同一扫描器每次扫描 = 一个版本）
  const groups = new Map();
  for (const s of items) {
    const k = `${s.src_ip}|${s.tool_guess || ""}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(s);
  }
  const rows = [];
  for (const seq of groups.values()) {
    seq.sort((a, b) => a.ts_start - b.ts_start);
    seq.forEach((s, i) => rows.push({ ...s, vnum: i + 1 }));
  }
  rows.sort((a, b) => b.ts_start - a.ts_start);  // 最新在上
  const newest = rows[0];
  const typing = keepTyping(["scan-f"]);
  $("#view").innerHTML = `
    <div class="cards">
      <div class="card"><div class="num">${ext.length}</div><div class="lbl">扫描事件（外部扫描器）</div></div>
      <div class="card"><div class="num">${ext.reduce((a, s) => a + s.new_count, 0)}</div><div class="lbl">累计新增 POC</div></div>
      <div class="card"><div class="num" style="font-size:22px">${newest ? "V" + newest.vnum : "-"}</div><div class="lbl">最新版本</div><div class="extra">${newest ? `${esc(newest.src_ip)} · ${newest.tool_guess ? esc(newest.tool_guess) : "未知工具"} · ${fmtTime(newest.ts_start)}` : "暂无扫描"}</div></div>
    </div>
    <div class="panel"><h3>版本历史 <span class="dim" style="font-size:11px;font-weight:400;margin-left:6px">同一扫描器每次扫描 = 一个版本；漏扫升级后再扫，新增数就是它新学会的 POC</span></h3>
      <div class="filters" style="margin-bottom:10px">
        <input id="scan-f" placeholder="过滤: 来源 IP / 工具 / 新增数" value="${esc(state.scanFilter)}">
        <button onclick="applyScanFilter()">过滤</button>
        <span class="dim" style="align-self:center">${rows.length} / ${ext.length} 个版本</span>
        <span class="dim" style="align-self:center;font-size:11px">当前库 ${esc(lib.items[0]?.lib_hash || "-")} · ${lib.items[0]?.poc_count ?? "-"} 模板</span>
      </div>
      <div class="table-scroll"><table><thead><tr><th>版本</th><th>时间</th><th>扫描器 IP</th><th>工具</th><th>端口</th><th>POC 数</th><th>新增</th><th>移除</th></tr></thead>
      <tbody>${rows.map((s) => `
        <tr class="clickable" onclick="openScanDetail('${esc(s.scan_id)}')">
          <td><span class="badge ${s.new_count > 0 ? "high" : "info"}">V${s.vnum}</span></td>
          <td>${fmtTime(s.ts_start)}</td>
          <td class="mono">${esc(s.src_ip)}</td>
          <td>${s.tool_guess ? esc(s.tool_guess) : '<span class="dim">未知</span>'}</td>
          <td>${(s.ports_hit || []).length}</td>
          <td>${s.poc_count}</td>
          <td><b class="n">+${s.new_count}</b></td>
          <td><b class="r">-${s.removed_count}</b></td></tr>`).join("") || `<tr><td colspan="8" class="empty">${q ? "无匹配事件" : "暂无扫描事件——扫描事件在扫描结束 " + 120 / 60 + " 分钟后自动闭合"}</td></tr>`}</tbody></table></div>
      <div class="dim" style="font-size:11px;margin-top:8px">点击任意一行查看该版本详情（端口探测明细 / 攻击意图 / 网站探测思路 / 利用链）。新增/移除 = 相对同一扫描器的上一版本。</div>
    </div>`;
  restoreTyping(["scan-f"], typing);
}
function applyScanFilter() { state.scanFilter = $("#scan-f").value.trim(); renderScans(); }

/* ---------- 扫描事件详情（端口明细 + 非 HTTP POC） ---------- */
async function openScanDetail(scanId) {
  const d = await api("/api/scans/" + encodeURIComponent(scanId));
  if (!d) return;
  const attackBadge = (a) => `<span class="badge ${a.includes("brute") || a.includes("attack") ? "critical" : "info"}">${esc(a)}</span>`;
  // 折叠分区：大事件默认只展开端口明细，其余点开才看（避免一屏堆满 + 卡顿）
  const sec = (title, content) => `
    <details class="sec"><summary>${title}</summary><div class="sec-body">${content}</div></details>`;
  $("#drawer-title").textContent = `扫描事件 ${d.scan_id.slice(0, 30)}`;
  $("#drawer-body").innerHTML = `
    <dl class="kv">
      <dt>来源</dt><dd class="mono">${esc(d.src_ip)}</dd>
      <dt>工具</dt><dd>${esc(d.tool_guess || "未知")}</dd>
      <dt>时间</dt><dd>${fmtTime(d.ts_start)} ~ ${fmtTime(d.ts_end)}</dd>
      <dt>规模</dt><dd>${d.conn_count} 连接 · ${d.session_ids.length} 会话 · ${d.ports_hit.length} 个端口</dd>
    </dl>
    <h3 style="font-size:13px">端口探测明细（${d.ports.length}）</h3>
    <div class="table-scroll" style="max-height:42vh">
      <table><thead><tr><th>端口</th><th>服务</th><th>Banner</th><th>连接数</th><th>攻击/探测意图</th><th>探测样例</th></tr></thead>
      <tbody>${d.ports.map((p) => `
        <tr class="clickable" onclick="openPort(${p.dst_port})">
          <td class="mono">${p.dst_port}</td><td>${esc(p.proto)}</td>
          <td class="mono">${esc((p.banner || "").slice(0, 30))}</td><td>${p.conn_count}</td>
          <td>${(p.attacks || []).map(attackBadge).join(" ")}</td>
          <td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis">${esc(JSON.stringify(p.sample || {}).slice(0, 70))}</td></tr>`).join("") || `<tr><td colspan="6" class="empty">无</td></tr>`}</tbody></table>
    </div>
    ${d.poc_ids_nonhttp.length ? sec(`🧪 非 HTTP POC（${d.poc_ids_nonhttp.length}，原始字节级重建）`,
      `<ul class="diff-list">${d.poc_ids_nonhttp.map((p) => `<li>🧪 <span class="mono">${esc(p.file)}</span> <span class="dim">${esc(p.name.slice(0, 60))}</span></li>`).join("")}</ul>
       <div class="dim" style="font-size:12px;margin-top:4px">tcp/network/dns 模板为客户端首块字节回放（原始字节级），matcher 为服务端响应特征——非 HTTP 协议无法像 HTTP 一样重建精细 payload/matcher。</div>`) : ""}
    ${d.web_probe ? sec(`🕵️ 网站探测思路（${d.web_probe.total_requests} 请求 / ${d.web_probe.distinct_paths} 路径）${d.web_probe.dict_scan ? '<span class="badge high">字典爆破特征</span>' : ""}`, renderWebProbe(d.web_probe)) : ""}
    ${(d.chains || []).length ? sec(`🔗 利用链（${d.chains.length}）——行为层：多步攻击序列`, renderChains(d.chains)) : ""}
  `;
  showLayer($("#drawer"));
}

/* ---------- 利用链（行为层） ---------- */
function renderChains(chains) {
  const CHAIN_LABELS = {
    upload_exec: "🔗 上传-执行链", upload_only: "📤 文件上传尝试",
    brute: "🔑 认证爆破链", probe_exploit: "🎯 先探后打",
    repeated_attack: "🔁 重复确认攻击", app_cluster_attack: "🧩 应用级攻击簇",
  };
  const CHAIN_CLS = {
    upload_exec: "critical", brute: "high", probe_exploit: "high",
    repeated_attack: "high", app_cluster_attack: "high", upload_only: "medium",
  };
  return `
    <table style="font-size:12px"><thead><tr><th>类型</th><th>目标</th><th>步骤</th><th>说明</th></tr></thead>
    <tbody>${chains.map((c) => `
      <tr><td><span class="badge ${CHAIN_CLS[c.type] || "high"}">${CHAIN_LABELS[c.type] || c.type}</span></td>
      <td class="mono">${esc(c.path.slice(0, 40))}</td><td>${c.steps}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${esc(c.detail.slice(0, 70))}</td></tr>`).join("")}</tbody></table>`;
}

/* ---------- 网站探测思路 ---------- */
function renderWebProbe(w) {
  const techBadge = (t) => `<span class="badge ${t.name === "sqli" ? "critical" : "high"}">${esc(t.name)} × ${t.count}</span>`;
  const paramsHtml = Object.entries(w.param_matrix || {}).slice(0, 10).map(([path, params]) => `
    <tr><td class="mono">${esc(path)}</td>
    <td>${Object.entries(params).map(([k, v]) => `${esc(k)}<span class="dim">(${v.variants})</span>`).join(", ")}</td>
    <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(Object.values(params)[0]?.example || "")}</td></tr>`).join("");
  return `
    <div style="margin:8px 0">${(w.techniques || []).map(techBadge).join(" ") || '<span class="dim">无明确攻击手法（纯探测）</span>'}</div>
    <div class="row2">
      <div><div class="dim" style="font-size:12px;margin-bottom:6px">路径发现序列（首次出现顺序）</div>
        <ol style="font-size:12px;padding-left:18px;max-height:220px;overflow-y:auto">${w.path_sequence.slice(0, 40).map((p) => `<li><span class="mono">${esc(p.path)}</span> <span class="dim">×${p.count}</span></li>`).join("") || '<span class="dim">无</span>'}</ol>
      </div>
      <div><div class="dim" style="font-size:12px;margin-bottom:6px">参数测试矩阵（路径 → 参数(变体数)）</div>
        <table style="font-size:12px"><thead><tr><th>路径</th><th>参数(变体)</th><th>示例 payload</th></tr></thead>
        <tbody>${paramsHtml || '<tr><td colspan="3" class="empty">无参数测试</td></tr>'}</tbody></table>
      </div>
    </div>`;
}

/* ---------- 控制台（扫描/攻击/克隆 浏览器操作） ---------- */
async function renderConsole() {
  const [svc, rep] = await Promise.all([api("/api/service"), api("/api/reports")]);
  $("#view").innerHTML = `
    <div class="cards">
      <div class="card">
        <div class="num" style="font-size:16px">${svc["eatal-proxy"] ? "✅ 运行中" : "❌ 已停止"}</div>
        <div class="lbl">蜜罐代理</div>
        <button onclick="restartProxy()" style="margin-top:8px;background:var(--accent);border:none;color:#06121c;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px">🔄 重启（应用配置）</button>
        <div id="restart-msg" class="dim" style="font-size:11px;margin-top:4px"></div>
      </div>
      <div class="card"><div class="num" style="font-size:16px">${svc.pipeline ? "✅ 运行中" : "❌ 已停止"}</div><div class="lbl">分析管道</div><div class="extra" style="font-size:11px">持续吸收 + 版本计算</div></div>
      <div class="card"><div class="num" style="font-size:16px">${svc.dashboard ? "✅ 运行中" : "❌ 已停止"}</div><div class="lbl">界面服务</div><div class="extra" style="font-size:11px">就是你正在看的这个</div></div>
    </div>
    <div class="panel" style="border-color:var(--accent)">
      <h3>⚡ 快速操作（按步骤来）</h3>
      <div class="step-row" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
        <div class="step">
          <div class="step-num">①</div>
          <div class="step-title">扫描目标</div>
          <div class="step-desc dim">探测端口 → 识别服务 → 自动匹配吸收的 POC → 报告</div>
          <input id="c-target" placeholder="目标 IP 或 URL" style="width:100%;margin-top:8px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px">
          <div class="filters" style="margin-top:6px">
            <input id="c-ports" placeholder="端口,逗号分隔(可选)" style="width:45%">
            <select id="c-scan-exploit" style="width:45%"><option value="">全部利用类型</option>
              ${["rce","sql_injection","traversal","xss","brute","ssrf","unknown","probe"].map(s => `<option value="${s}">${s}</option>`).join("")}</select>
          </div>
          <label style="font-size:12px"><input type="checkbox" id="c-nmap"> nmap 深度识别</label>
          <label style="font-size:12px"><input type="checkbox" id="c-backfill"> 命中回注 verified</label>
          <div style="margin-top:8px"><button onclick="runExec('scan')">🚀 开始扫描</button></div>
        </div>
        <div class="step">
          <div class="step-num">②</div>
          <div class="step-title">定向攻击</div>
          <div class="step-desc dim">用吸收的 POC 精准打授权目标（按来源端口/类型筛选）</div>
          <input id="a-target" placeholder="目标 URL" style="width:100%;margin-top:8px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px">
          <div class="filters" style="margin-top:6px">
            <input id="a-port" placeholder="来源端口(如 7001)" style="width:45%">
            <select id="a-exploit" style="width:45%"><option value="">全部利用类型</option>
              ${["rce","sql_injection","traversal","xss","brute","ssrf","unknown","probe"].map(s => `<option value="${s}">${s}</option>`).join("")}</select>
          </div>
          <input id="a-vendor" placeholder="厂商筛选(如 weblogic)" style="width:100%;margin-top:6px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px">
          <div style="margin-top:8px"><button onclick="runExec('attack')">⚔️ 开始攻击</button></div>
        </div>
        <div class="step">
          <div class="step-num">③</div>
          <div class="step-title">克隆目标</div>
          <div class="step-desc dim">把目标外观克隆到蜜罐 → 漏扫扫克隆体 = 扫真实目标 → 吸收针对性 POC</div>
          <input id="cl-url" placeholder="目标 URL（如 http://192.168.1.50:8080）" style="width:100%;margin-top:8px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px">
          <div class="filters" style="margin-top:6px">
            <input id="cl-port" placeholder="蜜罐端口" value="19999" style="width:45%">
            <input id="cl-name" placeholder="克隆名" value="myapp" style="width:45%">
          </div>
          <div style="margin-top:8px"><button onclick="runExec('clone')">🪞 克隆</button></div>
          <div class="dim" style="font-size:11px;margin-top:6px">⚠️ 目标须已授权；克隆后点上方"🔄 重启"生效</div>
        </div>
      </div>
    </div>
    <div class="panel"><h3>📋 任务输出 <span id="task-status" class="dim"></span></h3>
      <pre id="task-log" class="hexview" style="max-height:300px;min-height:100px">等待任务...</pre>
    </div>
    <div class="panel"><h3>📄 历史报告</h3>
      <table><thead><tr><th>文件</th><th>大小</th><th>时间</th><th></th></tr></thead>
      <tbody>${rep.items.map((f) => `
        <tr><td class="mono">${esc(f.name)}</td><td>${fmtSize(f.size)}</td>
        <td>${fmtTime(f.mtime * 1000)}</td>
        <td><a href="/api/reports/${encodeURIComponent(f.name)}" target="_blank" style="color:var(--accent)">查看</a></td></tr>`).join("") || '<tr><td colspan="4" class="empty">暂无报告</td></tr>'}</tbody></table>
    </div>`;
  pollTask();
}

let taskTimer = null;
async function pollTask() {
  const st = await api("/api/exec/status");
  const el = $("#task-log");
  const badge = $("#task-status");
  if (st.task) {
    const t = st.task;
    badge.textContent = `${t.type} · ${t.status}${t.finished ? " · " + t.result : ""}`;
    el.textContent = (t.log || []).join("\n") || "运行中...";
  }
  if (st.running) {
    clearTimeout(taskTimer);
    taskTimer = setTimeout(pollTask, 1500);
  }
}

async function runExec(kind) {
  const q = new URLSearchParams();
  if (kind === "scan") {
    q.set("target", $("#c-target").value.trim());
    if ($("#c-ports").value.trim()) q.set("ports", $("#c-ports").value.trim());
    if ($("#c-scan-exploit").value) q.set("exploit", $("#c-scan-exploit").value);
    q.set("nmap", $("#c-nmap").checked ? "1" : "0");
    q.set("backfill", $("#c-backfill").checked ? "1" : "0");
    q.set("limit", $("#c-limit").value || "200");
  } else if (kind === "attack") {
    q.set("target", $("#a-target").value.trim());
    if ($("#a-port").value.trim()) q.set("from_port", $("#a-port").value.trim());
    if ($("#a-exploit").value) q.set("exploit", $("#a-exploit").value);
    if ($("#a-vendor").value.trim()) q.set("vendor", $("#a-vendor").value.trim());
    q.set("limit", "200");
  } else if (kind === "clone") {
    q.set("url", $("#cl-url").value.trim());
    if ($("#cl-port").value.trim()) q.set("port", $("#cl-port").value.trim());
    if ($("#cl-name").value.trim()) q.set("name", $("#cl-name").value.trim());
  }
  const r = await api("/api/exec/" + kind + "?" + q);
  if (r.error) { $("#task-log").textContent = "错误: " + r.error; return; }
  $("#task-log").textContent = "任务已提交...";
  pollTask();
}

async function restartProxy() {
  const msg = $("#restart-msg");
  if (msg) msg.textContent = "重启中（约 8 秒）...";
  const r = await api("/api/service/restart");
  if (msg) msg.textContent = r.message || r.error || "";
  setTimeout(renderConsole, 9000); // 重启完成后刷新状态
}

/* ---------- 详情抽屉 / 弹窗 ---------- */
async function openSession(id) {
  const d = await api("/api/sessions/" + encodeURIComponent(id));
  if (!d) return;
  $("#drawer-title").textContent = "会话 " + id.slice(0, 12);
  $("#drawer-body").innerHTML = `
    <dl class="kv">
      <dt>时间</dt><dd>${fmtTime(d.ts_start)} ~ ${fmtTime(d.ts_end)}（${((d.ts_end - d.ts_start) / 1000).toFixed(1)}s）</dd>
      <dt>来源</dt><dd class="mono">${esc(d.src_ip)}:${d.src_port}</dd>
      <dt>目标</dt><dd class="mono">${esc(d.dst_ip)}:${d.dst_port} (${esc(d.transport)})</dd>
      <dt>协议</dt><dd>${esc(d.proto)} · banner: <span class="mono">${esc(d.banner || "-")}</span></dd>
      <dt>解析状态</dt><dd>${esc(d.parse_status)} · 关闭原因: ${esc(d.close_reason)}</dd>
      <dt>TLS</dt><dd class="mono">${esc(JSON.stringify(d.tls || {}))}</dd>
    </dl>
    <h3 style="font-size:13px">解析字段</h3>
    <pre class="hexview">${esc(JSON.stringify(d.parsed || {}, null, 2))}</pre>
    <div class="tabbtns">
      <button class="active" data-bytes="client" onclick="switchBytes(this, 'client')">客户端原始字节 (${fmtSize(d.client.len)})</button>
      <button data-bytes="server" onclick="switchBytes(this, 'server')">服务端原始字节 (${fmtSize(d.server.len)})</button>
    </div>
    <div id="bytes-hex" class="hexview"></div>
    <div id="bytes-ascii" class="hexview" style="display:none"></div>
    <button style="margin-top:10px" onclick="toggleBytesView()">切换 hex / ascii</button>
    ${d.client.truncated ? '<div class="dim" style="margin-top:6px">字节已截断（上限 64KB）</div>' : ""}
  `;
  window._bytes = { client: d.client, server: d.server, ascii: false };
  showBytes("client");
  showLayer($("#drawer"));
}
function switchBytes(btn, which) {
  document.querySelectorAll(".tabbtns button").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  showBytes(which);
}
function showBytes(which) {
  const b = window._bytes[which];
  $("#bytes-hex").textContent = b.hex;
  $("#bytes-ascii").textContent = b.ascii;
}
function toggleBytesView() {
  window._bytes.ascii = !window._bytes.ascii;
  $("#bytes-hex").style.display = window._bytes.ascii ? "none" : "block";
  $("#bytes-ascii").style.display = window._bytes.ascii ? "block" : "none";
}

async function openPoc(filename) {
  const d = await api("/api/pocs/" + encodeURIComponent(filename));
  if (!d || !d.yaml) return;
  $("#modal-title").textContent = filename;
  $("#modal-body").textContent = d.yaml;
  showLayer($("#modal"));
}

/* ---------- 轮询与页签 ---------- */
const INTERVALS = { overview: 3000, sessions: 3000, flows: 3000, ports: 5000, pocs: 10000, scans: 10000, console: 5000 };
const RENDERERS = { overview: renderOverview, sessions: renderSessions, flows: renderFlows, ports: renderPorts, pocs: renderPocs, scans: renderScans, console: renderConsole };

let timer = null;
function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  clearInterval(timer);
  timer = setInterval(tick, INTERVALS[tab] || 3000);
  tick();
}
async function tick() {
  try { await RENDERERS[state.tab](); } catch (e) { /* 管道未启动时静默 */ }
}

document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

/* 弹层显隐：drawer/modal 共用一个遮罩，支持 Esc / 点击遮罩关闭 */
function showLayer(el) { el.classList.remove("hidden"); $("#overlay").classList.remove("hidden"); }
function hideLayer(el) { el.classList.add("hidden"); $("#overlay").classList.add("hidden"); }
$("#drawer-close").addEventListener("click", () => hideLayer($("#drawer")));
$("#modal-close").addEventListener("click", () => hideLayer($("#modal")));
$("#overlay").addEventListener("click", () => { hideLayer($("#drawer")); hideLayer($("#modal")); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { hideLayer($("#drawer")); hideLayer($("#modal")); }
});
$("#clock").textContent = new Date().toLocaleString("zh-CN", { hour12: false });
setInterval(() => { $("#clock").textContent = new Date().toLocaleString("zh-CN", { hour12: false }); }, 1000);

switchTab("overview");
