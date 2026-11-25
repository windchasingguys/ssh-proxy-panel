const TOKEN_KEY = 'sshproxy.token';
const STATUS_TEXT = {
  stopped: '已停止',
  starting: '连接中',
  up: '已连通',
  retrying: '重连中',
  failed: '已暂停',
  'needs-secret': '等待密码',
};

const TUNNEL_AUTH_LABEL = { key: '私钥', password: '密码', ask: '交互输入' };

const $ = (id) => document.getElementById(id);

let rememberedToken = localStorage.getItem(TOKEN_KEY) || '';
let session = { authRequired: false, authenticated: true, expiresAt: null, idleUntil: null, ttlMinutes: 0, idleMinutes: 0 };
let state = { tunnels: [], stats: {} };
let selected = null;
let source = null;
let logCache = [];
let connecting = false;
let editingId = null;

/** 本页面的前端版本（由服务端注入到 script src 的 ?v=） */
const pageVersion = (() => {
  try {
    const el = document.querySelector('script[src*="app.js"]');
    return el ? new URL(el.src, location.href).searchParams.get('v') || '' : '';
  } catch {
    return '';
  }
})();

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function fmt(ms) {
  const total = Math.max(0, Math.floor((Number(ms) || 0) / 1000));
  if (total < 60) return `${total} 秒`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m < 60) return s ? `${m} 分 ${s} 秒` : `${m} 分`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分`;
}

function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  $('toasts').appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .25s';
    setTimeout(() => el.remove(), 260);
  }, type === 'error' ? 5200 : 2600);
}

async function request(path, method = 'GET', body) {
  const headers = {};
  let payload;
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  // 浏览器走 Cookie 会话（登录时换来的 HttpOnly Cookie），不再每次带令牌
  const res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    const err = new Error(data.error || '需要访问令牌');
    err.authRequired = true;
    err.sessionExpired = Boolean(data.sessionExpired);
    showTokenModal(err.sessionExpired ? err.message : '');
    throw err;
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  if (!$('token-modal').hidden) hideTokenModal();
  return data;
}

/* ---------------- 边缘机信息脱敏（截图分享用） ---------------- */

// 默认开启：首页只显示 d***@e***.com:22 这种形态，点右上角可切回真实值
let maskEdge = localStorage.getItem('sshproxy.mask') !== '0';

function maskUser(user) {
  const text = String(user || '');
  if (!text) return '';
  if (text.length <= 2) return '***';
  return text.length <= 4 ? `${text[0]}***` : `${text[0]}***${text[text.length - 1]}`;
}

function maskHost(host) {
  const text = String(host || '').trim();
  if (!text) return '';
  // IPv6（带不带端口）整体遮掉，端口保留
  const v6 = text.match(/^(\[[^\]]+\])(?::(\d+))?$/);
  if (v6) return `***${v6[2] ? `:${v6[2]}` : ''}`;
  // 带端口的先拆开，端口不敏感
  const portMatch = text.match(/^(.*?):(\d+)$/);
  const bare = portMatch ? portMatch[1] : text;
  const port = portMatch ? `:${portMatch[2]}` : '';

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) {
    const p = bare.split('.');
    return `${p[0]}.***.***.${p[3]}${port}`;
  }
  if (bare.includes(':')) return `***${port}`;
  const parts = bare.split('.');
  if (parts.length === 1) return `${parts[0].length <= 3 ? '***' : `${parts[0][0]}***`}${port}`;
  const head = parts[0].length <= 3 ? '***' : `${parts[0][0]}***`;
  const tail = parts[parts.length - 1];
  return `${head}.${tail}${port}`;
}

/** "user@host:port" 形态（ProxyJump 用） */
function maskVia(value) {
  if (!maskEdge) return String(value ?? '');
  const text = String(value ?? '');
  const m = text.match(/^([^@]+)@(.+)$/);
  if (!m) return maskHost(text);
  return `${maskUser(m[1])}@${maskHost(m[2])}`;
}

function updateMaskButton() {
  const btn = $('btn-mask');
  if (!btn) return;
  btn.textContent = maskEdge ? '隐藏边缘机' : '显示边缘机';
  btn.title = maskEdge
    ? '边缘机用户/地址已脱敏（截图分享时更安全）。点击显示真实值。'
    : '当前显示真实值。点击可脱敏，适合截图分享前打开。';
}

/* ---------------- 渲染 ---------------- */

function viaText(t) {
  const via = t.via || {};
  const user = via.user ? (maskEdge ? maskUser(via.user) : via.user) : '';
  const host = maskEdge ? maskHost(via.host) : via.host;
  const jump = via.proxyJump ? ` (经 ${maskEdge ? maskVia(via.proxyJump) : via.proxyJump})` : '';
  return `${user}${user ? '@' : ''}${host}:${via.port}${jump}`;
}

function card(t) {
  const status = STATUS_TEXT[t.status] || t.status;
  const uptime = t.upAt ? `<span>已连通 <b data-uptime="${esc(t.id)}">${fmt(t.uptimeMs)}</b></span>` : '';
  const retry = t.nextRetryAt ? `<span class="warn" data-retry="${esc(t.id)}">重连倒计时…</span>` : '';
  const failures = t.failures ? `<span class="warn">失败 ${t.failures} 次</span>` : '';
  const restarts = t.restarts ? `<span>重连 ${t.restarts} 次</span>` : '';
  return `
  <article class="card" data-status="${esc(t.status)}">
    <header>
      <span class="dot ${esc(t.status)}"></span>
      <h2 title="${esc(t.description || t.name)}">${esc(t.name)}</h2>
      <button class="icon-btn" type="button" data-act="edit" data-id="${esc(t.id)}" title="编辑这条隧道的配置">✎</button>
      <button class="icon-btn danger" type="button" data-act="remove" data-id="${esc(t.id)}" title="从 tunnels.json 删除这条隧道">✕</button>
      <label class="switch" title="${t.desired ? '点击关闭隧道' : '点击开启隧道'}">
        <input type="checkbox" data-act="toggle" data-id="${esc(t.id)}" ${t.desired ? 'checked' : ''} />
        <span class="track"><span class="knob"></span></span>
      </label>
    </header>
    <div class="route">
      <code>${esc(t.bindAddress)}:${t.localPort}</code>
      <span class="arrow">→</span>
      <code title="${maskEdge ? '边缘机用户/地址已脱敏，点右上角“显示边缘机”可查看真实值' : esc(viaText(t))}">${esc(viaText(t))}</code>
      <span class="arrow">→</span>
      <code>${esc(t.target.host)}:${t.target.port}</code>
    </div>
    <div class="meta">
      <span class="pill ${esc(t.status)}">${esc(status)}</span>
      <span class="pill">${esc(TUNNEL_AUTH_LABEL[t.auth?.mode] || '私钥')}</span>
      ${uptime}
      ${retry}
      ${restarts}
      ${failures}
    </div>
    ${t.lastError ? `<p class="err">${esc(t.lastError)}</p>` : ''}
    <footer>
      ${t.auth?.needsSecret ? `<button class="btn small primary" data-act="secret" data-id="${esc(t.id)}">输入密码</button>` : ''}
      <button class="btn small" data-act="open" data-id="${esc(t.id)}" ${t.status !== 'up' ? 'disabled' : ''}>在浏览器打开</button>
      <button class="btn small" data-act="restart" data-id="${esc(t.id)}">重连</button>
      <button class="btn small" data-act="logs" data-id="${esc(t.id)}">日志</button>
      <button class="btn small" data-act="copy" data-id="${esc(t.id)}">复制命令</button>
    </footer>
  </article>`;
}

function render() {
  const tunnels = state.tunnels || [];
  $('grid').innerHTML = tunnels.map(card).join('');
  $('empty').classList.toggle('hidden', tunnels.length > 0);
  const s = state.stats || {};
  $('stats').innerHTML = `
    <span class="chip">隧道 <b>${s.total ?? tunnels.length}</b></span>
    <span class="chip">已连通 <b>${s.up ?? 0}</b></span>
    <span class="chip">运行中 <b>${s.desired ?? 0}</b></span>
    ${s.failed ? `<span class="chip" style="color:#f87171">已暂停 <b style="color:#f87171">${s.failed}</b></span>` : ''}`;
  if (state.panel?.configFile) $('config-file').textContent = `配置：${state.panel.configFile}`;
  updateLive();
}

function updateLive() {
  for (const el of document.querySelectorAll('[data-uptime]')) {
    const t = (state.tunnels || []).find((x) => x.id === el.dataset.uptime);
    if (t?.upAt) el.textContent = fmt(Date.now() - t.upAt);
  }
  for (const el of document.querySelectorAll('[data-retry]')) {
    const t = (state.tunnels || []).find((x) => x.id === el.dataset.retry);
    if (!t?.nextRetryAt) {
      el.textContent = '重连倒计时…';
      continue;
    }
    const left = Math.max(0, Math.round((t.nextRetryAt - Date.now()) / 1000));
    el.textContent = `${left} 秒后重连`;
  }
}

function setConn(online) {
  const el = $('conn');
  el.classList.toggle('online', online);
  el.classList.toggle('offline', !online);
  el.title = online ? '面板实时连接正常' : '面板连接已断开，正在重试…';
}

/* ---------------- 实时数据 ---------------- */

function connect() {
  if (source) source.close();
  source = new EventSource('/api/events', { withCredentials: true });
  source.onopen = () => setConn(true);
  source.onerror = () => setConn(false);
  source.addEventListener('state', (event) => {
    try {
      state = JSON.parse(event.data);
    } catch {
      return;
    }
    setConn(true);
    render();
  });
  source.addEventListener('log', (event) => {
    try {
      const { id, line } = JSON.parse(event.data);
      if (selected === id) appendLogLine(line);
    } catch {
      /* ignore */
    }
  });
}

/* ---------------- 日志抽屉 ---------------- */

function logLineHtml(line) {
  const time = new Date(line.t).toLocaleTimeString('zh-CN', { hour12: false });
  return `<span class="t">${time}</span><span class="${esc(line.stream)}">${esc(line.text)}</span>\n`;
}

function paintLogs() {
  const el = $('drawer-log');
  el.innerHTML = logCache.map(logLineHtml).join('');
  el.scrollTop = el.scrollHeight;
}

function appendLogLine(line) {
  logCache.push(line);
  if (logCache.length > 800) logCache.splice(0, logCache.length - 800);
  const el = $('drawer-log');
  el.insertAdjacentHTML('beforeend', logLineHtml(line));
  el.scrollTop = el.scrollHeight;
}

async function openLogs(id) {
  const t = (state.tunnels || []).find((x) => x.id === id);
  selected = id;
  $('drawer').hidden = false;
  $('drawer-title').textContent = `日志 · ${t?.name || id}${maskEdge ? '（含真实命令，截图注意）' : ''}`;
  $('drawer-log').textContent = '加载中…';
  try {
    const data = await request(`/api/tunnels/${encodeURIComponent(id)}/logs?lines=200`);
    logCache = data.lines || [];
    paintLogs();
  } catch (err) {
    $('drawer-log').textContent = `读取日志失败: ${err.message}`;
  }
}

/* ---------------- 编辑隧道 ---------------- */

function fillEditor(t) {
  const f = $('editor-form').elements;
  f.id.value = t?.id ?? '';
  f.name.value = t?.name ?? '';
  f.description.value = t?.description ?? '';
  f.localPort.value = t ? t.localPort : '';
  f.bindAddress.value = t?.bindAddress ?? '127.0.0.1';
  f.targetHost.value = t?.target?.host ?? '';
  f.targetPort.value = t ? t.target?.port ?? '' : '';
  f.viaUser.value = t?.via?.user ?? '';
  f.viaHost.value = t?.via?.host ?? '';
  f.viaPort.value = t ? t.via?.port ?? 22 : '';
  f.identityFile.value = t?.auth?.identityFile || t?.via?.identityFile || '';
  f.proxyJump.value = t?.via?.proxyJump ?? '';
  f.authMode.value = t?.auth?.mode ?? 'key';
  f.authPassword.value = '';
  f.authClearPassword.checked = false;
  f.authPassword.placeholder = t?.auth?.hasPassword || t?.auth?.hasPassphrase ? '已保存（留空＝保持不变）' : '留空＝不使用密码';
  f.scheme.value = t?.scheme ?? 'http';
  f.url.value = t?.openPath ?? '';
  f.healthUrl.value = t?.healthUrl ?? '';
  f.extraArgs.value = (t?.extraArgs || []).join(' ');
  f.autoStart.checked = Boolean(t?.autoStart);
  f.openOnUp.checked = Boolean(t?.openOnUp);
  updateAuthHint();
}

/** 按认证方式给一句人话提示 */
function updateAuthHint() {
  const f = $('editor-form').elements;
  const mode = f.authMode.value;
  const hint = $('auth-hint');
  if (!hint) return;
  if (mode === 'password') {
    hint.textContent = '用边缘机账号的密码登录（ssh 会通过 askpass 拿到它）。密码加密保存在 tunnels.json 里，不会以明文出现。';
    f.authPassword.placeholder = '边缘机登录密码（留空＝保持不变）';
  } else if (mode === 'ask') {
    hint.textContent = '不保存任何凭据：每次连接时在面板里输入，只放在内存，面板重启后要重新输入。';
    f.authPassword.placeholder = '这种方式不需要填（连接时会问你）';
  } else {
    hint.textContent = '用私钥登录（推荐）。如果私钥有口令，填在右边，会加密保存并自动喂给 ssh；也可以交给 ssh-agent。';
    f.authPassword.placeholder = '私钥口令（可选，留空＝保持不变）';
  }
}

function payloadFromEditor() {
  const f = $('editor-form').elements;
  const num = (v) => (String(v ?? '').trim() === '' ? undefined : Number(v));
  return {
    id: f.id.value.trim(),
    name: f.name.value.trim(),
    description: f.description.value.trim(),
    localPort: num(f.localPort.value),
    bindAddress: f.bindAddress.value.trim() || '127.0.0.1',
    target: { host: f.targetHost.value.trim() || '127.0.0.1', port: num(f.targetPort.value) },
    via: {
      user: f.viaUser.value.trim(),
      host: f.viaHost.value.trim(),
      port: num(f.viaPort.value) ?? 22,
      identityFile: f.identityFile.value.trim(),
      proxyJump: f.proxyJump.value.trim(),
    },
    auth: {
      mode: f.authMode.value,
      identityFile: f.identityFile.value.trim(),
      password: f.authPassword.value,
      clearPassword: f.authClearPassword.checked,
    },
    scheme: f.scheme.value.trim() || 'http',
    url: f.url.value.trim(),
    healthUrl: f.healthUrl.value.trim(),
    extraArgs: f.extraArgs.value.trim() ? f.extraArgs.value.trim().split(/\s+/) : [],
    autoStart: f.autoStart.checked,
    openOnUp: f.openOnUp.checked,
  };
}

function showEditorError(message) {
  const el = $('editor-error');
  el.textContent = message;
  el.classList.toggle('hidden', !message);
}

function openEditor(tunnel) {
  const t = tunnel || null;
  editingId = t?.id ?? null;
  $('editor-title').textContent = t ? `编辑隧道 · ${t.name || t.id}` : '新建隧道';
  fillEditor(t);
  showEditorError('');
  $('editor').hidden = false;
  setTimeout(() => {
    const f = $('editor-form').elements;
    (t ? f.name : f.id).focus();
  }, 30);
}

async function saveEditor(event) {
  event.preventDefault();
  const payload = payloadFromEditor();
  if (!payload.id) return showEditorError('ID 不能为空');
  if (!payload.localPort) return showEditorError('本机端口不能为空');
  if (!payload.via.host) return showEditorError('边缘机地址不能为空');

  const btn = $('editor-save');
  btn.disabled = true;
  showEditorError('');
  try {
    const isEdit = Boolean(editingId);
    const path = isEdit ? `/api/tunnels/${encodeURIComponent(editingId)}` : '/api/tunnels';
    await request(path, isEdit ? 'PUT' : 'POST', payload);
    $('editor').hidden = true;
    toast(isEdit ? '配置已保存（在跑的隧道会用新参数重建）' : '已新增隧道');
  } catch (err) {
    showEditorError(err.message);
  } finally {
    btn.disabled = false;
  }
}

async function removeTunnel(t) {
  const label = t?.name || t?.id || '';
  if (!window.confirm(`确定删除隧道「${label}」吗？\n\n它会从 tunnels.json 里被删掉，正在跑的连接也会断开。`)) return;
  try {
    await request(`/api/tunnels/${encodeURIComponent(t.id)}`, 'DELETE');
    if (selected === t.id) {
      selected = null;
      $('drawer').hidden = true;
    }
    toast('已删除');
  } catch (err) {
    toast(err.message, 'error');
  }
}

/* ---------------- 连接时输入密码 ---------------- */

let secretTunnelId = null;

function showSecretError(message) {
  const el = $('secret-error');
  el.textContent = message || '';
  el.classList.toggle('hidden', !message);
}

function openSecretModal(tunnel) {
  secretTunnelId = tunnel?.id || null;
  $('secret-hint').textContent = `为「${tunnel?.name || tunnel?.id || ''}」输入 SSH 密码/口令。只保存在内存里，重启面板后需要重新输入。`;
  $('secret-input').value = '';
  showSecretError('');
  $('secret-modal').hidden = false;
  setTimeout(() => $('secret-input').focus(), 30);
}

/* ---------------- 全局设置 ---------------- */

function showSettingsError(message) {
  const el = $('settings-error');
  el.textContent = message;
  el.classList.toggle('hidden', !message);
}

/** "C:\Program Files\ssh.exe" --flag 这类字符串拆成 argv（支持引号） */
function parseCommandLine(text) {
  const out = [];
  let cur = '';
  let quote = null;
  for (const ch of String(text || '')) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (cur) {
        out.push(cur);
        cur = '';
      }
    } else {
      cur += ch;
    }
  }
  if (cur) out.push(cur);
  return out;
}

function formatCommandLine(bin) {
  const list = Array.isArray(bin) ? bin : [bin ?? 'ssh'];
  return list.map((part) => (/[\s"']/.test(String(part)) ? `"${String(part)}"` : String(part))).join(' ');
}

function renderKeyList(keys) {
  const box = $('key-list');
  if (!box) return;
  if (!keys.length) {
    box.innerHTML = '<p class="empty-key">还没有注册密钥。点右上角“注册本机密钥”，之后就能用私钥一键登录。</p>';
    return;
  }
  box.innerHTML = keys
    .map(
      (k) => `<div class="key-item">
        <span class="key-name">${esc(k.name)}</span>
        <code title="${esc(k.fingerprint)}">${esc(k.fingerprint)}</code>
        <button type="button" class="btn small danger" data-key-del="${esc(k.id)}">删除</button>
      </div>`,
    )
    .join('');
}

async function openSettings() {
  try {
    const cfg = await request('/api/config');
    const f = $('settings-form').elements;
    $('settings-file').textContent = cfg.configFile;
    f.bin.value = formatCommandLine(cfg.ssh.bin);
    f.connectTimeout.value = cfg.ssh.connectTimeout;
    f.serverAliveInterval.value = cfg.ssh.serverAliveInterval;
    f.serverAliveCountMax.value = cfg.ssh.serverAliveCountMax;
    f.strictHostKeyChecking.value = cfg.ssh.strictHostKeyChecking;
    f.batchMode.checked = Boolean(cfg.ssh.batchMode);
    for (const key of ['startTimeoutMs', 'watchIntervalMs', 'maxFailures', 'backoffBaseMs', 'backoffMaxMs', 'stableResetMs']) {
      f[key].value = cfg.supervision[key];
    }
    f.panelToken.value = '';
    f.panelToken.placeholder = cfg.panel.tokenRequired ? '已启用；留空表示保持不变' : '留空＝不需要登录';
    f.clearPanelToken.checked = false;
    f.sessionTtlMinutes.value = cfg.panel.sessionTtlMinutes;
    f.sessionIdleMinutes.value = cfg.panel.sessionIdleMinutes;
    renderKeyList(cfg.panel.keys || []);
    $('key-hint').textContent = (await supportsEd25519())
      ? '私钥保存在本浏览器（IndexedDB，不可导出），服务端只存公钥。'
      : '这个浏览器不支持 Ed25519（需要 Chrome/Edge 113+ 或 Firefox 129+），只能把公钥文件交给 CLI 注册。';
    $('btn-register-key').disabled = !(await supportsEd25519());
    showSettingsError('');
    $('settings').hidden = false;
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function saveSettings(event) {
  event.preventDefault();
  const f = $('settings-form').elements;
  const binParts = parseCommandLine(f.bin.value);
  const panel = {
    sessionTtlMinutes: Number(f.sessionTtlMinutes.value),
    sessionIdleMinutes: Number(f.sessionIdleMinutes.value),
  };
  if (f.clearPanelToken.checked) panel.token = '';
  else if (f.panelToken.value.trim()) panel.token = f.panelToken.value.trim();

  const payload = {
    panel,
    ssh: {
      bin: binParts.length > 1 ? binParts : binParts[0] || 'ssh',
      connectTimeout: Number(f.connectTimeout.value),
      serverAliveInterval: Number(f.serverAliveInterval.value),
      serverAliveCountMax: Number(f.serverAliveCountMax.value),
      strictHostKeyChecking: f.strictHostKeyChecking.value,
      batchMode: f.batchMode.checked,
    },
    supervision: {
      startTimeoutMs: Number(f.startTimeoutMs.value),
      watchIntervalMs: Number(f.watchIntervalMs.value),
      maxFailures: Number(f.maxFailures.value),
      backoffBaseMs: Number(f.backoffBaseMs.value),
      backoffMaxMs: Number(f.backoffMaxMs.value),
      stableResetMs: Number(f.stableResetMs.value),
    },
  };
  const btn = $('settings-save');
  btn.disabled = true;
  showSettingsError('');
  try {
    const result = await request('/api/settings', 'PUT', payload);
    $('settings').hidden = true;
    toast(result.restartRequired ? '已保存：访问令牌/会话参数重启面板后生效' : '全局设置已保存');
  } catch (err) {
    showSettingsError(err.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- 卡片操作 ---------------- */

async function toggle(id, on, input) {
  const label = input?.closest('.switch');
  if (label) label.dataset.busy = '1';
  try {
    await request(`/api/tunnels/${encodeURIComponent(id)}/${on ? 'start' : 'stop'}`, 'POST');
    toast(on ? '已下发开启指令' : '已下发关闭指令');
  } catch (err) {
    if (input) input.checked = !on;
    toast(err.message, 'error');
  } finally {
    if (label) delete label.dataset.busy;
  }
}

async function onAction(event) {
  const btn = event.target.closest('button[data-act]');
  if (!btn) return;
  const id = btn.dataset.id;
  const act = btn.dataset.act;
  const tunnel = (state.tunnels || []).find((x) => x.id === id);

  if (act === 'secret') {
    openSecretModal(tunnel);
    return;
  }
  if (act === 'open') {
    if (tunnel?.url) window.open(tunnel.url, '_blank', 'noopener');
    return;
  }
  if (act === 'edit') {
    openEditor(tunnel);
    return;
  }
  if (act === 'remove') {
    removeTunnel(tunnel || { id });
    return;
  }
  if (act === 'logs') {
    openLogs(id);
    return;
  }
  if (act === 'copy') {
    const text = tunnel?.command || '';
    try {
      await navigator.clipboard.writeText(text);
      toast('ssh 命令已复制');
    } catch {
      window.prompt('复制下面的命令', text);
    }
    return;
  }
  if (act === 'restart') {
    btn.disabled = true;
    try {
      await request(`/api/tunnels/${encodeURIComponent(id)}/restart`, 'POST');
      toast('正在重连…');
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      setTimeout(() => {
        btn.disabled = false;
      }, 800);
    }
  }
}

/* ---------------- 令牌 ---------------- */

const TOKEN_SOURCE_TEXT = {
  env: '环境变量 SSH_PROXY_TOKEN',
  cli: '启动参数 --token',
  file: '配置文件里的 panel.token',
  none: '未设置',
};

function showTokenError(message) {
  const el = $('token-error');
  el.textContent = message || '';
  el.classList.toggle('hidden', !message);
}

function showTokenModal(message = '') {
  renderAuthTabs();
  $('token-modal').hidden = false;
  showTokenError(message);
  fillTokenDiagnostics(message);
  preferKeyMode();
  setTimeout(() => {
    const mode = currentAuthMode();
    if (mode === 'password') $('password-input').focus();
    else if (mode === 'token') $('token-input').focus();
  }, 30);
}

/** 本机已经注册过密钥时，默认把登录框停在"密钥"上（一次点击就能进） */
async function preferKeyMode() {
  if (!authMethods.includes('key')) return;
  const stored = await keyStoreGet();
  if (stored?.keyId) setAuthMode('key');
}

function hideTokenModal() {
  $('token-modal').hidden = true;
  showTokenError('');
}

/**
 * 问一下服务端要不要登录、支持哪些方式。
 * 返回 health 对象（含 methods/version），连不上返回 null。
 */
async function probeAuthRequirement() {
  try {
    const res = await fetch('/healthz', { cache: 'no-store' });
    if (!res.ok) return null;
    const health = await res.json();
    if (Array.isArray(health.methods) && health.methods.length) authMethods = health.methods;
    const label = (health.methods || []).map((m) => AUTH_LABEL[m] || m).join(' / ');
    const source = TOKEN_SOURCE_TEXT[health.tokenSource] || '';
    $('token-hint').textContent = health.authRequired
      ? `这个面板需要登录，可用方式：${label || '令牌'}${health.methods?.includes('token') && source ? `（令牌来源：${source}）` : ''}`
      : '';
    checkFreshness(health.version);
    return health;
  } catch {
    return null;
  }
}

/* ---------------- 会话（登录 / 退出） ---------------- */

let authMethods = [];

async function getSession() {
  const res = await fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' });
  if (!res.ok) throw new Error(`读取登录状态失败（HTTP ${res.status}）`);
  const data = await res.json();
  if (Array.isArray(data.methods)) authMethods = data.methods;
  return data;
}

/** mode: token | password | key（key 时用 challengeId + signature） */
async function login(body, remember) {
  const res = await fetch('/api/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  session = data;
  if (Array.isArray(data.methods)) authMethods = data.methods;
  if (body.mode === 'token') {
    if (remember && body.token) {
      rememberedToken = body.token;
      localStorage.setItem(TOKEN_KEY, body.token);
    } else {
      rememberedToken = '';
      localStorage.removeItem(TOKEN_KEY);
    }
  }
  return data;
}

async function logout() {
  try {
    await fetch('/api/session', { method: 'DELETE', credentials: 'same-origin' });
  } catch {
    /* 服务端可能已经不可达，本地照样清干净 */
  }
  rememberedToken = '';
  localStorage.removeItem(TOKEN_KEY);
  location.reload();
}

/* ---------------- 本机密钥（Ed25519，私钥不可导出，存在 IndexedDB） ---------------- */

const KEY_DB = 'sshproxy';
const KEY_STORE = 'kv';
const KEY_ENTRY = 'ed25519';
let ed25519Support = null;

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(KEY_DB, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(KEY_STORE)) req.result.createObjectStore(KEY_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('打开 IndexedDB 失败'));
  });
}

async function keyStoreGet() {
  try {
    const db = await openKeyDb();
    return await new Promise((resolve, reject) => {
      const req = db.transaction(KEY_STORE, 'readonly').objectStore(KEY_STORE).get(KEY_ENTRY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function keyStoreSet(value) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readwrite');
    tx.objectStore(KEY_STORE).put(value, KEY_ENTRY);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

async function supportsEd25519() {
  if (ed25519Support !== null) return ed25519Support;
  try {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    ed25519Support = Boolean(pair && pair.privateKey);
  } catch {
    ed25519Support = false;
  }
  return ed25519Support;
}

function base64ToBytes(b64) {
  const bin = atob(String(b64).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** raw 32 字节 → "ssh-ed25519 AAAA..."（OpenSSH 线格式） */
function sshEd25519FromRaw(raw) {
  const type = new TextEncoder().encode('ssh-ed25519');
  const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const parts = [u32(type.length), type, u32(raw.length), raw];
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const blob = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    blob.set(part, offset);
    offset += part.length;
  }
  return `ssh-ed25519 ${bytesToBase64(blob)}`;
}

/** 用本机密钥完成一次签名登录 */
async function loginWithKey() {
  const stored = await keyStoreGet();
  if (!stored?.pair || !stored?.keyId) {
    throw new Error('本机还没有注册密钥：先用令牌或密码登录，再到“全局设置 → 密钥登录”点注册');
  }
  const res = await fetch(`/api/auth/challenge?keyId=${encodeURIComponent(stored.keyId)}`, { cache: 'no-store' });
  const info = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(info.error || `获取签名挑战失败（HTTP ${res.status}）`);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, stored.pair.privateKey, base64ToBytes(info.challenge));
  return login({ mode: 'key', challengeId: info.challengeId, signature: bytesToBase64(new Uint8Array(signature)) });
}

/** 生成一对 Ed25519 密钥并把公钥注册到服务端（私钥留在 IndexedDB，不可导出） */
async function registerThisBrowserKey() {
  if (!(await supportsEd25519())) {
    throw new Error('这个浏览器不支持 Ed25519（需要 Chrome/Edge 113+ 或 Firefox 129+）');
  }
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const name = `浏览器密钥 ${new Date().toLocaleDateString('zh-CN')}`;
  const data = await request('/api/auth/keys', 'POST', { name, publicKey: sshEd25519FromRaw(raw) });
  await keyStoreSet({ pair, keyId: data.id, name });
  return data;
}

/* ---------------- 登录框 ---------------- */

const AUTH_LABEL = { token: '令牌', password: '密码', key: '密钥' };

function currentAuthMode() {
  const active = document.querySelector('#auth-tabs button.active');
  if (active) return active.dataset.mode;
  return authMethods[0] || 'token';
}

function setAuthMode(mode) {
  for (const btn of document.querySelectorAll('#auth-tabs button')) {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  }
  for (const panel of document.querySelectorAll('.auth-panel')) {
    panel.hidden = panel.dataset.mode !== mode;
  }
  const submit = $('token-submit');
  const rememberRow = $('remember-row');
  submit.textContent = mode === 'key' ? '用密钥登录' : '登录';
  rememberRow.hidden = mode !== 'token';
  const focusTarget = mode === 'password' ? $('password-input') : mode === 'token' ? $('token-input') : null;
  if (focusTarget) setTimeout(() => focusTarget.focus(), 20);
  refreshKeyLoginHint();
}

async function refreshKeyLoginHint() {
  const hint = $('key-login-hint');
  if (!hint) return;
  if (!(await supportsEd25519())) {
    hint.textContent = '这个浏览器不支持 Ed25519，请改用令牌或密码。';
    $('btn-key-login').disabled = true;
    return;
  }
  $('btn-key-login').disabled = false;
  const stored = await keyStoreGet();
  hint.textContent = stored?.name
    ? `已检测到本机密钥「${stored.name}」，可以直接登录。`
    : '本机还没有密钥：先用令牌或密码登录，然后在“全局设置 → 密钥登录”里注册。';
}

function renderAuthTabs() {
  const tabs = $('auth-tabs');
  const methods = authMethods.length ? authMethods : ['token'];
  tabs.innerHTML = methods
    .map((m) => `<button type="button" data-mode="${m}">${AUTH_LABEL[m] || m}</button>`)
    .join('');
  tabs.hidden = methods.length <= 1;
  for (const btn of tabs.querySelectorAll('button')) {
    btn.addEventListener('click', () => setAuthMode(btn.dataset.mode));
  }
  const preferred = methods.includes('key') && authMethods.length > 1 ? methods[0] : methods[0];
  setAuthMode(preferred);
}

function sessionRemainingMs() {
  if (!session.expiresAt) return null;
  const until = Math.min(session.expiresAt, session.idleUntil ?? session.expiresAt);
  return until - Date.now();
}

function updateSessionChip() {
  const chip = $('session');
  if (!chip || chip.classList.contains('hidden')) return;
  const left = sessionRemainingMs();
  if (left === null) {
    chip.textContent = '已登录';
    return;
  }
  if (left <= 0) {
    chip.textContent = '登录已过期';
    chip.classList.add('expired');
    return;
  }
  chip.classList.remove('expired');
  const label = AUTH_LABEL[session.method] || '';
  chip.textContent = `${label ? `${label}登录` : '已登录'} · 剩 ${fmt(left)}`;
}

function renderSession() {
  const active = Boolean(session.authRequired && session.authenticated);
  $('session').classList.toggle('hidden', !active);
  $('btn-logout').classList.toggle('hidden', !active);
  if (!active) return;
  $('session').title = `会话 ${session.ttlMinutes} 分钟到期；${session.idleMinutes} 分钟无操作也会失效。到点后需要重新输入令牌。`;
  updateSessionChip();
}

/** 页面版本落后于服务端时给条明路，而不是让人以为"面板坏了" */
function checkFreshness(serverVersion) {
  const banner = $('stale-banner');
  if (!banner) return;
  const stale = Boolean(pageVersion && serverVersion && pageVersion !== String(serverVersion));
  banner.classList.toggle('hidden', !stale);
  if (stale) $('stale-version').textContent = String(serverVersion);
}

/** 令牌框里的诊断信息：出问题时这一块能直接说明白 */
async function fillTokenDiagnostics(message) {
  let health = '（/healthz 也拿不到）';
  try {
    const res = await fetch('/healthz', { cache: 'no-store' });
    health = `${res.status} ${JSON.stringify(await res.json())}`;
  } catch (err) {
    health = `请求失败：${err.message}`;
  }
  const stored = localStorage.getItem(TOKEN_KEY) || '';
  const lines = [
    `页面地址：${location.href}`,
    `页面版本：${pageVersion || '(未注入版本号，可能是旧页面)'}`,
    `healthz：${health}`,
    `本地已保存令牌：${stored ? `${stored.length} 个字符` : '无'}`,
    `最近一次错误：${message || '(无)'}`,
  ];
  $('token-diag-body').textContent = lines.join('\n');
}

/* ---------------- 启动 ---------------- */

async function boot() {
  if (connecting) return;
  connecting = true;
  try {
    const health = await probeAuthRequirement();
    if (health?.authRequired) {
      session = await getSession();
      if (!session.authenticated) {
        // 1) 记住的令牌
        if (rememberedToken && authMethods.includes('token')) {
          try {
            await login({ mode: 'token', token: rememberedToken }, true);
          } catch (err) {
            rememberedToken = '';
            localStorage.removeItem(TOKEN_KEY);
            renderSession();
            showTokenModal(`记住的令牌已失效（${err.message}）`);
            return;
          }
        } else if (authMethods.includes('key') && (await keyStoreGet())?.keyId) {
          // 本机有密钥：弹出登录框并默认选中"密钥"，一次点击即可进入（不静默登录，否则"退出"看起来没生效）
          renderSession();
          showTokenModal('');
          return;
        } else {
          renderSession();
          showTokenModal('');
          return;
        }
      }
    }
    state = await request('/api/state');
    hideTokenModal();
    render();
    renderSession();
    setConn(true);
    connect();
  } catch (err) {
    setConn(false);
    if (err.authRequired) {
      // 需要登录：停下来等用户输入，不再自动重试
      return;
    }
    toast(`连不上面板：${err.message}`, 'error');
    setTimeout(() => boot(), 3000);
  } finally {
    connecting = false;
  }
}

/* ---------------- 事件绑定 ---------------- */

$('grid').addEventListener('click', onAction);
$('grid').addEventListener('change', (event) => {
  const input = event.target.closest('input[data-act="toggle"]');
  if (!input) return;
  toggle(input.dataset.id, input.checked, input);
});

$('btn-new').addEventListener('click', () => openEditor(null));
$('btn-mask').addEventListener('click', () => {
  maskEdge = !maskEdge;
  localStorage.setItem('sshproxy.mask', maskEdge ? '1' : '0');
  updateMaskButton();
  render();
  toast(maskEdge ? '已隐藏边缘机用户/地址' : '已显示真实值');
});
$('btn-settings').addEventListener('click', openSettings);
$('btn-start-all').addEventListener('click', async () => {
  try {
    await request('/api/all/start', 'POST');
    toast('已下发全部开启');
  } catch (err) {
    toast(err.message, 'error');
  }
});
$('btn-stop-all').addEventListener('click', async () => {
  try {
    await request('/api/all/stop', 'POST');
    toast('已下发全部关闭');
  } catch (err) {
    toast(err.message, 'error');
  }
});
$('btn-reload').addEventListener('click', async () => {
  try {
    const res = await request('/api/reload', 'POST');
    toast(`配置已重载（${res.tunnels} 个隧道）`);
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('editor-form').addEventListener('submit', saveEditor);
$('editor-form').elements.authMode.addEventListener('change', updateAuthHint);
$('editor-cancel').addEventListener('click', () => {
  $('editor').hidden = true;
});

$('secret-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = $('secret-input').value;
  if (!value) {
    showSecretError('密码不能为空');
    return;
  }
  const btn = $('secret-submit');
  btn.disabled = true;
  showSecretError('');
  try {
    await request(`/api/tunnels/${encodeURIComponent(secretTunnelId)}/secret`, 'POST', { value });
    $('secret-modal').hidden = true;
    toast('已收到凭据，正在连接…');
  } catch (err) {
    showSecretError(err.message);
  } finally {
    btn.disabled = false;
  }
});
$('secret-cancel').addEventListener('click', () => {
  $('secret-modal').hidden = true;
});
$('settings-form').addEventListener('submit', saveSettings);
$('settings-cancel').addEventListener('click', () => {
  $('settings').hidden = true;
});

async function submitLogin(event) {
  event.preventDefault();
  const mode = currentAuthMode();
  const btn = $('token-submit');
  btn.disabled = true;
  showTokenError('');
  try {
    if (mode === 'key') {
      await loginWithKey();
    } else if (mode === 'password') {
      await login({ mode: 'password', password: $('password-input').value });
    } else {
      await login({ mode: 'token', token: $('token-input').value.trim() }, $('token-remember').checked);
    }
    $('token-modal').hidden = true;
    $('token-input').value = '';
    $('password-input').value = '';
    await boot();
  } catch (err) {
    showTokenError(err.message);
    fillTokenDiagnostics(err.message);
  } finally {
    btn.disabled = false;
  }
}

$('token-form').addEventListener('submit', submitLogin);
$('btn-key-login').addEventListener('click', (event) => {
  event.preventDefault();
  submitLogin({ preventDefault() {} });
});

$('btn-token-clear').addEventListener('click', async () => {
  // 清掉记住的令牌 + 让服务端作废当前会话，然后再试一次
  rememberedToken = '';
  localStorage.removeItem(TOKEN_KEY);
  $('token-input').value = '';
  $('token-remember').checked = false;
  try {
    await fetch('/api/session', { method: 'DELETE', credentials: 'same-origin' });
  } catch {
    /* 忽略 */
  }
  hideTokenModal();
  boot();
});

$('btn-logout').addEventListener('click', () => {
  logout();
});

$('btn-stale-reload').addEventListener('click', () => location.reload());

$('btn-register-key').addEventListener('click', async () => {
  const btn = $('btn-register-key');
  btn.disabled = true;
  try {
    const data = await registerThisBrowserKey();
    toast('已注册本机密钥，下次可以一键登录');
    await openSettings();
    $('key-hint').textContent = `已注册：${data.fingerprint}`;
  } catch (err) {
    $('key-hint').textContent = err.message;
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

$('key-list').addEventListener('click', async (event) => {
  const btn = event.target.closest('[data-key-del]');
  if (!btn) return;
  if (!window.confirm('删除这把密钥？删掉之后它就不能再用来登录了。')) return;
  try {
    await request(`/api/auth/keys/${encodeURIComponent(btn.dataset.keyDel)}`, 'DELETE');
    toast('已删除');
    await openSettings();
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('btn-log-close').addEventListener('click', () => {
  $('drawer').hidden = true;
  selected = null;
});
$('btn-log-refresh').addEventListener('click', () => selected && openLogs(selected));
$('btn-log-copy').addEventListener('click', async () => {
  const text = $('drawer-log').textContent || '';
  try {
    await navigator.clipboard.writeText(text);
    toast('日志已复制');
  } catch {
    window.prompt('复制日志', text);
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!$('editor').hidden) $('editor').hidden = true;
  else if (!$('secret-modal').hidden) $('secret-modal').hidden = true;
  else if (!$('settings').hidden) $('settings').hidden = true;
  else {
    $('drawer').hidden = true;
    selected = null;
  }
});

// 点日志抽屉外面（页面任何地方）就关掉，不用去找关闭按钮
document.addEventListener('mousedown', (event) => {
  if ($('drawer').hidden) return;
  if (event.target.closest('#drawer')) return;
  $('drawer').hidden = true;
  selected = null;
});

// 点遮罩关闭弹窗（点卡片内部不关）
for (const id of ['editor', 'settings', 'secret-modal']) {
  $(id).addEventListener('mousedown', (event) => {
    if (event.target === $(id)) $(id).hidden = true;
  });
}

setInterval(updateLive, 1000);
updateMaskButton();
// 登录态：本地倒计时 + 定时向服务端核对（会话过期/被服务端清掉都能发现）
setInterval(() => {
  updateSessionChip();
  const left = sessionRemainingMs();
  if (left !== null && left <= 0 && $('token-modal').hidden) {
    session = { ...session, authenticated: false };
    renderSession();
    showTokenModal('登录已过期，请重新输入令牌');
  }
}, 30_000);
setInterval(async () => {
  if (!session.authRequired) return;
  try {
    session = await getSession();
    renderSession();
  } catch {
    /* 面板暂时不可达，交给 boot 的重试逻辑 */
  }
}, 120_000);
// 定期确认"服务端还是不是那个服务端"：令牌要求变了、前端更新了，都能自己发现
setInterval(() => probeAuthRequirement(), 60000);
boot();
