#!/usr/bin/env node
/**
 * 端到端冒烟测试：不需要真实 SSH 服务器，用 test/fake-ssh.mjs 扮演 ssh。
 * 覆盖：启动 → 就绪 → 关闭 / 断线自动重连 / 持续失败退避 / 端口占用 / 看门狗 /
 *       配置增删改 / 令牌来源 / 孤儿进程回收 / 优雅退出
 */
import fs from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Supervisor } from '../src/supervisor.mjs';
import { createPanelServer } from '../src/server.mjs';
import { normalizeConfig } from '../src/config.mjs';
import { sleep, probeTcp } from '../src/util.mjs';
import { processAlive } from '../src/ssh.mjs';
import { hashPassword, opensshFromRawEd25519 } from '../src/auth.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const TMP = path.join(ROOT, '.tmp-test');
const FAKE_SSH = path.join(HERE, 'fake-ssh.mjs');
const TOKEN = 'test-token-123';

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`);
};

function canBind(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

/** 显式挑互不相同的端口，避开系统临时端口段，防止和面板自己的监听撞车 */
async function pickPorts(count) {
  const picked = [];
  while (picked.length < count) {
    const candidate = 20000 + Math.floor(Math.random() * 20000);
    if (picked.includes(candidate)) continue;
    if (await canBind(candidate)) picked.push(candidate);
  }
  return picked;
}

async function waitFor(label, fn, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await sleep(200);
  }
  throw new Error(`等待超时: ${label}`);
}

async function main() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });

  const [okPort, flakyPort, failPort, slowPort] = await pickPorts(4);
  const ports = { ok: okPort, flaky: flakyPort, fail: failPort, slow: slowPort };

  const raw = {
    panel: { host: '127.0.0.1', port: 0, token: TOKEN },
    ssh: { bin: [process.execPath, FAKE_SSH], batchMode: true },
    supervision: {
      startTimeoutMs: 3000,
      watchIntervalMs: 700,
      backoffBaseMs: 300,
      backoffMaxMs: 1200,
      maxFailures: 5,
      stableResetMs: 60000,
    },
    tunnels: [
      { id: 'ok', name: '正常隧道', localPort: ports.ok, target: { host: '10.0.0.9', port: 80 }, via: 'deploy@edge.test:22' },
      {
        id: 'flaky',
        name: '会断的隧道',
        localPort: ports.flaky,
        target: '10.0.0.9:80',
        via: { host: 'edge.test', user: 'deploy', port: 22 },
        env: { FAKE_SSH_MODE: 'flaky' },
      },
      { id: 'fail', name: '认证失败', localPort: ports.fail, target: '10.0.0.9:80', via: 'deploy@edge.test:22', env: { FAKE_SSH_MODE: 'fail' } },
      { id: 'slow', name: '起不来的', localPort: ports.slow, target: '10.0.0.9:80', via: 'deploy@edge.test:22', env: { FAKE_SSH_MODE: 'slow' } },
    ],
  };
  const configFile = path.join(TMP, 'tunnels.json');
  fs.writeFileSync(configFile, JSON.stringify(raw, null, 2));
  const config = normalizeConfig(raw, configFile);

  const quiet = { log() {}, warn() {}, error: console.error };
  const supervisor = new Supervisor(config, { logger: quiet });
  await supervisor.init({ reapOrphans: false });
  const { server, close } = await createPanelServer({ supervisor, config });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { 'x-panel-token': TOKEN };
  const getState = async () => (await fetch(`${base}/api/state`, { headers })).json();
  const tunnelOf = async (id) => (await getState()).tunnels.find((t) => t.id === id);

  // ---- 1. 鉴权 ----
  const noToken = await fetch(`${base}/api/state`);
  check('面板 API 无令牌时返回 401', noToken.status === 401, `status=${noToken.status}`);
  const withToken = await fetch(`${base}/api/state`, { headers });
  check('面板 API 带令牌时返回 200', withToken.status === 200, `status=${withToken.status}`);
  const health = await (await fetch(`${base}/healthz`)).json();
  check('healthz 不用令牌就能看"要不要令牌"', health.ok === true && health.authRequired === true, JSON.stringify(health));
  check('healthz 说明了令牌来源', health.tokenSource === 'file', health.tokenSource);
  const html = await fetch(`${base}/`);
  const htmlText = await html.text();
  check('面板首页可访问且包含标题', html.status === 200 && htmlText.includes('SSH 隧道面板'));
  const css = await fetch(`${base}/style.css`);
  check('静态样式可访问', css.status === 200);

  // ---- 2. 启动 → 就绪 ----
  const started = await fetch(`${base}/api/tunnels/ok/start`, { method: 'POST', headers }).then((r) => r.json());
  check('start 接口立即返回（不阻塞等连接）', Boolean(started.ok), `status=${started.tunnel?.status}`);
  const upState = await waitFor('ok 隧道变成 up', async () => {
    const t = await tunnelOf('ok');
    return t?.status === 'up' ? t : null;
  });
  check('隧道进入 up 状态', upState.status === 'up');
  check('本地端口真的能连上', await probeTcp(ports.ok));
  check(
    '快照里带等价 ssh 命令',
    /^.*-N -T .*-L 127\.0\.0\.1:\d+:10\.0\.0\.9:80 deploy@edge\.test$/s.test(upState.command),
    upState.command,
  );
  const logs = await fetch(`${base}/api/tunnels/ok/logs?lines=50`, { headers }).then((r) => r.json());
  check('日志能拿到 ssh 的 stderr 输出', logs.lines.some((l) => l.text.includes('forwarding')), `${logs.lines.length} 行`);

  // ---- 3. 关闭 ----
  const stopped = await fetch(`${base}/api/tunnels/ok/stop`, { method: 'POST', headers }).then((r) => r.json());
  check('stop 后状态为 stopped', stopped.tunnel.status === 'stopped', stopped.tunnel.status);
  await sleep(400);
  check('stop 后本地端口已释放', !(await probeTcp(ports.ok)));

  // ---- 4. 断线自动重连 ----
  await fetch(`${base}/api/tunnels/flaky/start`, { method: 'POST', headers });
  await waitFor('flaky 先连上', async () => (await tunnelOf('flaky'))?.status === 'up', 8000);
  const recovered = await waitFor(
    'flaky 断开后自动恢复',
    async () => {
      const t = await tunnelOf('flaky');
      return t?.status === 'up' && t.restarts >= 1 ? t : null;
    },
    20000,
  );
  check('断线后自动重连成功', recovered.status === 'up' && recovered.restarts >= 1, `restarts=${recovered.restarts}`);

  // ---- 5. 持续失败退避 ----
  await fetch(`${base}/api/tunnels/fail/start`, { method: 'POST', headers });
  const failing = await waitFor(
    'fail 进入重连/暂停',
    async () => {
      const t = await tunnelOf('fail');
      return t && (t.status === 'retrying' || t.status === 'failed') ? t : null;
    },
    8000,
  );
  check('认证失败进入重连状态', failing.status === 'retrying' || failing.status === 'failed', `status=${failing.status}`);
  check('重连计数在增长', failing.restarts >= 1, `restarts=${failing.restarts}`);
  const cappedState = await waitFor(
    'fail 达到上限后暂停',
    async () => {
      const t = await tunnelOf('fail');
      return t?.status === 'failed' ? t : null;
    },
    25000,
  );
  check('连续失败达到上限后自动暂停', cappedState.paused === true, `failures=${cappedState.failures}`);
  check('暂停后不再自动拉起重连', cappedState.nextRetryAt === null);

  // ---- 6. 端口占用检测 ----
  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(ports.ok, '127.0.0.1', resolve));
  await fetch(`${base}/api/tunnels/ok/start`, { method: 'POST', headers });
  const busy = await waitFor(
    '端口被占用时报错',
    async () => {
      const t = await tunnelOf('ok');
      return t?.lastError?.includes('占用') ? t : null;
    },
    6000,
  );
  check('本地端口被占用时给出明确错误', busy.lastError.includes('占用'), busy.lastError);
  await new Promise((resolve) => blocker.close(resolve));
  await fetch(`${base}/api/tunnels/ok/stop`, { method: 'POST', headers });

  // ---- 7. 慢启动超时 ----
  await fetch(`${base}/api/tunnels/slow/start`, { method: 'POST', headers });
  const slowState = await waitFor(
    '慢启动被 watchdog 重建',
    async () => {
      const t = await tunnelOf('slow');
      return t && t.failures >= 1 ? t : null;
    },
    25000,
  );
  check('端口一直起不来会被 watchdog 杀掉重试', slowState.failures >= 1, `failures=${slowState.failures}`);

  // ---- 8. 面板里改配置（增 / 改 / 删 / 全局设置）----
  const api = async (route, method = 'GET', body) => {
    const h = { ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    const res = await fetch(`${base}${route}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const readConfigFile = () => JSON.parse(fs.readFileSync(configFile, 'utf8'));
  const [crudPort, renamePort] = await pickPorts(2);

  const created = await api('/api/tunnels', 'POST', {
    id: 'from-panel',
    name: '面板新增的隧道',
    description: 'smoke test',
    localPort: crudPort,
    target: { host: '10.0.0.7', port: 8080 },
    via: { user: 'deploy', host: 'edge.test', port: 22 },
    autoStart: false,
  });
  check('面板新增隧道返回 200', created.status === 200, `status=${created.status} ${created.body.error || ''}`);
  check('新增后写进了 tunnels.json', readConfigFile().tunnels.some((t) => t.id === 'from-panel'));
  check('新增后出现在状态列表里', (await tunnelOf('from-panel'))?.localPort === crudPort);

  const beforeInvalid = fs.readFileSync(configFile, 'utf8');
  const invalid = await api('/api/tunnels', 'POST', { id: 'bad', localPort: 99999, via: { host: '' }, target: {} });
  check('非法配置返回 400', invalid.status === 400, `status=${invalid.status}`);
  check('非法配置不会修改文件', fs.readFileSync(configFile, 'utf8') === beforeInvalid);

  const dup = await api('/api/tunnels', 'POST', { id: 'from-panel', localPort: crudPort, via: { host: 'edge.test' } });
  check('id 重复时拒绝新增', dup.status === 400, dup.body.error);

  const updated = await api('/api/tunnels/from-panel', 'PUT', {
    id: 'from-panel',
    name: '改过名字的隧道',
    localPort: crudPort,
    target: { host: '10.0.0.8', port: 9090 },
    via: { user: 'deploy', host: 'edge.test', port: 22, proxyJump: 'jump@bastion:22' },
    autoStart: false,
  });
  check('面板编辑隧道返回 200', updated.status === 200, updated.body.error || '');
  const editedRaw = readConfigFile().tunnels.find((t) => t.id === 'from-panel');
  check(
    '编辑内容落盘正确',
    editedRaw.name === '改过名字的隧道' && editedRaw.target.port === 9090 && editedRaw.via.proxyJump === 'jump@bastion:22',
    JSON.stringify(editedRaw),
  );

  // 手写字段（env）在面板编辑后必须保留
  const flakyForm = (await api('/api/config')).body.tunnels.find((t) => t.id === 'flaky');
  await api('/api/tunnels/flaky', 'PUT', { ...flakyForm, name: '会断的隧道（改名）' });
  const flakyRaw = readConfigFile().tunnels.find((t) => t.id === 'flaky');
  check('手写的 env 在面板编辑后仍然保留', flakyRaw?.env?.FAKE_SSH_MODE === 'flaky', JSON.stringify(flakyRaw?.env));
  check('改名生效', flakyRaw?.name === '会断的隧道（改名）', flakyRaw?.name);

  // 改名 + 保持运行状态
  await api('/api/tunnels', 'POST', {
    id: 'rename-me',
    localPort: renamePort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
    autoStart: true,
  });
  await waitFor('rename-me 起来', async () => (await tunnelOf('rename-me'))?.status === 'up', 12000);
  const renamed = await api('/api/tunnels/rename-me', 'PUT', {
    id: 'renamed',
    name: '改名后',
    localPort: renamePort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
  });
  const afterRename = await waitFor(
    '改名后仍然在线',
    async () => {
      const t = await tunnelOf('renamed');
      return t && t.desired && (t.status === 'up' || t.status === 'starting') ? t : null;
    },
    12000,
  );
  check('改名后隧道仍然保持开启状态', afterRename.desired === true, `${afterRename.id}/${afterRename.status}`);
  check('改名后旧 id 已消失', !(await tunnelOf('rename-me')), renamed.body.error || '');

  const settingsRes = await api('/api/settings', 'PUT', { ssh: { connectTimeout: 7 }, supervision: { maxFailures: 9 } });
  check('全局设置保存成功', settingsRes.status === 200 && settingsRes.body.ssh.connectTimeout === 7, `status=${settingsRes.status}`);
  check('全局设置落盘', readConfigFile().ssh.connectTimeout === 7 && readConfigFile().supervision.maxFailures === 9);
  const arrayBin = await api('/api/settings', 'PUT', { ssh: { bin: [process.execPath, FAKE_SSH] } });
  const savedBin = readConfigFile().ssh.bin;
  check('数组形式的 ssh.bin 不会被拼成字符串', arrayBin.status === 200 && Array.isArray(savedBin) && savedBin.length === 2, JSON.stringify(savedBin));

  const removed = await api('/api/tunnels/from-panel', 'DELETE');
  check('删除隧道返回 200', removed.status === 200);
  check('删除后状态列表里没有了', !(await tunnelOf('from-panel')));
  check('删除后文件里也没有了', !readConfigFile().tunnels.some((t) => t.id === 'from-panel'));
  const removeMissing = await api('/api/tunnels/nope', 'DELETE');
  check('删除不存在的隧道返回 400', removeMissing.status === 400, removeMissing.body.error);

  // 打开路径：只写 /admin/login 也能拼成完整 URL
  const [pathPort, fullPort] = await pickPorts(2);
  await api('/api/tunnels', 'POST', {
    id: 'with-path',
    localPort: pathPort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
    url: '/admin/login?next=/dash',
  });
  const pathTunnel = await tunnelOf('with-path');
  check('打开路径拼成本机 URL', pathTunnel?.url === `http://127.0.0.1:${pathPort}/admin/login?next=/dash`, pathTunnel?.url);
  check('原始路径原样保留（编辑器回填用）', pathTunnel?.openPath === '/admin/login?next=/dash', pathTunnel?.openPath);

  await api('/api/tunnels', 'POST', {
    id: 'full-url',
    localPort: fullPort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
    url: 'https://admin.example.com/login',
  });
  check('完整 URL 原样使用', (await tunnelOf('full-url'))?.url === 'https://admin.example.com/login');
  await api('/api/tunnels/with-path', 'DELETE');
  await api('/api/tunnels/full-url', 'DELETE');

  // ---- 9. 令牌来源（文件 / 环境变量 / 都没有）----
  const hadEnvToken = Object.prototype.hasOwnProperty.call(process.env, 'SSH_PROXY_TOKEN');
  const prevEnvToken = process.env.SSH_PROXY_TOKEN;
  process.env.SSH_PROXY_TOKEN = 'env-token';
  const envCfg = normalizeConfig({ panel: { token: 'file-token' }, tunnels: [] }, configFile);
  check(
    '环境变量 SSH_PROXY_TOKEN 优先于配置文件',
    envCfg.panel.token === 'env-token' && envCfg.panel.tokenSource === 'env',
    `${envCfg.panel.token}/${envCfg.panel.tokenSource}`,
  );
  if (hadEnvToken) process.env.SSH_PROXY_TOKEN = prevEnvToken;
  else delete process.env.SSH_PROXY_TOKEN;

  const spacedCfg = normalizeConfig({ panel: { token: '  file-token  ' }, tunnels: [] }, configFile);
  check('token 首尾空格会被去掉', spacedCfg.panel.token === 'file-token' && spacedCfg.panel.tokenSource === 'file', JSON.stringify(spacedCfg.panel.token));
  const emptyCfg = normalizeConfig({ panel: { token: '' }, tunnels: [] }, configFile);
  check('token 为空时标记为不需要令牌', emptyCfg.panel.token === '' && emptyCfg.panel.tokenSource === 'none', emptyCfg.panel.tokenSource);
  const blankCfg = normalizeConfig({ panel: { token: '   ' }, tunnels: [] }, configFile);
  check('只有空格也算没配 token', blankCfg.panel.token === '' && blankCfg.panel.tokenSource === 'none', JSON.stringify(blankCfg.panel.token));

  // ---- 10. 登录会话（时效 / 退出 / 跨站 / 限流） ----
  const loginRequest = async (token = TOKEN) => {
    const res = await fetch(`${base}/api/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const setCookie = (res.headers.getSetCookie?.()[0] || res.headers.get('set-cookie') || '').split(';')[0];
    return { status: res.status, body: await res.json().catch(() => ({})), cookie: setCookie };
  };
  const stateStatus = async (cookie) => (await fetch(`${base}/api/state`, { headers: cookie ? { cookie } : {} })).status;

  const guest = await (await fetch(`${base}/api/session`)).json();
  check('未登录时 /api/session 说明需要令牌', guest.authRequired === true && guest.authenticated === false, JSON.stringify(guest).slice(0, 80));
  check('未登录时能看到会话时效配置', guest.ttlMinutes > 0 && guest.idleMinutes > 0, `${guest.ttlMinutes}/${guest.idleMinutes}`);

  const badLogin = await loginRequest('nope');
  check('令牌错误时登录返回 401', badLogin.status === 401, `status=${badLogin.status}`);

  const goodLogin = await loginRequest();
  check('正确令牌换到会话 Cookie', goodLogin.status === 200 && goodLogin.cookie.startsWith('sshproxy_session='), goodLogin.cookie.slice(0, 34));
  check('会话 Cookie 能访问 API', (await stateStatus(goodLogin.cookie)) === 200);
  check('没有 Cookie 依旧不能访问 API', (await stateStatus('')) === 401);

  const crossSite = await fetch(`${base}/api/all/stop`, {
    method: 'POST',
    headers: { cookie: goodLogin.cookie, origin: 'http://evil.example' },
  });
  check('跨站 POST 被拒绝（防 CSRF）', crossSite.status === 403, `status=${crossSite.status}`);

  await fetch(`${base}/api/session`, { method: 'DELETE', headers: { cookie: goodLogin.cookie } });
  check('退出后会话立刻失效', (await stateStatus(goodLogin.cookie)) === 401);

  // 会话到期（改文件 + 重载，让运行中的服务端真正拿到新 TTL）
  const patchPanel = async (patch) => {
    const raw2 = readConfigFile();
    raw2.panel = { ...raw2.panel, ...patch };
    fs.writeFileSync(configFile, JSON.stringify(raw2, null, 2));
    await api('/api/reload', 'POST');
  };

  await patchPanel({ sessionTtlMinutes: 0.02 }); // 1.2 秒
  const shortSession = await loginRequest();
  check('短时效会话登录成功', shortSession.status === 200);
  await sleep(1600);
  const expiredRes = await fetch(`${base}/api/state`, { headers: { cookie: shortSession.cookie } });
  const expiredBody = await expiredRes.json().catch(() => ({}));
  check('会话到期后 401 并标记过期', expiredRes.status === 401 && expiredBody.sessionExpired === true, `${expiredRes.status}/${expiredBody.sessionExpired}`);

  // 闲置超时（TTL 放长，只留闲置时间）
  await patchPanel({ sessionTtlMinutes: 720, sessionIdleMinutes: 0.02 });
  const idleSession = await loginRequest();
  await sleep(1600);
  const idleRes = await fetch(`${base}/api/state`, { headers: { cookie: idleSession.cookie } });
  const idleBody = await idleRes.json().catch(() => ({}));
  check('闲置超时后同样要求重新登录', idleRes.status === 401 && idleBody.sessionExpired === true, `${idleRes.status}/${idleBody.sessionExpired}`);
  await patchPanel({ sessionIdleMinutes: 120 });

  // 连续输错限流（放最后，因为它会锁定 30 秒）
  let lastStatus = 0;
  for (let i = 0; i < 6; i += 1) lastStatus = (await loginRequest('bad-token')).status;
  check('连续输错会被限流', lastStatus === 429, `最后一次 status=${lastStatus}`);

  // 面板里设置令牌：只落盘、不热应用（否则会当场把自己踢下线）
  const panelSettings = await api('/api/settings', 'PUT', { panel: { token: 'file-token-xyz', sessionTtlMinutes: 60 } });
  check('设置令牌返回 restartRequired', panelSettings.status === 200 && panelSettings.body.restartRequired === true, `status=${panelSettings.status}`);
  check('令牌写进了配置文件', readConfigFile().panel.token === 'file-token-xyz');
  check('令牌未热应用（当前进程仍用旧令牌）', (await fetch(`${base}/api/state`, { headers })).status === 200);

  // ---- 10.5 隧道到边缘机的认证：存储密码（加密）/ 连接时输入 ----
  const [pwPort, badPwPort, askPort] = await pickPorts(3);

  const pwCreate = await api('/api/tunnels', 'POST', {
    id: 'pw-tunnel',
    localPort: pwPort,
    target: { host: '10.0.0.9', port: 80 },
    via: { user: 'deploy', host: 'edge.test', port: 22 },
    auth: { mode: 'password', password: 'tunnel-pass-1' },
    env: { FAKE_SSH_EXPECT: 'tunnel-pass-1' },
  });
  check('能创建"存储密码"隧道', pwCreate.status === 200, pwCreate.body.error || '');
  const pwRaw = JSON.parse(fs.readFileSync(configFile, 'utf8')).tunnels.find((t) => t.id === 'pw-tunnel');
  check(
    '密码以密文写入配置（明文不落盘）',
    /^enc:v1:/.test(pwRaw?.auth?.password || '') && !String(pwRaw?.auth?.password).includes('tunnel-pass-1'),
    String(pwRaw?.auth?.password).slice(0, 24),
  );

  await api('/api/tunnels/pw-tunnel/start', 'POST');
  const pwUp = await waitFor(
    '密码模式连上',
    async () => {
      const t = await tunnelOf('pw-tunnel');
      return t?.status === 'up' ? t : null;
    },
    15000,
  );
  check('密码模式能把凭据经 askpass 递给 ssh', pwUp.status === 'up');
  check('快照里的命令不含密码', !JSON.stringify(pwUp).includes('tunnel-pass-1'));
  const pwLogs = await api('/api/tunnels/pw-tunnel/logs?lines=50');
  check('日志里也不出现密码', !pwLogs.body.lines.some((l) => l.text.includes('tunnel-pass-1')));

  const badPw = await api('/api/tunnels', 'POST', {
    id: 'bad-pw',
    localPort: badPwPort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
    auth: { mode: 'password', password: 'wrong-password' },
    env: { FAKE_SSH_EXPECT: 'tunnel-pass-1' },
  });
  check('密码错误也能创建（校验在连接时）', badPw.status === 200);
  await api('/api/tunnels/bad-pw/start', 'POST');
  const badState = await waitFor(
    '密码错误时连接失败',
    async () => {
      const t = await tunnelOf('bad-pw');
      return t && (t.status === 'retrying' || t.status === 'failed') ? t : null;
    },
    15000,
  );
  check('密码不对时连不上（ssh 拒绝）', badState.status !== 'up', `status=${badState.status}`);

  const askCreate = await api('/api/tunnels', 'POST', {
    id: 'ask-tunnel',
    localPort: askPort,
    target: { host: '10.0.0.9', port: 80 },
    via: { host: 'edge.test' },
    auth: { mode: 'ask' },
    env: { FAKE_SSH_EXPECT: 'ask-pass' },
  });
  check('能创建"连接时输入"隧道', askCreate.status === 200);
  check('配置里没有任何密码字段', !/enc:v1:/.test(JSON.stringify(JSON.parse(fs.readFileSync(configFile, 'utf8')).tunnels.find((t) => t.id === 'ask-tunnel'))));
  await api('/api/tunnels/ask-tunnel/start', 'POST');
  const needSecret = await waitFor(
    '连接时输入 → 等待密码',
    async () => {
      const t = await tunnelOf('ask-tunnel');
      return t?.status === 'needs-secret' ? t : null;
    },
    8000,
  );
  check('没有凭据时停在"等待密码"', needSecret.auth.needsSecret === true);
  const secretRes = await api('/api/tunnels/ask-tunnel/secret', 'POST', { value: 'ask-pass' });
  check('提交凭据接口返回成功', secretRes.status === 200, secretRes.body.error || '');
  const askUp = await waitFor(
    '交互输入后连上',
    async () => {
      const t = await tunnelOf('ask-tunnel');
      return t?.status === 'up' ? t : null;
    },
    15000,
  );
  check('输入密码后隧道连上', askUp.status === 'up');
  const askRaw = JSON.parse(fs.readFileSync(configFile, 'utf8')).tunnels.find((t) => t.id === 'ask-tunnel');
  check('内存里的凭据不会写进配置', !askRaw?.auth?.password && !askRaw?.auth?.passphrase, JSON.stringify(askRaw?.auth));
  await api('/api/tunnels/ask-tunnel/stop', 'POST');
  check('停止后凭据被忘掉', (await tunnelOf('ask-tunnel'))?.auth.hasSecret === false);

  // ---- 11. 全部关闭 + 优雅退出 ----
  await fetch(`${base}/api/all/stop`, { method: 'POST', headers });
  await supervisor.shutdown();
  await close();
  await sleep(500);

  const runtimeFile = path.join(TMP, '.ssh-proxy', 'runtime.json');
  const leftover = fs.existsSync(runtimeFile) ? JSON.parse(fs.readFileSync(runtimeFile, 'utf8')) : [];
  check('退出后没有遗留 ssh 进程记录', leftover.length === 0);
  check('退出后本地端口都已释放', !(await probeTcp(ports.ok)) && !(await probeTcp(ports.flaky)));

  // ---- 12. 面板被强杀后遗留的 ssh 进程能被回收 ----
  const reapDir = path.join(TMP, 'reap');
  fs.mkdirSync(path.join(reapDir, '.ssh-proxy'), { recursive: true });
  const [orphanPort] = await pickPorts(1);
  const spec = `127.0.0.1:${orphanPort}:10.0.0.9:80`;
  const orphan = spawn(process.execPath, [FAKE_SSH, '-N', '-T', '-L', spec, 'deploy@edge.test'], {
    stdio: 'ignore',
    windowsHide: true,
  });
  await sleep(1000);
  check('已造出一个"遗留 ssh"进程', processAlive(orphan.pid) && (await probeTcp(orphanPort)), `pid=${orphan.pid}`);
  fs.writeFileSync(path.join(reapDir, '.ssh-proxy', 'runtime.json'), JSON.stringify([{ id: 'orphan', pid: orphan.pid, spec, at: Date.now() }]));
  const reapRaw = { tunnels: [{ id: 'orphan', name: 'orphan', localPort: orphanPort, target: '10.0.0.9:80', via: 'deploy@edge.test:22' }] };
  const reapConfigFile = path.join(reapDir, 'tunnels.json');
  fs.writeFileSync(reapConfigFile, JSON.stringify(reapRaw));
  const sup2 = new Supervisor(normalizeConfig(reapRaw, reapConfigFile), { logger: quiet });
  await sup2.init();
  const reaped = await waitFor('遗留 ssh 被回收', async () => !processAlive(orphan.pid) || !(await probeTcp(orphanPort)), 15000);
  check('重启面板时回收上次遗留的 ssh 进程', reaped);
  await sleep(500);
  check('回收后端口已释放', !(await probeTcp(orphanPort)));
  await sup2.shutdown();
  try {
    orphan.kill('SIGKILL');
  } catch {
    /* 已经退出 */
  }

  // ---- 12. 多种登录方式：密码（scrypt 哈希）+ Ed25519 密钥 ----
  const authDir = path.join(TMP, 'auth');
  fs.mkdirSync(authDir, { recursive: true });
  const authFile = path.join(authDir, 'tunnels.json');
  const password = 'correct horse battery staple';
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const sshPub = (pair) => opensshFromRawEd25519(pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64'));

  const authRaw = {
    panel: {
      host: '127.0.0.1',
      port: 0,
      token: '',
      passwordHash: hashPassword(password),
      publicKeys: [{ id: 'k-bootstrap', name: '预置密钥', key: sshPub(keyPair) }],
    },
    tunnels: [],
  };
  fs.writeFileSync(authFile, JSON.stringify(authRaw, null, 2));
  const authConfig = normalizeConfig(authRaw, authFile);
  const authSup = new Supervisor(authConfig, { logger: quiet });
  await authSup.init({ reapOrphans: false });
  const authServer = await createPanelServer({ supervisor: authSup, config: authConfig });
  await new Promise((resolve) => authServer.server.listen(0, '127.0.0.1', resolve));
  const authBase = `http://127.0.0.1:${authServer.server.address().port}`;

  const loginAs = async (body) => {
    const res = await fetch(`${authBase}/api/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const setCookie = (res.headers.getSetCookie?.()[0] || res.headers.get('set-cookie') || '').split(';')[0];
    return { status: res.status, body: await res.json().catch(() => ({})), cookie: setCookie };
  };
  const stateWith = async (cookie) => (await fetch(`${authBase}/api/state`, { headers: cookie ? { cookie } : {} })).status;

  const guestAuth = await (await fetch(`${authBase}/api/session`)).json();
  check('密码与密钥方式都能被发现', guestAuth.methods.includes('password') && guestAuth.methods.includes('key'), JSON.stringify(guestAuth.methods));
  check('游客看不到密钥指纹', guestAuth.authenticated === false && guestAuth.keys.length === 0 && guestAuth.keyCount === 1, `keyCount=${guestAuth.keyCount}`);

  const wrongPassword = await loginAs({ mode: 'password', password: 'nope' });
  check('密码错误返回 401', wrongPassword.status === 401, `status=${wrongPassword.status}`);

  const passwordLogin = await loginAs({ mode: 'password', password });
  check('密码登录成功并拿到会话', passwordLogin.status === 200 && passwordLogin.cookie.startsWith('sshproxy_session='), `status=${passwordLogin.status}`);
  check('密码会话可以访问 API', (await stateWith(passwordLogin.cookie)) === 200);

  // 登录后注册一把新密钥（浏览器里的流程就是这样）
  const pair2 = crypto.generateKeyPairSync('ed25519');
  const registered = await fetch(`${authBase}/api/auth/keys`, {
    method: 'POST',
    headers: { cookie: passwordLogin.cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ name: '第二把密钥', publicKey: sshPub(pair2) }),
  });
  const registeredBody = await registered.json();
  check('登录后可以注册新公钥', registered.status === 200 && Boolean(registeredBody.id), `status=${registered.status}`);
  const savedKeys = JSON.parse(fs.readFileSync(authFile, 'utf8')).panel.publicKeys;
  check('新公钥写进了配置文件', savedKeys.length === 2, `keys=${savedKeys.length}`);
  check('注册后热生效（不用重启）', (await (await fetch(`${authBase}/api/session`)).json()).keyCount === 2);

  // 挑战 + 签名登录
  const challenge = await (await fetch(`${authBase}/api/auth/challenge?keyId=${registeredBody.id}`)).json();
  const sign = (ch, pair) => crypto.sign(null, Buffer.from(ch.challenge, 'base64'), pair.privateKey).toString('base64');
  const keyLogin = await loginAs({ mode: 'key', challengeId: challenge.challengeId, signature: sign(challenge, pair2) });
  check('密钥签名登录成功', keyLogin.status === 200, `status=${keyLogin.status} ${keyLogin.body.error || ''}`);
  check('密钥会话可以访问 API', (await stateWith(keyLogin.cookie)) === 200);
  const replay = await loginAs({ mode: 'key', challengeId: challenge.challengeId, signature: sign(challenge, pair2) });
  check('同一个挑战不能用第二次（防重放）', replay.status === 401, `status=${replay.status}`);

  const badChallenge = await (await fetch(`${authBase}/api/auth/challenge?keyId=${registeredBody.id}`)).json();
  const wrongSignature = crypto.sign(null, Buffer.from('not-the-challenge'), pair2.privateKey).toString('base64');
  const badSigLogin = await loginAs({ mode: 'key', challengeId: badChallenge.challengeId, signature: wrongSignature });
  check('签名对不上返回 401', badSigLogin.status === 401, `status=${badSigLogin.status}`);

  const keyRemoved = await fetch(`${authBase}/api/auth/keys/${registeredBody.id}`, { method: 'DELETE', headers: { cookie: keyLogin.cookie } });
  check('可以删除已注册的密钥', keyRemoved.status === 200, `status=${keyRemoved.status}`);
  const afterRemove = await (await fetch(`${authBase}/api/session`)).json();
  check('删除后只剩一把密钥', afterRemove.keyCount === 1, `keyCount=${afterRemove.keyCount}`);
  check('删掉的密钥不能再申请挑战', (await fetch(`${authBase}/api/auth/challenge?keyId=${registeredBody.id}`)).status === 404);

  // 只配密钥时，不允许把最后一把删掉（否则面板变成开放状态）
  const onlyKeyRaw = { panel: { host: '127.0.0.1', port: 0, publicKeys: [{ id: 'only', name: '唯一密钥', key: sshPub(pair2) }] }, tunnels: [] };
  fs.writeFileSync(authFile, JSON.stringify(onlyKeyRaw, null, 2));
  await fetch(`${authBase}/api/reload`, { method: 'POST', headers: { cookie: keyLogin.cookie } });
  const ch2 = await (await fetch(`${authBase}/api/auth/challenge?keyId=only`)).json();
  const onlyLogin = await loginAs({ mode: 'key', challengeId: ch2.challengeId, signature: sign(ch2, pair2) });
  check('只剩密钥时仍能登录', onlyLogin.status === 200, `status=${onlyLogin.status}`);
  const deleteLast = await fetch(`${authBase}/api/auth/keys/only`, { method: 'DELETE', headers: { cookie: onlyLogin.cookie } });
  check('不允许删掉最后一种登录方式', deleteLast.status === 400, `status=${deleteLast.status}`);

  await authSup.shutdown();
  await authServer.close();

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} 项通过`);
  if (failed.length) {
    console.log('失败项:');
    for (const item of failed) console.log(` - ${item.name} ${item.detail}`);
    console.log(`\n（测试现场保留在 ${TMP}，方便排查）`);
    process.exitCode = 1;
  } else {
    fs.rmSync(TMP, { recursive: true, force: true });
  }
}

main()
  .catch((err) => {
    console.error(`\n测试异常: ${err.stack || err.message}`);
    process.exitCode = 1;
  })
  .finally(() => {
    setTimeout(() => process.exit(process.exitCode || 0), 300).unref();
  });
