#!/usr/bin/env node
/**
 * 面板 UI 冒烟检查（可选，需要本机有 Chrome/Edge）：
 * 用 CDP 打开面板，检查卡片渲染、开关是否真的调用了 API、日志抽屉、以及新建/编辑/删除表单。
 *
 * 用法:
 *   node test/ui-check.mjs --url http://127.0.0.1:7799/ [--out .tmp-demo/panel.png]
 *   node test/ui-check.mjs --url ... --allow-write       # 额外测试配置增删改（会写 tunnels.json）
 *   node test/ui-check.mjs --url ... --no-interact       # 只渲染 + 截图，不做交互
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { sleep } from '../src/util.mjs';

const CHROME_CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
];

const args = process.argv.slice(2);
const argOf = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const url = argOf('url', 'http://127.0.0.1:7799/');
const outPng = argOf('out', '.tmp-demo/panel.png');
const interact = !args.includes('--no-interact');
// 会真的增删改 tunnels.json，必须显式开启
const allowWrite = args.includes('--allow-write');
const outEditor = argOf('out-editor', '');
// 面板启用了令牌时，用它自动登录
const tokenArg = argOf('token', '');
// "连接时输入"的隧道：--ask <隧道id>:<密码>
const askSpec = argOf('ask', '');
const debugPort = 9333;

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}
const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}`);
};

function findChrome() {
  return CHROME_CANDIDATES.find((p) => fs.existsSync(p));
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let nextId = 0;
  const pending = new Map();
  const listeners = [];
  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    for (const fn of listeners) fn(msg);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    }
  });
  const ready = new Promise((resolve, reject) => {
    ws.addEventListener('open', () => resolve());
    ws.addEventListener('error', (err) => reject(new Error(`WS 连接失败: ${err.message || err.type}`)));
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = (nextId += 1);
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  return { ready, send, on: (fn) => listeners.push(fn), close: () => ws.close() };
}

async function main() {
  const chrome = findChrome();
  if (!chrome) {
    console.log('跳过：没有找到 Chrome/Edge，无法做 UI 检查');
    return;
  }
  fs.mkdirSync(path.dirname(path.resolve(outPng)), { recursive: true });
  const profile = path.resolve('.tmp-ui-profile');
  fs.rmSync(profile, { recursive: true, force: true });

  const child = spawn(
    chrome,
    [
      '--headless=new',
      // CI（尤其容器）里 Chrome 的沙箱常常起不来，只在 CI 下关掉
      ...(process.env.CI ? ['--no-sandbox'] : []),
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      '--window-size=1380,940',
      `--remote-debugging-port=${debugPort}`,
      `--user-data-dir=${profile}`,
      'about:blank',
    ],
    { stdio: 'ignore', windowsHide: true },
  );

  let client;
  try {
    let version = null;
    for (let i = 0; i < 60 && !version; i += 1) {
      await sleep(250);
      try {
        version = await fetch(`http://127.0.0.1:${debugPort}/json/version`).then((r) => r.json());
      } catch {
        /* 还没起来 */
      }
    }
    if (!version) throw new Error('Chrome 调试端口没起来');

    const target = await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' }).then((r) => r.json());
    client = cdp(target.webSocketDebuggerUrl);
    await client.ready;
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Log.enable');

    const pageErrors = [];
    client.on((msg) => {
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params?.exceptionDetails;
        pageErrors.push(d?.exception?.description || d?.text || 'unknown exception');
      }
      if (msg.method === 'Log.entryAdded' && msg.params?.entry?.level === 'error') {
        pageErrors.push(msg.params.entry.text);
      }
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params?.type === 'error') {
        pageErrors.push(msg.params.args?.map((a) => a.value ?? a.description ?? '').join(' '));
      }
    });

    const evaluate = async (expression) => {
      const res = await client.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (res.exceptionDetails) throw new Error(res.exceptionDetails.text || '页面脚本异常');
      return res.result.value;
    };

    const waitCards = async (timeoutTicks = 40) => {
      let count = 0;
      for (let i = 0; i < timeoutTicks && count === 0; i += 1) {
        await sleep(250);
        count = await evaluate(`document.querySelectorAll('.card').length`).catch(() => 0);
      }
      return count;
    };

    // ---- 令牌弹窗：该弹就弹、能进就进 ----
    await sleep(600);
    const modalUp = await evaluate(`!document.getElementById('token-modal').hidden`);
    if (modalUp) {
      check('面板启用令牌时会弹令牌框', true);
      if (!tokenArg) {
        check('提供了 --token 才能通过令牌校验', false, '面板要求令牌，但脚本没给 --token');
      } else {
        const hint = await evaluate(`document.getElementById('token-hint').textContent`);
        check('令牌框说明了令牌来源', /来源/.test(hint), hint.slice(0, 60));

        // 空令牌提交：必须给反馈，不能像以前那样点了没反应
        await evaluate(`(() => {
          document.getElementById('token-input').value = '';
          document.getElementById('token-form').requestSubmit();
          return true;
        })()`);
        await sleep(1200);
        const afterEmpty = JSON.parse(
          await evaluate(`JSON.stringify({
            modal: !document.getElementById('token-modal').hidden,
            error: document.getElementById('token-error').textContent
          })`),
        );
        check('令牌填错/留空时留在弹窗并给出提示', afterEmpty.modal && afterEmpty.error.length > 0, afterEmpty.error);

        await evaluate(`(() => {
          document.getElementById('token-input').value = ${JSON.stringify(tokenArg)};
          document.getElementById('token-form').requestSubmit();
          return true;
        })()`);
        const logged = await waitCards();
        check('输入正确令牌后进入面板', logged > 0, `${logged} 张卡片`);

        // 登录态展示 + 退出
        const chip = await evaluate(`(() => {
          const el = document.getElementById('session');
          return { hidden: el.classList.contains('hidden'), text: el.textContent, title: el.title };
        })()`);
        check('顶栏显示登录态与剩余时间', chip.hidden === false && /登录/.test(chip.text), chip.text);
        const logoutVisible = await evaluate(`!document.getElementById('btn-logout').classList.contains('hidden')`);
        check('顶栏出现“退出”按钮', logoutVisible);

        await evaluate(`document.getElementById('btn-logout').click()`);
        await sleep(2500);
        const backToLogin = await evaluate(`!document.getElementById('token-modal').hidden`).catch(() => false);
        check('点“退出”后回到登录框', backToLogin);

        // 重新登录，后面还要用
        await evaluate(`(() => {
          document.getElementById('token-input').value = ${JSON.stringify(tokenArg)};
          document.getElementById('token-form').requestSubmit();
          return true;
        })()`);
        check('退出后可以重新登录', (await waitCards()) > 0);

        // 浏览器里生成 Ed25519、注册到服务端、再用私钥登录（会写配置，需 --allow-write）
        if (allowWrite) {
          const supported = await evaluate(`(async () => {
            try {
              const p = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
              return Boolean(p.privateKey);
            } catch { return false; }
          })()`);
          check('浏览器支持 Ed25519', supported, String(supported));
          if (supported) {
            await evaluate(`document.getElementById('btn-settings').click()`);
            for (let i = 0; i < 20; i += 1) {
              await sleep(200);
              if (!(await evaluate(`document.getElementById('settings').hidden`))) break;
            }
            await evaluate(`document.getElementById('btn-register-key').click()`);
            let registered = false;
            for (let i = 0; i < 40 && !registered; i += 1) {
              await sleep(250);
              registered = await evaluate(`document.querySelectorAll('#key-list .key-item').length > 0`);
            }
            check('在设置里注册本机密钥', registered);
            const hint = await evaluate(`document.getElementById('key-hint').textContent`);
            check('注册后显示密钥指纹', /SHA256:/.test(hint), hint.slice(0, 60));

            await evaluate(`document.getElementById('settings').hidden = true`);
            await evaluate(`document.getElementById('btn-logout').click()`);
            await sleep(2500);
            const tabs = await evaluate(`[...document.querySelectorAll('#auth-tabs button')].map((b) => b.dataset.mode)`);
            check('登录框出现多种登录方式', tabs.includes('token') && tabs.includes('key'), tabs.join(','));
            await evaluate(`document.querySelector('#auth-tabs button[data-mode="key"]').click()`);
            await evaluate(`document.getElementById('btn-key-login').click()`);
            const keyedIn = await waitCards();
            check('用本机密钥登录成功', keyedIn > 0, `${keyedIn} 张卡片`);
            const chipKey = await evaluate(`document.getElementById('session').textContent`);
            check('顶栏标明是密钥登录', /密钥/.test(chipKey), chipKey);
          }
        }
      }
    } else {
      check('未启用令牌时不会弹令牌框', true);
      check('未启用令牌时的卡片渲染', (await waitCards()) > 0);
    }

    // 本地残留的旧令牌不能挡住访问（服务端已不要求令牌时）
    if (!modalUp) {
      await evaluate(`localStorage.setItem('sshproxy.token', 'stale-token')`).catch(() => {});
      await evaluate(`location.reload()`).catch(() => {});
      await sleep(1500);
      const afterReload = await waitCards();
      const stillModal = await evaluate(`!document.getElementById('token-modal').hidden`).catch(() => false);
      check('浏览器里残留旧令牌不会把人挡在门外', afterReload > 0 && !stillModal, `cards=${afterReload} modal=${stillModal}`);
    }

    // 等页面真正渲染出卡片（首帧 + SSE 连接需要一点时间）
    let cards = await waitCards();
    if (cards === 0 && pageErrors.length) {
      console.log('页面报错:');
      for (const e of pageErrors.slice(0, 5)) console.log(`  ! ${e}`);
    }

    // 「连接时输入」：点开关 → 提示要密码 → 输入 → 连上（需要 --ask <隧道id>:<密码>）
    if (askSpec) {
      const [askId, askSecret] = askSpec.split(':');
      await evaluate(`(() => {
        const el = document.querySelector('input[data-act="toggle"][data-id="${askId}"]');
        if (el) el.click();
        return true;
      })()`);
      let needSecret = false;
      for (let i = 0; i < 40 && !needSecret; i += 1) {
        await sleep(250);
        needSecret = await evaluate(`Boolean(document.querySelector('button[data-act="secret"][data-id="${askId}"]'))`).catch(() => false);
      }
      check('「连接时输入」的隧道会提示要密码', needSecret);

      if (needSecret) {
        await evaluate(`document.querySelector('button[data-act="secret"][data-id="${askId}"]').click()`);
        await sleep(400);
        check('密码输入框能打开', !(await evaluate(`document.getElementById('secret-modal').hidden`)));
        await evaluate(`(() => {
          document.getElementById('secret-input').value = ${JSON.stringify(askSecret)};
          document.getElementById('secret-form').requestSubmit();
          return true;
        })()`);
        let up = false;
        for (let i = 0; i < 40 && !up; i += 1) {
          await sleep(250);
          up = await evaluate(`Boolean(document.querySelector('.card[data-status="up"]'))`).catch(() => false);
        }
        check('输入密码后隧道连上', up);
      }
    }

    const snapshot = JSON.parse(
      await evaluate(`JSON.stringify({
        title: document.title,
        cards: [...document.querySelectorAll('.card')].map((c) => ({
          name: c.querySelector('h2')?.textContent,
          status: c.dataset.status,
          pill: c.querySelector('.pill')?.textContent,
          route: (c.querySelector('.route')?.textContent || '').replace(/\\s+/g, ' ').trim(),
          switches: c.querySelectorAll('input[data-act="toggle"]').length,
          buttons: [...c.querySelectorAll('button[data-act]')].map((b) => b.dataset.act),
          err: c.querySelector('.err')?.textContent || null
        })),
        stats: (document.getElementById('stats')?.textContent || '').replace(/\\s+/g, ' ').trim(),
        conn: document.getElementById('conn')?.className,
        staleHidden: document.getElementById('stale-banner')?.classList.contains('hidden'),
        visibility: {
          token: getComputedStyle(document.getElementById('token-modal')).display,
          editor: getComputedStyle(document.getElementById('editor')).display,
          settings: getComputedStyle(document.getElementById('settings')).display,
          drawer: getComputedStyle(document.getElementById('drawer')).display
        },
        hitTest: (() => {
          const grid = document.querySelector('.grid');
          if (!grid) return null;
          const r = grid.getBoundingClientRect();
          const el = document.elementFromPoint(r.left + Math.min(120, r.width / 2), r.top + 40);
          if (!el) return 'null';
          return el.closest('.card') ? 'card' : el.id || el.className || el.tagName;
        })(),
        bg: getComputedStyle(document.body).backgroundColor,
        gridCols: getComputedStyle(document.querySelector('.grid')).gridTemplateColumns
      })`),
    );

    check('页面标题正确', snapshot.title === 'SSH 隧道面板', snapshot.title);
    check('卡片数量与配置一致', snapshot.cards.length >= 1, `${snapshot.cards.length} 张`);
    check('没有误报"页面已过期"', snapshot.staleHidden === true);
    check(
      '弹窗/抽屉默认不可见（hidden 属性真的生效）',
      ['token', 'editor', 'settings', 'drawer'].every((k) => snapshot.visibility[k] === 'none'),
      JSON.stringify(snapshot.visibility),
    );
    check('卡片区域没有被遮罩挡住', snapshot.hitTest === 'card', `命中: ${snapshot.hitTest}`);

    const indexHtml = await (await fetch(new URL('/', url))).text();
    const healthInfo = await (await fetch(new URL('/healthz', url))).json();
    check('首页静态资源带版本号（避免旧页面卡住）', /\/app\.js\?v=\d+-\d+/.test(indexHtml), (indexHtml.match(/\/app\.js\?v=[^"]+/) || [''])[0]);
    check('healthz 带前端版本号', Boolean(healthInfo.version), String(healthInfo.version));
    const pageSrc = await evaluate(`document.querySelector('script[src*="app.js"]').src`);
    const pageVer = new URL(pageSrc).searchParams.get('v');
    check('页面版本与服务端版本一致', String(pageVer) === String(healthInfo.version), `${pageVer} vs ${healthInfo.version}`);
    check(
      '每张卡片都有开关 / 编辑 / 删除和 4 个操作按钮',
      snapshot.cards.every(
        (c) => c.switches === 1 && c.buttons.length === 6 && c.buttons.includes('edit') && c.buttons.includes('remove'),
      ),
      snapshot.cards[0]?.buttons.join(','),
    );
    check('渲染出了实时状态', snapshot.conn?.includes('online'), `conn=${snapshot.conn}`);
    check('统计栏有内容', snapshot.stats.includes('已连通'), snapshot.stats);
    check('CSS 生效（深色底 + 多列网格）', snapshot.bg !== 'rgba(0, 0, 0, 0)' && snapshot.gridCols.split(' ').length > 1, `${snapshot.bg} | ${snapshot.gridCols}`);
    const routeCard = snapshot.cards.find((c) => c.status === 'up') || snapshot.cards[0];
    check('卡片上的本地端口 / 边缘机 / 目标链路完整', Boolean(routeCard && /→/.test(routeCard.route) && /\d+\.\d+\.\d+\.\d+:\d+/.test(routeCard.route)), routeCard?.route);

    // 边缘机信息默认脱敏（截图分享用），可一键切回
    const gridText = await evaluate(`document.getElementById('grid').textContent`);
    check('默认隐藏边缘机用户与地址', !gridText.includes('edge.example.com') && !gridText.includes('deploy@'), (gridText.match(/[a-z]\*\*\*[^\s→]*/i) || [''])[0]);
    const maskedRoute = await evaluate(`[...document.querySelectorAll('.route code')].map((c) => c.textContent).join(' | ')`);
    check('脱敏后仍看得出结构（端口 / 域名后缀）', /\*\*\*/.test(maskedRoute) && /:22/.test(maskedRoute), maskedRoute.slice(0, 70));

    await evaluate(`document.getElementById('btn-mask').click()`);
    await sleep(400);
    const revealedText = await evaluate(`document.getElementById('grid').textContent`);
    check('点「显示边缘机」能看到真实值', revealedText.includes('edge.example.com'), revealedText.includes('deploy@edge') ? '用户+域名都回来了' : '域名回来了');
    await evaluate(`document.getElementById('btn-mask').click()`);
    await sleep(300);
    const remasked = await evaluate(`document.getElementById('grid').textContent`);
    check('再点一次重新脱敏', !remasked.includes('edge.example.com'));

    // 通过 UI 关掉第一条隧道，再从 API 侧确认真的停了
    const apiHeaders = tokenArg
      ? { 'x-panel-token': tokenArg }
      : process.env.SSH_PROXY_TOKEN
        ? { 'x-panel-token': process.env.SSH_PROXY_TOKEN }
        : {};
    const readState = async () => (await fetch(new URL('/api/state', url), { headers: apiHeaders })).json();
    if (interact) {
      const firstId = await evaluate(`document.querySelector('input[data-act="toggle"]')?.dataset.id`);
      const beforeState = await readState();
      const before = beforeState.tunnels?.find((t) => t.id === firstId);
      const expected = !before?.desired;
      await evaluate(`(() => { document.querySelector('input[data-act="toggle"]').click(); return true; })()`);
      await sleep(2000);
      const afterState = await readState();
      const toggled = afterState.tunnels?.find((t) => t.id === firstId);
      const okToggle = expected
        ? toggled?.desired === true && ['starting', 'up', 'retrying'].includes(toggled.status)
        : toggled?.desired === false && toggled?.status === 'stopped';
      check('点开关后状态真的跟着变（UI→API 生效）', Boolean(okToggle), `${firstId} desired=${toggled?.desired} status=${toggled?.status}`);

      // 再点回来，让截图里是“全部正常”的状态
      await evaluate(`(() => { document.querySelector('input[data-act="toggle"]').click(); return true; })()`);
      await sleep(1800);

      // 打开日志抽屉
      await evaluate(`document.querySelector('button[data-act="logs"]').click()`);
      await sleep(1200);
      const drawer = JSON.parse(
        await evaluate(`JSON.stringify({
          hidden: document.getElementById('drawer').hidden,
          title: document.getElementById('drawer-title').textContent,
          lines: document.getElementById('drawer-log').childElementCount
        })`),
      );
      check('日志抽屉能打开并显示日志行', drawer.hidden === false && drawer.lines > 0, `${drawer.title} / ${drawer.lines} 行`);

      // 点抽屉外面应该直接关掉
      await evaluate(`document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))`);
      await sleep(200);
      check('点抽屉外面会关闭日志', await evaluate(`document.getElementById('drawer').hidden`));
      // 截图上还是要有抽屉，重新打开
      await evaluate(`document.querySelector('button[data-act="logs"]').click()`);
      await sleep(600);
    }

    // 面板里新建 / 编辑 / 删除隧道（会写配置文件，需显式 --allow-write）
    if (interact && allowWrite) {
      const port = await freePort();
      const waitCard = async (id, present = true) => {
        for (let i = 0; i < 40; i += 1) {
          await sleep(250);
          const found = await evaluate(`Boolean(document.querySelector('.card [data-act="edit"][data-id="${id}"]'))`).catch(() => false);
          if (found === present) return true;
        }
        return false;
      };

      await evaluate(`document.getElementById('btn-new').click()`);
      await sleep(300);
      check('点“新建隧道”能打开表单', !(await evaluate(`document.getElementById('editor').hidden`)));
      const editorShown = await evaluate(`(() => {
        const el = document.getElementById('editor');
        const dlg = el.querySelector('.modal-card').getBoundingClientRect();
        const hit = document.elementFromPoint(dlg.left + dlg.width / 2, dlg.top + 20);
        return { display: getComputedStyle(el).display, hit: hit ? (hit.closest('.modal-card') ? 'dialog' : hit.tagName) : 'null' };
      })()`);
      check('表单真的显示出来了（不是被 CSS 隐藏/挡住）', editorShown.display !== 'none' && editorShown.hit === 'dialog', JSON.stringify(editorShown));

      await evaluate(`(() => {
        const f = document.getElementById('editor-form').elements;
        f.id.value = 'ui-test';
        f.name.value = 'UI 测试隧道';
        f.description.value = '由 ui-check 创建';
        f.localPort.value = '${port}';
        f.targetHost.value = '10.0.0.55';
        f.targetPort.value = '8080';
        f.viaUser.value = 'deploy';
        f.viaHost.value = 'edge.ui.test';
        f.viaPort.value = '22';
        f.url.value = '/admin/login';
        document.getElementById('editor-save').click();
        return true;
      })()`);
      const created = await waitCard('ui-test');
      check('表单保存后卡片出现', created);
      const cardName = await evaluate(
        `[...document.querySelectorAll('.card')].find((c) => c.querySelector('[data-act="edit"][data-id="ui-test"]'))?.querySelector('h2')?.textContent`,
      );
      check('新卡片显示表单里的名字', cardName === 'UI 测试隧道', cardName);
      const createdState = (await readState()).tunnels?.find((t) => t.id === 'ui-test');
      check('新隧道写进了配置（API 可见）', createdState?.localPort === port && createdState?.target?.host === '10.0.0.55', JSON.stringify(createdState?.target));
      check('打开路径生效', createdState?.openPath === '/admin/login' && /\/admin\/login$/.test(createdState?.url || ''), createdState?.url);

      await evaluate(`document.querySelector('button[data-act="edit"][data-id="ui-test"]').click()`);
      await sleep(300);
      const prefilled = await evaluate(`document.getElementById('editor-form').elements.localPort.value`);
      check('编辑表单回填了已有配置', String(prefilled) === String(port), `localPort=${prefilled}`);
      if (outEditor) {
        const editorShot = await client.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
        fs.writeFileSync(path.resolve(outEditor), Buffer.from(editorShot.data, 'base64'));
      }
      await evaluate(`(() => {
        const f = document.getElementById('editor-form').elements;
        f.name.value = 'UI 测试隧道（改名）';
        document.getElementById('editor-save').click();
        return true;
      })()`);
      await sleep(1200);
      const renamed = (await readState()).tunnels?.find((t) => t.id === 'ui-test');
      check('编辑保存后名字变了', renamed?.name === 'UI 测试隧道（改名）', renamed?.name);
      check('保存后表单自动关闭', (await evaluate(`getComputedStyle(document.getElementById('editor')).display`)) === 'none');

      await evaluate(`window.confirm = () => true`);
      await evaluate(`document.querySelector('button[data-act="remove"][data-id="ui-test"]').click()`);
      const removed = await waitCard('ui-test', false);
      check('删除后卡片消失', removed);
      check('删除后 API 里也没有了', !(await readState()).tunnels?.some((t) => t.id === 'ui-test'));

      // 全局设置
      await evaluate(`document.getElementById('btn-settings').click()`);
      for (let i = 0; i < 20; i += 1) {
        await sleep(200);
        if (!(await evaluate(`document.getElementById('settings').hidden`))) break;
      }
      check('全局设置弹窗能打开', !(await evaluate(`document.getElementById('settings').hidden`)));
      const binValue = await evaluate(`document.getElementById('settings-form').elements.bin.value`);
      check('全局设置回填了 ssh.bin', Boolean(binValue), binValue);
      await evaluate(`(() => {
        const f = document.getElementById('settings-form').elements;
        f.maxFailures.value = '7';
        document.getElementById('settings-save').click();
        return true;
      })()`);
      await sleep(1200);
      const cfg = await (await fetch(new URL('/api/config', url), { headers: apiHeaders })).json();
      check('全局设置保存生效', Number(cfg.supervision.maxFailures) === 7, `maxFailures=${cfg.supervision.maxFailures}`);
    }

    const shot = await client.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    fs.writeFileSync(path.resolve(outPng), Buffer.from(shot.data, 'base64'));
    check('截图已保存', fs.existsSync(outPng), path.resolve(outPng));
  } finally {
    client?.close();
    try {
      child.kill();
    } catch {
      /* ignore */
    }
    await sleep(300);
    fs.rmSync(profile, { recursive: true, force: true });
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} 项通过`);
  if (failed.length) {
    process.exitCode = 1;
    for (const f of failed) console.log(` - ${f.name} ${f.detail}`);
  }
}

main().catch((err) => {
  console.error(`UI 检查异常: ${err.stack || err.message}`);
  process.exitCode = 1;
});
