#!/usr/bin/env node
/**
 * 打包成**一个** exe：托盘 + 内嵌的控制器 + 内嵌前端。
 *
 *   node scripts/build-exe.mjs                 # 默认用 Rust 控制器（rust/ 目录，cargo build --release）
 *   node scripts/build-exe.mjs --core=node     # 回退到旧的 Node SEA 控制器（esbuild + postject）
 *   node scripts/build-exe.mjs --no-zip
 *
 * 产物 dist/：
 *   ssh-proxy.exe          ← 就这一个（首次运行会把控制器/前端解包到 %LOCALAPPDATA%\ssh-proxy\runtime\<buildId>）
 *   tunnels.example.json
 *   使用说明.txt
 *   ssh-proxy-portable.zip
 *
 * 两种控制器对托盘壳是同一件事：都是"能 `serve --config <文件> --quiet` / `init --target <文件>` / `version`"的可执行文件。
 */
import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const BUILD = path.join(ROOT, '.build');
const DIST = path.join(ROOT, 'dist');
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const CORE = path.join(BUILD, 'ssh-proxy-core.exe');
const OUT_EXE = path.join(DIST, 'ssh-proxy.exe');
const WEB_FILES = ['index.html', 'app.js', 'style.css'];
const wantsZip = !process.argv.includes('--no-zip');

const log = (msg) => console.log(`\n▶ ${msg}`);
const fail = (msg) => {
  console.error(`\n✖ ${msg}`);
  process.exit(1);
};

function run(file, args, options = {}) {
  const { quietStderr = false, ...rest } = options;
  const result = spawnSync(file, args, {
    stdio: quietStderr ? ['inherit', 'inherit', 'pipe'] : 'inherit',
    cwd: ROOT,
    ...rest,
  });
  if (result.error) fail(`${file} 执行失败: ${result.error.message}`);
  if (result.status !== 0) {
    if (quietStderr && result.stderr) process.stderr.write(result.stderr);
    fail(`${path.basename(file)} 退出码 ${result.status}`);
  }
}

function findCsc() {
  const candidates = [
    'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe',
    'C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe',
  ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) fail('找不到 csc.exe（需要 .NET Framework 4.x，Windows 10/11 自带）');
  return found;
}

/** 控制器实现：默认 rust，可用 --core=node 回退 */
function coreChoice() {
  const flag = process.argv.find((a) => a.startsWith('--core'));
  if (!flag) return 'rust';
  const value = flag.includes('=') ? flag.split('=')[1] : process.argv[process.argv.indexOf('--core') + 1];
  if (value !== 'rust' && value !== 'node') fail(`--core 只能是 rust 或 node（收到 ${value}）`);
  return value;
}

/** 找 cargo：env > 本机手工工具链 > PATH */
function findCargo() {
  const candidates = [
    process.env.CARGO_BIN,
    path.join(process.env.LOCALAPPDATA || '', 'rust-toolchain', '1.100.0', 'bin', 'cargo.exe'),
    'cargo',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (candidate === 'cargo' || fs.existsSync(candidate)) return candidate;
  }
  return fail('找不到 cargo；用 CARGO_BIN 指定，或先安装 Rust 工具链');
}

/** Rust 控制器：cargo build --release，产物复制成 core */
function buildRustCore() {
  log('编译 Rust 控制器（cargo build --release）');
  const cargo = findCargo();
  const rustDir = path.join(ROOT, 'rust');
  run(cargo, ['build', '--release'], { cwd: rustDir });

  // 本机是 gnu 手工工具链（target/<triple>/release），CI 的 windows-latest 是默认 MSVC（target/release）
  const candidates = [
    path.join(rustDir, 'target', 'x86_64-pc-windows-gnu', 'release', 'ssh-proxy.exe'),
    path.join(rustDir, 'target', 'release', 'ssh-proxy.exe'),
  ];
  const built = candidates.find((p) => fs.existsSync(p));
  if (!built) fail(`cargo 说成功了，但没找到产物：${candidates.join(' 或 ')}`);
  fs.copyFileSync(built, CORE);
  const mb = (fs.statSync(CORE).size / 1024 / 1024).toFixed(2);
  console.log(`  ${CORE}  ${mb} MB`);
  return Number(mb);
}

/** Node 控制器（旧路径，留作回退）：esbuild → SEA blob → postject 注入 */
async function buildNodeCore() {
  log('打包 JS（esbuild → 单个 CJS）');
  await build({
    entryPoints: [path.join(ROOT, 'src/cli.mjs')],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    outfile: path.join(BUILD, 'cli.cjs'),
    define: { __SEA__: 'true' },
    logOverride: { 'empty-import-meta': 'silent' },
    banner: { js: '/* bundled by scripts/build-exe.mjs */' },
  });

  log('生成 SEA blob 并注入控制器');
  const seaConfig = path.join(BUILD, 'sea-config.json');
  fs.writeFileSync(
    seaConfig,
    JSON.stringify({ main: path.join(BUILD, 'cli.cjs'), output: path.join(BUILD, 'sea-prep.blob'), disableExperimentalSEAWarning: true }, null, 2),
  );
  run(process.execPath, ['--experimental-sea-config', seaConfig]);

  fs.copyFileSync(process.execPath, CORE);
  const postjectCli = path.join(ROOT, 'node_modules/postject/dist/cli.js');
  if (!fs.existsSync(postjectCli)) fail('找不到 postject，先运行 npm install');
  run(process.execPath, [postjectCli, CORE, 'NODE_SEA_BLOB', path.join(BUILD, 'sea-prep.blob'), '--sentinel-fuse', FUSE], {
    quietStderr: true, // postject 会打一行 "signature seems corrupted"，不是错
  });
  return Number((fs.statSync(CORE).size / 1024 / 1024).toFixed(2));
}

/** 版本号：时间戳，用来区分 %LOCALAPPDATA% 下的解包目录 */
function buildId() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

async function main() {
  log('清理 .build / dist');
  fs.rmSync(BUILD, { recursive: true, force: true });
  fs.rmSync(DIST, { recursive: true, force: true });
  fs.mkdirSync(BUILD, { recursive: true });
  fs.mkdirSync(DIST, { recursive: true });

  const core = coreChoice();
  const coreMb = core === 'rust' ? buildRustCore() : await buildNodeCore();

  log('生成版本信息');
  const id = buildId();
  const infoCs = path.join(BUILD, 'BuildInfo.cs');
  fs.writeFileSync(
    infoCs,
    ['namespace SshProxyTray', '{', '    internal static class BuildInfo', '    {', `        public const string BuildId = "${id}";`, '    }', '}', ''].join('\n'),
  );

  log('编译单文件 exe（托盘 + 内嵌控制器 + 内嵌前端）');
  const csc = findCsc();
  const resources = [`/resource:${CORE},core`].concat(WEB_FILES.map((f) => `/resource:${path.join(ROOT, 'public', f)},web.${f}`));
  run(csc, [
    '/nologo',
    '/target:winexe',
    '/optimize+',
    `/out:${OUT_EXE}`,
    '/r:System.Windows.Forms.dll',
    '/r:System.Drawing.dll',
    ...resources,
    path.join(ROOT, 'tray/TrayApp.cs'),
    infoCs,
  ]);

  log('写示例配置与说明');
  fs.copyFileSync(path.join(ROOT, 'tunnels.example.json'), path.join(DIST, 'tunnels.example.json'));
  fs.writeFileSync(
    path.join(DIST, '使用说明.txt'),
    `\uFEFF${[
      'SSH 隧道面板（单文件版）',
      '',
      '1. 双击 ssh-proxy.exe —— 托盘出现绿色小箭头，控制器在后台跑（没有控制台窗口）。',
      '2. 第一次运行会在本目录生成 tunnels.json；右键托盘 →「编辑 tunnels.json」填边缘机和内网服务。',
      '3. 双击托盘图标（或右键「打开面板」）打开网页面板。',
      '4. 右键菜单：打开面板 / 全部开启 / 全部关闭 / 重载配置 / 打开配置文件夹 / 编辑 tunnels.json / 退出。',
      '',
      '它是怎么跑起来的：',
      `- exe 里内嵌了${core === 'rust' ? ' Rust 控制器' : ' Node 控制器'}（约 ${coreMb} MB）和面板前端；首次运行解包到 %LOCALAPPDATA%\\ssh-proxy\\runtime\\<版本>\\。`,
      '- 之后每次启动直接复用，不会重复解包；升级版本会解到新目录并清掉旧的。',
      '- 你的配置和日志都在 exe 所在目录（tunnels.json / tray-daemon.log / .ssh-proxy\\），删 exe 前先退出托盘。',
      '- 如果 exe 所在目录不可写（比如只读 U 盘），配置会自动放到 %APPDATA%\\ssh-proxy\\。',
      '',
      '卸载：退出托盘 → 删掉 exe 和同目录的 tunnels.json / .ssh-proxy\\ / tray-daemon.log，',
      '      再删 %LOCALAPPDATA%\\ssh-proxy\\ 即可。',
      '',
    ].join('\r\n')}`,
    'utf8',
  );

  const files = fs
    .readdirSync(DIST)
    .filter((f) => fs.statSync(path.join(DIST, f)).isFile())
    .map((f) => `  ${f}  ${(fs.statSync(path.join(DIST, f)).size / 1024 / 1024).toFixed(1)} MB`);
  log('产物');
  for (const line of files) console.log(line);

  if (wantsZip) {
    log('压缩成 zip');
    const zip = path.join(DIST, 'ssh-proxy-portable.zip');
    const ps = spawnSync(
      'powershell',
      ['-NoProfile', '-Command', `Compress-Archive -Path '${DIST}\\*' -DestinationPath '${zip}' -Force`],
      { stdio: 'inherit' },
    );
    if (ps.status !== 0) console.warn('  （压缩失败，不影响 dist 里的产物）');
    else console.log(`  ${zip}  ${(fs.statSync(zip).size / 1024 / 1024).toFixed(1)} MB`);
  }

  console.log(`\n完成（build ${id}）。双击 dist/ssh-proxy.exe 即可。`);
}

main().catch((err) => fail(err.stack || err.message));
