import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * 开发运行时用项目目录；用 SEA 打成单文件 exe 之后，资源（public/ 等）就放在 exe 旁边。
 * 打包脚本会 define __SEA__ = true，这里只做一次判断。
 */
const SEA_BUILD = typeof __SEA__ !== 'undefined' && Boolean(__SEA__);

function devRoot() {
  try {
    return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  } catch {
    // 打包成 CJS 后 import.meta.url 不存在，走 cwd 兜底（正常不会用到）
    return process.cwd();
  }
}

export function publicDir() {
  return path.join(appRoot(), 'public');
}

/** 应用根目录：开发时是项目目录，SEA 打包后是 exe 所在目录 */
function appRoot() {
  return SEA_BUILD ? path.dirname(process.execPath) : devRoot();
}

/**
 * ssh 的 askpass 小帮手怎么启动：
 *  - 开发：node <项目>/src/cli.mjs --askpass
 *  - SEA ：<exe> --askpass
 */
export function askpassLaunch() {
  if (SEA_BUILD) return { file: process.execPath, args: ['--askpass'] };
  return { file: process.execPath, args: [path.join(appRoot(), 'src', 'cli.mjs'), '--askpass'] };
}
