import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import fs from 'node:fs';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));

/** 把 ~ / ~/xxx 展开成真实 home 路径（ssh 的 -i / -o 不一定会自己展开） */
export function expandHome(input) {
  if (typeof input !== 'string' || !input) return input;
  if (input === '~') return os.homedir();
  if (input.startsWith('~/') || input.startsWith('~\\')) return os.homedir() + input.slice(1);
  return input;
}

/** TCP 探活：能建立连接即认为端口可用 */
export function probeTcp(port, host = '127.0.0.1', timeoutMs = 800) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ port: Number(port), host });
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

/** HTTP 探活：拿到 <500 的响应即认为隧道可用 */
export function probeHttp(url, timeoutMs = 2500) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok) => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    let req;
    try {
      const mod = url.startsWith('https:') ? https : http;
      req = mod.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
        res.resume();
        done(Number(res.statusCode) < 500);
      });
    } catch {
      done(false);
      return;
    }
    req.on('timeout', () => {
      req.destroy();
      done(false);
    });
    req.on('error', () => done(false));
  });
}

/** 把流式输出切成整行（同时兜住超长无换行的输出） */
export function makeLineReader(onLine, maxLineLen = 4000) {
  let buf = '';
  return (chunk) => {
    buf += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, '');
      buf = buf.slice(idx + 1);
      if (line.trim()) onLine(line);
    }
    if (buf.length > maxLineLen) {
      onLine(buf.slice(0, maxLineLen));
      buf = '';
    }
  };
}

export function formatDuration(ms) {
  const total = Math.max(0, Math.floor(Number(ms) / 1000));
  if (total < 60) return `${total} 秒`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m < 60) return s ? `${m} 分 ${s} 秒` : `${m} 分`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  if (h < 24) return mm ? `${h} 小时 ${mm} 分` : `${h} 小时`;
  return `${Math.floor(h / 24)} 天 ${h % 24} 小时`;
}

export function readJsonSafe(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
