/**
 *  SuperEdge_无注释版 v1.7
 * 【Path 格式】（全部以 /api/v1/chat 开头）
 *   纯直连        : /api/v1/chat?ed=2560
 *   proxyip 备用  : /api/v1/chat?ed=2560&proxyip=1.2.3.4:443
 *   局部 SOCKS5   : /api/v1/chat?ed=2560&token=sg-<B64U of "socks5://user:pass@host:port">
 *   局部 HTTP     : /api/v1/chat?ed=2560&token=sg-<B64U of "http://user:pass@host:port">
 *   全局 SOCKS5   : /api/v1/chat?ed=2560&token=wg-<B64U of "socks5://...">
 *   全局 HTTP     : /api/v1/chat?ed=2560&token=wg-<B64U of "http://...">
 *
 * 【出站优先级】
 *   wg-*   → 单路径全局代理，不 fallback
 *   其他   → Happy Eyeballs：直连 / sg-* / proxyip 按 stagger 梯度并发竞速
 */

import { connect } from 'cloudflare:sockets';

const CFG = {
  id: 'db3f3cbc-ec67-44bc-815c-e358e3cffde8',

  chunk: 64 * 1024,
  dnPack: 32 * 1024,
  dnTail: 512,
  dnQr: 4,
  upPack: 20 * 1024,

  maxED: 8 * 1024,

  concur: 2,
  stagger: 700,
  totalTimeout: 8000,
  directLoserTimeout: 3000,

  maxUQ: 16 * 1024 * 1024,

  pathPrefix: '/api/v1/chat',
};

if (!/^[0-9a-fA-F-]{32,36}$/.test(CFG.id)) {
  throw new Error('CFG.id 未设置或格式错误（应为标准 佑佑ID，如 12345678-1234-1234-1234-123456789abc）');
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const S5_GREET_NOAUTH = new Uint8Array([5, 1, 0]);
const S5_GREET_AUTH   = new Uint8Array([5, 2, 0, 2]);

const HTTP_TAIL = ENC.encode('User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n');

const VLESS_RESP_V0 = new Uint8Array([0, 0]);
const VLESS_RESP_V1 = new Uint8Array([1, 0]);

const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16);
for (let i = 0, p = 0, c, h; i < 16; i++) {
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
  h = hex(c);
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
  idB[i] = (h << 4) | hex(c);
}

const matchID = c => {
  for (let i = 0; i < 16; i++) if (c[1 + i] !== idB[i]) return false;
  return true;
};

const addr = (t, b) => t === 1
  ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
  : t === 2 ? DEC.decode(b)
  : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;

const parseAddr = (b, o, t) => {
  const l = t === 1 ? 4 : t === 2 ? b[o++] : t === 3 ? 16 : null;
  if (l === null) return null;
  const n = o + l;
  return n > b.length ? null : { targetAddrBytes: b.subarray(o, n), dataOffset: n };
};

const relay = c => {
  if (c.length < 24 || !matchID(c)) return null;
  const o = 19 + c[17];
  const p = (c[o] << 8) | c[o + 1];
  const t = c[o + 2];
  const a = parseAddr(c, o + 3, t);
  return a ? { addrType: t, ...a, port: p } : null;
};

const b64urlDecode = str => {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const parseIPv6Into = (s, buf, off) => {
  let str = s.startsWith('[') ? s.slice(1, -1) : s;
  const dbl = str.indexOf('::');
  let head, tail;
  if (dbl >= 0) {
    head = str.slice(0, dbl).split(':').filter(Boolean);
    tail = str.slice(dbl + 2).split(':').filter(Boolean);
  } else {
    head = str.split(':');
    tail = [];
  }
  const groups = [...head];
  while (groups.length < 8 - tail.length) groups.push('0');
  groups.push(...tail);
  for (let i = 0; i < 8; i++) {
    const n = parseInt(groups[i] || '0', 16);
    buf[off + i * 2] = (n >> 8) & 0xff;
    buf[off + i * 2 + 1] = n & 0xff;
  }
};

const parseAddressPort = seg => {
  if (seg.startsWith('[')) {
    const m = seg.match(/^\[(.+?)\]:(\d+)$/);
    return m ? [m[1], +m[2]] : [seg.slice(1, -1), 443];
  }
  const [a, p = 443] = seg.split(':');
  return [a, +p];
};

const parseAuthHost = raw => {
  let username, password, hostPart = raw;
  const at = raw.lastIndexOf('@');
  let authPart = '';
  if (at !== -1) { authPart = raw.substring(0, at); hostPart = raw.substring(at + 1); }

  if (authPart && authPart.includes(':')) {
    [username, password] = authPart.split(':');
  } else if (authPart) {
    try {
      let b64 = authPart.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      const d = atob(b64);
      const p = d.split(':');
      if (p.length === 2) [username, password] = p;
    } catch {}
  }

  const [h, p] = parseAddressPort(hostPart);
  const cfg = { username, password, hostname: h, port: p || 1080 };

  if (username) {
    const ub = ENC.encode(username);
    const pb = ENC.encode(password ?? '');
    if (ub.length > 255 || pb.length > 255) {
      cfg._s5Invalid = true;
    } else {
      const buf = new Uint8Array(3 + ub.length + pb.length);
      buf[0] = 1;
      buf[1] = ub.length;
      buf.set(ub, 2);
      buf[2 + ub.length] = pb.length;
      buf.set(pb, 3 + ub.length);
      cfg._s5Auth = buf;
    }
    cfg._httpAuth = btoa(`${username}:${password ?? ''}`);
  }

  return cfg;
};

const parseProxyURL = raw => {
  if (!raw) return null;
  const m = raw.match(/^(socks5?|https?):\/\/(.+)$/i);
  if (!m) return null;
  const cfg = parseAuthHost(m[2]);
  const scheme = m[1].toLowerCase();
  const type = (scheme.includes('5') || scheme === 'socks') ? 'S5' : 'H';
  return { type, cfg };
};

const tryDecodeToken = str => {
  if (str.includes('://')) return str;
  try { return DEC.decode(b64urlDecode(str)); } catch { return str; }
};

const buildS5Connect = (type, addressRemote, portRemote) => {
  let len, hostBytes = null;
  if (type === 1) len = 10;
  else if (type === 2) {
    hostBytes = ENC.encode(addressRemote);
    len = 7 + hostBytes.length;
  } else if (type === 3) len = 22;
  else throw new Error('Unsupported address type');

  const buf = new Uint8Array(len);
  buf[0] = 5; buf[1] = 1; buf[2] = 0;
  let o = 3;

  if (type === 1) {
    buf[o++] = 1;
    const p = addressRemote.split('.');
    buf[o++] = +p[0]; buf[o++] = +p[1]; buf[o++] = +p[2]; buf[o++] = +p[3];
  } else if (type === 2) {
    buf[o++] = 3;
    buf[o++] = hostBytes.length;
    buf.set(hostBytes, o); o += hostBytes.length;
  } else {
    buf[o++] = 4;
    parseIPv6Into(addressRemote, buf, o); o += 16;
  }

  buf[o++] = (portRemote >> 8) & 0xff;
  buf[o++] = portRemote & 0xff;
  return buf;
};

async function s5Connect(addressType, addressRemote, portRemote, cfg) {
  if (cfg._s5Invalid) throw new Error('S5 auth too long (>255)');
  const { username, hostname, port, _s5Auth } = cfg;

  const sock = connect({ hostname, port });
  if (sock.opened) await sock.opened;

  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    await writer.write(username ? S5_GREET_AUTH : S5_GREET_NOAUTH);
    let resp = (await reader.read()).value;
    if (!resp || resp[1] === 0xff) throw new Error('S5 method rejected');

    if (resp[1] === 2) {
      if (!_s5Auth) throw new Error('S5 requires auth');
      await writer.write(_s5Auth);
      resp = (await reader.read()).value;
      if (!resp || resp[1] !== 0) throw new Error('S5 auth failed');
    } else if (resp[1] !== 0) {
      throw new Error('S5 method not accepted');
    }

    await writer.write(buildS5Connect(addressType, addressRemote, portRemote));
    resp = (await reader.read()).value;
    if (!resp || resp[1] !== 0) throw new Error('S5 connect failed');

    return sock;
  } catch (err) {
    try { sock.close(); } catch {}
    throw err;
  } finally {
    try { writer.releaseLock(); } catch {}
    try { reader.releaseLock(); } catch {}
  }
}

const findHeaderEnd = buf => {
  for (let i = 0; i + 3 < buf.length; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return i + 4;
    }
  }
  return -1;
};

const PREFIX_MAP = new WeakMap();

async function hTunnelConnect(addressType, addressRemote, portRemote, cfg) {
  const { hostname, port, _httpAuth } = cfg;
  const sock = connect({ hostname, port });
  if (sock.opened) await sock.opened;

  const target = `${addressRemote}:${portRemote}`;
  const head = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n` +
    (_httpAuth ? `Proxy-Authorization: Basic ${_httpAuth}\r\n` : '');

  const headBytes = ENC.encode(head);
  const req = new Uint8Array(headBytes.length + HTTP_TAIL.length);
  req.set(headBytes);
  req.set(HTTP_TAIL, headBytes.length);

  const writer = sock.writable.getWriter();
  try { await writer.write(req); }
  finally { try { writer.releaseLock(); } catch {} }

  const reader = sock.readable.getReader();
  let buf = new Uint8Array(0);
  let locked = true;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) throw new Error('Tunnel closed before response');

      const tmp = new Uint8Array(buf.length + value.length);
      tmp.set(buf); tmp.set(value, buf.length);
      buf = tmp;
      if (buf.length > 65536) throw new Error('Tunnel response too large');

      const idx = findHeaderEnd(buf);
      if (idx < 0) continue;

      const status = DEC.decode(buf.subarray(0, idx)).split('\r\n')[0];
      if (!/^HTTP\/1\.[01]\s+2\d\d/.test(status)) {
        throw new Error(`Tunnel refused: ${status}`);
      }

      const leftover = buf.subarray(idx);
      locked = false;
      reader.releaseLock();
      if (leftover.byteLength) PREFIX_MAP.set(sock, leftover);
      return sock;
    }
  } catch (err) {
    if (locked) { try { reader.releaseLock(); } catch {} }
    try { sock.close(); } catch {}
    throw err;
  }
}

const sproutDirect = (h, p) => {
  const s = connect({ hostname: h, port: p });
  return s.opened ? s.opened.then(() => s) : Promise.resolve(s);
};

const raceDirect = (h, p, concur) => {
  if (concur <= 1) return sproutDirect(h, p);
  const ts = Array(concur).fill().map(() => sproutDirect(h, p));
  return Promise.any(ts).then(w => {
    for (const t of ts) {
      let closed = false;
      const closeOnce = s => {
        if (closed || s === w) return;
        closed = true;
        try { s.close(); } catch {}
      };
      t.then(closeOnce, () => { closed = true; });
      setTimeout(() => {
        if (!closed) t.then(closeOnce, () => {});
      }, CFG.directLoserTimeout);
    }
    return w;
  });
};

const sproutIP = async ({ address, port }) => {
  const s = connect({ hostname: address, port });
  if (s.opened) await s.opened;
  return s;
};

const raceHappy = (stages, staggerMs, totalTimeoutMs) => {
  return new Promise((resolve, reject) => {
    let settled = false;
    let failed = 0;
    let nextIdx = 0;
    let timer = 0;
    let deadline = 0;

    const cleanup = () => {
      if (timer) { clearTimeout(timer); timer = 0; }
      if (deadline) { clearTimeout(deadline); deadline = 0; }
    };

    const finish = sock => {
      if (settled) { try { sock.close(); } catch {} return; }
      settled = true;
      cleanup();
      resolve(sock);
    };

    const launch = () => {
      if (settled) return;
      if (timer) { clearTimeout(timer); timer = 0; }
      if (nextIdx >= stages.length) return;

      const idx = nextIdx++;
      stages[idx]().then(finish, () => {
        if (settled) return;
        failed++;
        if (failed === stages.length) {
          settled = true;
          cleanup();
          reject(new Error('all outbound stages failed'));
          return;
        }
        launch();
      });

      if (nextIdx < stages.length) {
        timer = setTimeout(launch, staggerMs);
      }
    };

    deadline = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error('happy-eyeballs timeout'));
    }, totalTimeoutMs);

    launch();
  });
};

const connectToTarget = async (host, port, addressType, strategy) => {
  const { globalGW, localSocks, localHttp, gwIP, concur, stagger, totalTimeout } = strategy;

  if (globalGW) {
    return globalGW.type === 'S5'
      ? await s5Connect(addressType, host, port, globalGW.cfg)
      : await hTunnelConnect(addressType, host, port, globalGW.cfg);
  }

  const stages = [];
  stages.push(() => raceDirect(host, port, concur));
  if (localSocks) stages.push(() => s5Connect(addressType, host, port, localSocks.cfg));
  if (localHttp)  stages.push(() => hTunnelConnect(addressType, host, port, localHttp.cfg));
  if (gwIP)       stages.push(() => sproutIP(gwIP));

  if (stages.length === 1) return stages[0]();
  return raceHappy(stages, stagger, totalTimeout);
};

const mkK = (cap, cpy = 0) => {
  let q = [], h = 0, b = 0, buf = null;
  const e = () => h >= q.length;
  const trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); };
  const clear = () => { q = []; h = 0; b = 0; };
  const take = () => {
    if (e()) return null;
    const d = q[h]; q[h++] = undefined; b -= d.byteLength; trim(); return d;
  };
  const sow = d => {
    const n = d?.byteLength || 0;
    return !n || (q.push(d), b += n, 1);
  };
  const pack = d => {
    d ||= take();
    if (!d || e()) return [d, 0];
    let n = d.byteLength, j = h;
    while (j < q.length) {
      const x = q[j], nn = n + x.byteLength;
      if (nn > cap) break;
      n = nn; j++;
    }
    if (j === h) return [d, 0];
    const out = buf ||= new Uint8Array(cap);
    out.set(d);
    for (let o = d.byteLength; h < j;) {
      const x = q[h]; q[h++] = undefined; b -= x.byteLength;
      out.set(x, o); o += x.byteLength;
    }
    trim();
    const u = out.subarray(0, n);
    return [cpy ? u.slice() : u, 1];
  };
  return { e, get b() { return b; }, clear, take, sow, pack };
};

const mkQ = cap => {
  const k = mkK(cap);
  return {
    get empty() { return k.e(); },
    get b() { return k.b; },
    clear: k.clear,
    sow: k.sow,
    bundle: d => k.pack(d),
  };
};

const mkDn = w => {
  const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail * 12);
  const k = mkK(cap, 1);
  let tp = 0, gen = 0, qk = 0, qr = 0;

  const reap = () => {
    tp && clearTimeout(tp); tp = 0; qr = 0;
    for (;;) {
      const [u] = k.pack();
      if (!u) break;
      w.send(u);
    }
  };

  const ripen = () => {
    if (k.e() || tp) return;
    if (k.b >= cap || cap - k.b < tail) return reap();
    tp = setTimeout(() => {
      tp = 0;
      if (k.e()) return;
      if (k.b >= cap || cap - k.b < tail) return reap();
      if (qr < CFG.dnQr && (gen !== qk || k.b < low)) { qr++; qk = gen; return ripen(); }
      reap();
    }, 1);
  };

  return {
    send(u) {
      let o = 0, n = u?.byteLength || 0;
      if (!n) return;
      while (o < n) {
        const m = Math.min(cap - k.b, n - o);
        if (!m) { reap(); continue; }
        k.sow(o || m !== n ? u.subarray(o, o + m) : u);
        gen++; o += m;
        if (k.b >= cap || cap - k.b < tail) reap();
        else ripen();
      }
    },
    reap,
  };
};

const mill = async (rd, w) => {
  const r = rd.getReader({ mode: 'byob' });
  const tx = mkDn(w);
  let buf = new ArrayBuffer(CFG.chunk);
  try {
    for (;;) {
      const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk));
      if (done) break;
      if (!v?.byteLength) continue;
      if (v.byteLength >= (CFG.chunk >> 1)) {
        tx.reap(); w.send(v); buf = new ArrayBuffer(CFG.chunk);
      } else {
        tx.send(v.slice()); buf = v.buffer;
      }
    }
    tx.reap();
  } catch {} finally {
    try { tx.reap(); } catch {}
    try { r.releaseLock(); } catch {}
  }
};

const parseED = req => {
  const raw = req.headers.get('sec-websocket-protocol') || '';
  if (!raw) return null;
  const list = raw.split(',').map(s => s.trim()).filter(Boolean);
  for (const c of list) {
    if (c.length > CFG.maxED * 4 / 3 + 4) continue;
    try {
      const t = b64urlDecode(c);
      if (t.byteLength <= CFG.maxED) return t;
    } catch {}
  }
  return null;
};

const runSession = (server, req, strategy) => {
  const ed = parseED(req);
  const uq = mkQ(CFG.upPack);
  let curW = null, sock = null, closed = false, busy = false;

  const wither = () => {
    if (closed) return;
    closed = true;
    uq.clear();
    try { curW?.releaseLock(); } catch {}
    try { sock?.close(); } catch {}
    try { server.close(); } catch {}
  };

  const toU8 = d => d instanceof Uint8Array ? d
    : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
    : new Uint8Array(d);

  const sow = d => {
    const u = toU8(d), n = u.byteLength;
    if (!n) return 1;
    if (uq.b + n > CFG.maxUQ) { wither(); return 0; }
    if (uq.sow(u)) return 1;
    wither();
    return 0;
  };

  const thresh = async () => {
    if (busy || closed) return;
    busy = true;
    try {
      for (;;) {
        if (closed) break;

        if (!sock) {
          const [d] = uq.bundle();
          if (!d) break;
          const r = relay(d);
          if (!r) { wither(); break; }

          server.send(d[0] === 0 ? VLESS_RESP_V0 : d[0] === 1 ? VLESS_RESP_V1 : new Uint8Array([d[0], 0]));

          const host = addr(r.addrType, r.targetAddrBytes);
          const port = r.port;
          const payload = d.subarray(r.dataOffset);

          try {
            sock = await connectToTarget(host, port, r.addrType, strategy);
            if (!sock) { wither(); break; }

            const pfx = PREFIX_MAP.get(sock);
            if (pfx) { PREFIX_MAP.delete(sock); try { server.send(pfx); } catch {} }

            curW = sock.writable.getWriter();
            if (payload?.byteLength) await curW.write(payload);

            mill(sock.readable, server).finally(() => wither());
          } catch {
            wither();
            break;
          }
          continue;
        }

        const [d] = uq.bundle();
        if (!d) break;
        try { await curW.write(d); }
        catch { wither(); break; }
      }
    } finally {
      busy = false;
      if (!closed && !uq.empty) queueMicrotask(thresh);
    }
  };

  if (ed && sow(ed)) thresh();

  server.addEventListener('message', e => {
    if (!closed && sow(e.data)) thresh();
  });
  server.addEventListener('close', wither);
  server.addEventListener('error', wither);
};

const parseStrategy = searchParams => {
  const s = {
    globalGW: null,
    localSocks: null,
    localHttp: null,
    gwIP: null,
    concur: CFG.concur,
    stagger: CFG.stagger,
    totalTimeout: CFG.totalTimeout,
  };

  const token = searchParams.get('token');
  if (token && token.length > 3) {
    const prefix = token.slice(0, 3);
    const rest = token.slice(3);
    if (prefix === 'sg-' || prefix === 'wg-') {
      const raw = tryDecodeToken(rest);
      const proxy = parseProxyURL(raw);
      if (proxy) {
        if (prefix === 'sg-') {
          if (proxy.type === 'S5') s.localSocks = proxy;
          else s.localHttp = proxy;
        } else {
          s.globalGW = proxy;
        }
      }
    }
  }

  const ipRaw = searchParams.get('proxyip') || searchParams.get('ip');
  if (ipRaw) {
    const [a, p = 443] = parseAddressPort(ipRaw);
    s.gwIP = { address: a.startsWith('[') ? a.slice(1, -1) : a, port: +p };
  }

  return s;
};

const render502 = b64sid => `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>502 Bad Gateway</title>
<style>
  :root { --bg:#f1f1f1; --ink:#333; --muted:#999; --line:#e5e7eb; --accent:#e05454; --accent-hover:#c94848; --mono: ui-monospace, Menlo, Consolas, monospace; }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--ink); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; padding: 24px; line-height: 1.5; }
  .container { text-align: center; max-width: 600px; padding: 40px; }
  h1 { font-size: 48px; margin: 0 0 10px 0; color: var(--accent); font-weight: 600; }
  h2 { font-size: 20px; margin: 0 0 20px 0; color: #666; font-weight: normal; }
  p { font-size: 14px; color: var(--muted); line-height: 1.6; }
  #trigger { cursor: pointer; transition: color .2s, font-weight .2s; user-select: none; }
  #trigger:hover { color: var(--accent); font-weight: 600; text-decoration: underline; }

  #pn { position: fixed; right: 16px; bottom: 16px; width: 380px; max-width: calc(100vw - 32px); max-height: calc(100vh - 32px); overflow-y: auto; padding: 18px; background: #fff; border-radius: 10px; box-shadow: 0 6px 28px rgba(0,0,0,0.18); border: 1px solid var(--line); display: none; text-align: left; font-size: 13px; z-index: 9999; }
  #pn h3 { margin: 0 0 10px 0; font-size: 14px; font-weight: 600; }
  #pn .close { float: right; cursor: pointer; color: #bbb; font-size: 20px; line-height: 1; user-select: none; }
  #pn .close:hover { color: #666; }
  .meta { font-size: 11px; color: var(--muted); background: #fafafa; border: 1px dashed var(--line); border-radius: 5px; padding: 6px 9px; margin-bottom: 14px; word-break: break-all; }
  .meta b { color: var(--accent); font-weight: 600; }
  .field { margin-bottom: 12px; }
  label { display: block; font-size: 12px; color: #666; margin-bottom: 4px; }
  input[type="text"], select { width: 100%; padding: 7px 9px; border: 1px solid #ddd; border-radius: 5px; font-size: 12px; font-family: var(--mono); background: #fff; outline: none; }
  input[type="text"]:focus, select:focus { border-color: var(--accent); }
  .row { display: flex; gap: 8px; }
  .row > .field { flex: 1; }
  .collapse { display: none; }
  .collapse.open { display: block; }
  .divider { border-top: 1px dashed #eee; margin: 14px 0; padding-top: 12px; }
  .divider h4 { margin: 0 0 2px 0; font-size: 13px; }
  .divider .desc { font-size: 11px; color: var(--muted); margin: 0 0 12px 0; }
  .out-row { display: flex; gap: 6px; align-items: center; margin-bottom: 10px; }
  .out-row input { flex: 1; }
  button { padding: 7px 12px; border: none; border-radius: 5px; background: var(--accent); color: #fff; cursor: pointer; font-size: 12px; }
  button:hover { background: var(--accent-hover); }
  button.sec { background: #666; }
  button.sec:hover { background: #555; }
  .ok { color: #2a9d2a; font-size: 11px; margin-left: 6px; }
  .note { margin-top: 10px; color: #aaa; font-size: 11px; line-height: 1.5; }
  .warn { color: #e05454; font-weight: 600; }
</style>
</head>
<body>
<div class="container">
  <h1>502</h1>
  <h2>Bad Gateway</h2>
  <p>The server encountered a temporary error and could not complete your request.<br>
     The client sent an error request to the <span id="trigger">HTTPS</span> server.</p>
</div>

<div id="pn">
  <span class="close" id="pnc">×</span>
  <h3>节点生成器 · SuperEdge v1.7</h3>

  <div class="meta" id="meta"></div>

  <div class="field">
    <label>代理类型</label>
    <select id="ptype">
      <option value="direct">纯直连</option>
      <option value="proxyip">proxyip 备用</option>
      <option value="sg-socks5">局部 SOCKS5</option>
      <option value="sg-http">局部 HTTP</option>
      <option value="wg-socks5">全局 SOCKS5</option>
      <option value="wg-http">全局 HTTP</option>
    </select>
  </div>

  <div id="f-proxyip" class="field collapse">
    <label>proxyip 地址</label>
    <input id="pi-host" type="text" placeholder="1.2.3.4:443 或 [2400::1]:443">
  </div>

  <div id="f-proxy" class="collapse">
    <div class="field">
      <label>完整代理链接（可选，粘贴后自动填充）</label>
      <input id="pr-link" type="text" placeholder="socks5://user:pass@1.2.3.4:1080 或 http://1.2.3.4:8080">
    </div>
    <div class="field">
      <label>代理地址（host:port）</label>
      <input id="pr-host" type="text" placeholder="1.2.3.4:1080">
    </div>
    <div class="row">
      <div class="field">
        <label>用户名（可选）</label>
        <input id="pr-user" type="text" placeholder="user">
      </div>
      <div class="field">
        <label>密码（可选）</label>
        <input id="pr-pass" type="text" placeholder="pass">
      </div>
    </div>
  </div>

  <div class="field">
    <label>名称</label>
    <input id="nm" type="text" value="SuperEdge v1.7">
  </div>

  <div class="divider">
    <h4>生成结果</h4>
    <p class="desc">输入变化时自动刷新。</p>
    <div class="out-row">
      <input id="out-path" type="text" readonly onclick="this.select()" placeholder="Path 将在此显示">
      <button class="sec" id="cp-path">复制</button>
      <span class="ok" id="ok-path"></span>
    </div>
    <div class="out-row">
      <input id="out-vless" type="text" readonly onclick="this.select()" placeholder="VLESS 链接将在此显示">
      <button class="sec" id="cp-vless">复制</button>
      <span class="ok" id="ok-vless"></span>
    </div>
  </div>

  <p class="note"><span class="warn">请勿公开分享此页面</span>，UUID 已注入。节点配置由服务端自动同步。</p>
</div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var pn = $('pn');

  function togglePanel(show) {
    pn.style.display = show ? 'block' : 'none';
  }
  $('trigger').addEventListener('click', function () {
    togglePanel(pn.style.display !== 'block');
  });
  $('pnc').addEventListener('click', function () { togglePanel(false); });

  var _k = ${JSON.stringify(b64sid)};
  function uuid() {
    try { return atob(_k); } catch (e) { return ''; }
  }

  function renderMeta() {
    var u = uuid();
    $('meta').innerHTML = 'UUID：<b>' + (u || '未设置') + '</b> · Host：<b>' +
      (location.host || '由访问域名自动识别') + '</b>';
  }

  function parseProxyURL(raw) {
    if (!raw) return null;
    var m = raw.match(/^(socks5?|https?):[/]{2}(.+)$/i);
    if (!m) return null;
    var proto = m[1].toLowerCase();
    var rest = m[2];
    var username = '', password = '', hostPart = rest;
    var at = rest.lastIndexOf('@');
    if (at !== -1) {
      var authPart = rest.substring(0, at);
      hostPart = rest.substring(at + 1);
      var c = authPart.indexOf(':');
      if (c !== -1) { username = authPart.substring(0, c); password = authPart.substring(c + 1); }
      else { username = authPart; }
    }
    var host = hostPart, port = '';
    if (hostPart.charAt(0) === '[') {
      var cm = hostPart.match(/^\\[(.+?)\\](?::(\\d+))?$/);
      if (cm) { host = '[' + cm[1] + ']'; port = cm[2] || ''; }
    } else {
      var ci = hostPart.lastIndexOf(':');
      if (ci !== -1) { host = hostPart.substring(0, ci); port = hostPart.substring(ci + 1); }
    }
    return { proto: proto, username: username, password: password, host: host, port: port };
  }

  function applyLink(raw) {
    var p = parseProxyURL(raw.trim());
    if (!p) return false;
    $('pr-host').value = p.host + (p.port ? ':' + p.port : '');
    $('pr-user').value = p.username;
    $('pr-pass').value = p.password;
    var cur = $('ptype').value;
    var scope = (cur.indexOf('sg-') === 0) ? 'sg-' : (cur.indexOf('wg-') === 0 ? 'wg-' : 'sg-');
    $('ptype').value = scope + (/socks/.test(p.proto) ? 'socks5' : 'http');
    return true;
  }

  function b64urlEnc(str) {
    var bytes = new TextEncoder().encode(str);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function genPath() {
    var t = $('ptype').value;
    var params = ['ed=2560'];
    if (t === 'proxyip') {
      var ip = $('pi-host').value.trim();
      if (ip) params.push('proxyip=' + encodeURIComponent(ip));
    } else if (t.indexOf('sg-') === 0 || t.indexOf('wg-') === 0) {
      var host = $('pr-host').value.trim();
      var user = $('pr-user').value.trim();
      var pass = $('pr-pass').value.trim();
      if (host) {
        var prefix = t.slice(0, 3);
        var type = t.slice(3);
        var proto = type === 'socks5' ? 'socks5://' : 'http://';
        var auth = (user && pass) ? (user + ':' + pass + '@') : '';
        var raw = proto + auth + host;
        params.push('token=' + prefix + b64urlEnc(raw));
      }
    }
    return '${CFG.pathPrefix}?' + params.join('&');
  }

  function genVless() {
    var h = location.host;
    var u = uuid();
    var p = genPath();
    var n = $('nm').value || 'SuperEdge v1.7';
    if (!u) return 'UUID 未设置（请与 CFG.id 同步）';
    var q = 'encryption=none&security=tls&sni=' + encodeURIComponent(h) +
            '&type=ws&host=' + encodeURIComponent(h) +
            '&path=' + encodeURIComponent(p);
    return 'vless://' + u + '@' + h + ':443?' + q + '#' + encodeURIComponent(n);
  }

  function update() {
    $('out-path').value = genPath();
    $('out-vless').value = genVless();
  }

  function updateFields() {
    var t = $('ptype').value;
    $('f-proxyip').classList.toggle('open', t === 'proxyip');
    $('f-proxy').classList.toggle('open', t.indexOf('sg-') === 0 || t.indexOf('wg-') === 0);
  }

  function copyFrom(inputId, okId) {
    var el = $(inputId), ok = $(okId);
    if (!el.value) return;
    var done = function () { ok.textContent = '已复制'; setTimeout(function () { ok.textContent = ''; }, 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(el.value).then(done, function () {
        el.select(); document.execCommand('copy'); done();
      });
    } else {
      el.select(); document.execCommand('copy'); done();
    }
  }

  ['ptype', 'pi-host', 'pr-host', 'pr-user', 'pr-pass', 'nm'].forEach(function (id) {
    $(id).addEventListener('input', update);
    $(id).addEventListener('change', function () { updateFields(); update(); });
  });

  $('ptype').addEventListener('change', updateFields);
  $('pr-link').addEventListener('input', function () {
    if (applyLink(this.value)) { updateFields(); update(); }
  });
  $('cp-path').addEventListener('click', function () { copyFrom('out-path', 'ok-path'); });
  $('cp-vless').addEventListener('click', function () { copyFrom('out-vless', 'ok-vless'); });

  updateFields();
  renderMeta();
  update();
})();
</script>
</body>
</html>`;

const HTML_502 = render502(btoa(CFG.id));

const HTML_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

export default {
  async fetch(req) {
    const url = new URL(req.url);

    if (req.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response(HTML_502, { status: 502, headers: HTML_HEADERS });
    }

    if (!url.pathname.startsWith(CFG.pathPrefix)) {
      return new Response(HTML_502, { status: 502, headers: HTML_HEADERS });
    }

    const strategy = parseStrategy(url.searchParams);

    const [client, server] = Object.values(new WebSocketPair());
    server.accept({ allowHalfOpen: true });
    server.binaryType = 'arraybuffer';

    runSession(server, req, strategy);

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'Sec-WebSocket-Extensions': '' },
    });
  }
};
