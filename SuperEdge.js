/**
 *  SuperEdge_无注释版 v1.8.3
 * 【Path 格式】（全部以 /api/v1/chat 开头）
 *   纯直连        : ?ed=2560
 *   proxyip 备用  : ?ed=2560&ip=1.2.3.4:443
 *   局部 SOCKS5   : ?ed=2560&s5=<URL-encoded "socks5://user:pass@host:port">
 *   局部 HTTP     : ?ed=2560&h=<URL-encoded "http://user:pass@host:port">
 *   全局 SOCKS5   : ?ed=2560&g5=<URL-encoded "socks5://user:pass@host:port">
 *   全局 HTTP     : ?ed=2560&gh=<URL-encoded "http://user:pass@host:port">
 *   低延迟模式    : 任意 path 后追加 &ll=1（SSH / 游戏 / 实时交互）
 *
 * 【出站优先级】
 *   g5 / gh → 单路径全局代理，不 fallback（带超时兜底）
 *   其他    → Happy Eyeballs：直连 / s5 / h / ip 按 stagger 梯度并发竞速
 */

import { connect } from 'cloudflare:sockets';

const CFG = {
  id: 'UUID',

  chunk: 64 * 1024,
  dnPack: 32 * 1024,
  dnTail: 512,
  dnQr: 4,
  upPack: 20 * 1024,

  maxED: 8 * 1024,

  concur: 1,
  stagger: 1200,
  totalTimeout: 6000,
  directLoserTimeout: 1500,
  failTTL: 30_000,
  failCacheMax: 512,

  maxUQ: 32 * 1024 * 1024,

  pathPrefix: '/api/v1/chat',

  lowLatPorts: [22, 23, 3389, 5900],
};

if (!/^[0-9a-fA-F-]{32,36}$/.test(CFG.id)) {
  throw new Error('CFG.id 未设置或格式错误（应为标准 UUID，如 12345678-1234-1234-1234-123456789abc）');
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const S5_GREET_NOAUTH = new Uint8Array([5, 1, 0]);
const S5_GREET_AUTH   = new Uint8Array([5, 2, 0, 2]);

const HTTP_TAIL = ENC.encode('User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n');

const VLESS_RESP_V0 = new Uint8Array([0, 0]);
const VLESS_RESP_V1 = new Uint8Array([1, 0]);

const LOW_LAT_PORTS = new Set(CFG.lowLatPorts);

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
  if (at !== -1) {
    const authPart = raw.substring(0, at);
    hostPart = raw.substring(at + 1);
    const colon = authPart.indexOf(':');
    if (colon !== -1) {
      username = authPart.substring(0, colon);
      password = authPart.substring(colon + 1);
    } else {
      username = authPart;
    }
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
      if (t === w) continue;
      t.then(
        s => { if (s !== w) { try { s.close(); } catch {} } },
        () => {}
      );
      Promise.race([
        t.catch(() => null),
        new Promise(r => setTimeout(() => r(null), CFG.directLoserTimeout)),
      ]).then(s => { if (s && s !== w) { try { s.close(); } catch {} } });
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
      stages[idx]().then(finish, err => {
        if (settled) return;
        console.log(`[raceHappy] stage ${idx} failed:`, err?.message || err);
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

const connectWithTimeout = (fn, ms, label) => {
  let timedOut = false;
  let timer = 0;
  const p = Promise.resolve()
    .then(fn)
    .then(sock => {
      if (timedOut) { try { sock.close(); } catch {} throw new Error(`${label} late arrival`); }
      return sock;
    });
  const t = new Promise((_, rej) => {
    timer = setTimeout(() => { timedOut = true; rej(new Error(`${label} timeout`)); }, ms);
  });
  return Promise.race([p, t]).finally(() => { if (timer) clearTimeout(timer); });
};

const FAIL_CACHE = new Map();

const markFail = key => {
  const now = Date.now();
  if (FAIL_CACHE.has(key)) FAIL_CACHE.delete(key);
  else if (FAIL_CACHE.size >= CFG.failCacheMax) {
    const first = FAIL_CACHE.keys().next().value;
    if (first !== undefined) FAIL_CACHE.delete(first);
  }
  FAIL_CACHE.set(key, now + CFG.failTTL);
};

const isFailed = key => {
  const exp = FAIL_CACHE.get(key);
  if (!exp) return false;
  if (exp < Date.now()) { FAIL_CACHE.delete(key); return false; }
  return true;
};

const connectToTarget = async (host, port, addressType, strategy) => {
  const { globalGW, localSocks, localHttp, gwIP, concur, stagger, totalTimeout } = strategy;

  if (globalGW) {
    const fn = globalGW.type === 'S5'
      ? () => s5Connect(addressType, host, port, globalGW.cfg)
      : () => hTunnelConnect(addressType, host, port, globalGW.cfg);
    return connectWithTimeout(fn, totalTimeout, 'globalGW');
  }

  const key = `${host}:${port}`;
  if (isFailed(key)) {
    if (localSocks) return s5Connect(addressType, host, port, localSocks.cfg);
    if (localHttp)  return hTunnelConnect(addressType, host, port, localHttp.cfg);
    if (gwIP)       return sproutIP(gwIP);
  }

  const stages = [];
  stages.push(() => raceDirect(host, port, concur));
  if (localSocks) stages.push(() => s5Connect(addressType, host, port, localSocks.cfg));
  if (localHttp)  stages.push(() => hTunnelConnect(addressType, host, port, localHttp.cfg));
  if (gwIP)       stages.push(() => sproutIP(gwIP));

  try {
    if (stages.length === 1) return await stages[0]();
    return await raceHappy(stages, stagger, totalTimeout);
  } catch (err) {
    markFail(key);
    throw err;
  }
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

const mkDn = (w, lowLat = false) => {
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
    if (lowLat) return reap();
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

const mill = async (rd, w, lowLat = false) => {
  const r = rd.getReader({ mode: 'byob' });
  const tx = mkDn(w, lowLat);
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
  } catch (e) {
    console.log('[mill]', e?.message || e);
  } finally {
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
    if (uq.b + n > CFG.maxUQ) {
      console.log('[session] maxUQ exceeded:', uq.b + n, '>', CFG.maxUQ);
      wither();
      return 0;
    }
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
          if (!r) {
            console.log('[session] invalid VLESS header');
            wither();
            break;
          }

          server.send(d[0] === 0 ? VLESS_RESP_V0 : d[0] === 1 ? VLESS_RESP_V1 : new Uint8Array([d[0], 0]));

          const host = addr(r.addrType, r.targetAddrBytes);
          const port = r.port;
          const payload = d.subarray(r.dataOffset);

          const lowLat = strategy.lowLat || LOW_LAT_PORTS.has(port);

          try {
            sock = await connectToTarget(host, port, r.addrType, strategy);
            if (!sock) { wither(); break; }

            const pfx = PREFIX_MAP.get(sock);
            if (pfx) { PREFIX_MAP.delete(sock); try { server.send(pfx); } catch {} }

            curW = sock.writable.getWriter();
            if (payload?.byteLength) await curW.write(payload);

            mill(sock.readable, server, lowLat).finally(() => wither());
          } catch (e) {
            console.log('[session] connect failed:', e?.message || e);
            wither();
            break;
          }
          continue;
        }

        const [d] = uq.bundle();
        if (!d) break;
        try { await curW.write(d); }
        catch (e) {
          console.log('[session] write failed:', e?.message || e);
          wither();
          break;
        }
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
  server.addEventListener('error', e => {
    console.log('[session] ws error:', e?.message || e);
    wither();
  });
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
    lowLat: false,
  };

  if (searchParams.get('ll') === '1') s.lowLat = true;

  const rawS5 = searchParams.get('s5');
  if (rawS5) {
    const proxy = parseProxyURL(rawS5);
    if (proxy && proxy.type === 'S5') s.localSocks = proxy;
  }

  const rawH = searchParams.get('h');
  if (rawH) {
    const proxy = parseProxyURL(rawH);
    if (proxy && proxy.type === 'H') s.localHttp = proxy;
  }

  const rawG5 = searchParams.get('g5');
  if (rawG5) {
    const proxy = parseProxyURL(rawG5);
    if (proxy && proxy.type === 'S5') s.globalGW = proxy;
  }

  const rawGH = searchParams.get('gh');
  if (rawGH) {
    const proxy = parseProxyURL(rawGH);
    if (proxy && proxy.type === 'H') s.globalGW = proxy;
  }

  const ipRaw = searchParams.get('ip') || searchParams.get('proxyip');
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
  :root { --bg:#f1f1f1; --ink:#333; --muted:#999; --line:#e5e7eb; --accent:#e05454; --accent-hover:#c94848; --warn:#f59e0b; --warn-hover:#d97706; --mono: ui-monospace, Menlo, Consolas, monospace; }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--ink); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; padding: 24px; line-height: 1.5; }
  .container { text-align: center; max-width: 600px; padding: 40px; }
  h1 { font-size: 48px; margin: 0 0 10px 0; color: var(--accent); font-weight: 600; }
  h2 { font-size: 20px; margin: 0 0 20px 0; color: #666; font-weight: normal; }
  p { font-size: 14px; color: var(--muted); line-height: 1.6; }
  #trigger { cursor: pointer; transition: color .2s, font-weight .2s; user-select: none; }
  #trigger:hover { color: var(--accent); font-weight: 600; text-decoration: underline; }

  #pn { position: fixed; right: 16px; top: 16px; width: 400px; max-width: calc(100vw - 32px); max-height: calc(100vh - 32px); overflow-y: auto; padding: 18px; background: #fff; border-radius: 10px; box-shadow: 0 6px 28px rgba(0,0,0,0.18); border: 1px solid var(--line); display: none; text-align: left; font-size: 13px; z-index: 9999; }
  #pn h3 { margin: 0 0 10px 0; font-size: 14px; font-weight: 600; }
  #pn .close { float: right; cursor: pointer; color: #bbb; font-size: 20px; line-height: 1; user-select: none; }
  #pn .close:hover { color: #666; }

  .meta { display: grid; grid-template-columns: auto 1fr; column-gap: 10px; row-gap: 4px; align-items: baseline; font-size: 11px; background: #fafafa; border: 1px dashed var(--line); border-radius: 5px; padding: 8px 10px; margin-bottom: 14px; }
  .meta .k { color: #999; white-space: nowrap; }
  .meta .v { color: var(--accent); font-family: var(--mono); font-weight: 600; word-break: break-all; line-height: 1.4; }

  .field { margin-bottom: 12px; }
  label { display: block; font-size: 12px; color: #666; margin-bottom: 4px; }
  input[type="text"], select { width: 100%; padding: 7px 9px; border: 1px solid #ddd; border-radius: 5px; font-size: 12px; font-family: var(--mono); background: #fff; outline: none; }
  input[type="text"]:focus, select:focus { border-color: var(--accent); }
  .row { display: flex; gap: 8px; }
  .row > .field { flex: 1; }
  .collapse { display: none; }
  .collapse.open { display: block; }
  .divider { border-top: 1px dashed #eee; margin: 14px 0; padding-top: 12px; }
  .divider h4 { margin: 0 0 10px 0; font-size: 13px; }
  .out-row { display: flex; gap: 6px; align-items: center; margin-bottom: 10px; }
  .out-row input { flex: 1; }
  button { padding: 7px 12px; border: none; border-radius: 5px; background: var(--accent); color: #fff; cursor: pointer; font-size: 12px; transition: background .15s; }
  button:hover { background: var(--accent-hover); }
  button.sec { background: #666; }
  button.sec:hover { background: #555; }
  button.ghost { background: #fff; color: #666; border: 1px solid #ddd; }
  button.ghost:hover { background: #f5f5f5; color: #333; }
  button.gen { width: 100%; padding: 10px 12px; font-size: 13px; font-weight: 600; margin-bottom: 12px; }
  button.gen.dirty { background: var(--warn); }
  button.gen.dirty:hover { background: var(--warn-hover); }
  .actions { display: flex; gap: 6px; margin-bottom: 12px; }
  .actions button { flex: 1; }
  .ok { color: #2a9d2a; font-size: 11px; margin-left: 6px; }
  .foot { margin-top: 12px; padding-top: 10px; border-top: 1px dashed #eee; color: #aaa; font-size: 11px; line-height: 1.6; }
  .foot .warn { color: var(--accent); font-weight: 600; }
  .foot .ver { float: right; color: #ccc; }
  .chk { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #666; }
  .chk input { width: auto; }
  #qr-wrap { display: none; margin-top: 12px; padding: 12px; border: 1px dashed var(--line); border-radius: 8px; text-align: center; background: #fafafa; }
  #qr-wrap.show { display: block; }
  #qr-wrap svg { display: block; margin: 0 auto; width: 200px; height: 200px; image-rendering: pixelated; }
  #qr-wrap .qr-note { margin-top: 8px; color: var(--muted); font-size: 11px; }
  #qr-wrap .qr-err { color: var(--accent); font-size: 12px; }
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
  <h3>节点生成器</h3>

  <div class="meta" id="meta"></div>

  <div class="field">
    <label>代理类型</label>
    <select id="ptype">
      <option value="direct">纯直连</option>
      <option value="ip">proxyip 备用</option>
      <option value="s5">局部 SOCKS5</option>
      <option value="h">局部 HTTP</option>
      <option value="g5">全局 SOCKS5</option>
      <option value="gh">全局 HTTP</option>
    </select>
  </div>

  <div id="f-ip" class="field collapse">
    <label>proxyip 地址</label>
    <input id="ip-host" type="text" placeholder="1.2.3.4:443 或 [2400::1]:443">
  </div>

  <div id="f-proxy" class="collapse">
    <div class="field">
      <label>粘贴完整链接（自动识别）</label>
      <input id="pr-link" type="text" placeholder="socks5://user:pass@1.2.3.4:1080">
    </div>
    <div class="field">
      <label>代理服务器</label>
      <input id="pr-host" type="text" placeholder="1.2.3.4:1080">
    </div>
    <div class="row">
      <div class="field">
        <label>用户名</label>
        <input id="pr-user" type="text" placeholder="可选">
      </div>
      <div class="field">
        <label>密码</label>
        <input id="pr-pass" type="text" placeholder="可选">
      </div>
    </div>
  </div>

  <div class="field">
    <label>节点名称</label>
    <input id="nm" type="text" value="SuperEdge">
  </div>

  <div class="field chk">
    <input id="lowlat" type="checkbox">
    <label for="lowlat" style="margin:0;cursor:pointer">低延迟模式 · 适合 SSH / 游戏 / 实时通信</label>
  </div>

  <div class="divider">
    <h4>生成结果</h4>
    <button id="gen-btn" class="gen">生成</button>
    <div class="actions">
      <button id="qr-btn" class="ghost">显示二维码</button>
      <button id="reset-btn" class="ghost">重置</button>
    </div>
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
    <div id="qr-wrap">
      <div id="qr-box"></div>
      <div class="qr-note" id="qr-note">本地生成 · 链接不会上传</div>
    </div>
  </div>

  <p class="foot">
    <span class="warn">此页面包含你的 UUID，请勿公开分享</span>
    <span class="ver">v1.8.3</span>
  </p>
</div>

<script>
var QR = (function () {
  var EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  for (var i = 0, x = 1; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x = (x << 1) ^ ((x & 0x80) ? 0x11D : 0);
  }
  for (var i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  var mul = function (a, b) { return (a && b) ? EXP[LOG[a] + LOG[b]] : 0; };

  function rsEnc(data, n) {
    var g = [1];
    for (var i = 0; i < n; i++) {
      var ng = new Array(g.length + 1).fill(0);
      for (var j = 0; j < g.length; j++) {
        ng[j] ^= mul(g[j], 1);
        ng[j + 1] ^= mul(g[j], EXP[i]);
      }
      g = ng;
    }
    var res = new Array(data.length + n).fill(0);
    for (var i = 0; i < data.length; i++) res[i] = data[i];
    for (var i = 0; i < data.length; i++) {
      var c = res[i];
      if (!c) continue;
      for (var j = 0; j < g.length; j++) res[i + j] ^= mul(g[j], c);
    }
    return res.slice(data.length);
  }

  var V = [
    null,
    [19, [[1, 19]], 7],
    [34, [[1, 34]], 10],
    [55, [[1, 55]], 15],
    [80, [[1, 80]], 20],
    [108, [[1, 108]], 26],
    [136, [[2, 68]], 18],
    [156, [[2, 78]], 20],
    [194, [[2, 97]], 24],
    [232, [[2, 116]], 30],
    [274, [[2, 68], [2, 69]], 18],
    [324, [[4, 81]], 20],
    [370, [[2, 92], [2, 93]], 24],
    [428, [[4, 107]], 26],
    [461, [[3, 115], [1, 116]], 30],
    [523, [[5, 87], [1, 88]], 22],
    [589, [[5, 98], [1, 99]], 24],
    [647, [[1, 107], [5, 108]], 28],
    [721, [[5, 120], [1, 121]], 30],
    [795, [[3, 113], [4, 114]], 28],
    [861, [[3, 107], [5, 108]], 28],
  ];

  var APOS = [
    null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46],
    [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70],
    [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
  ];

  var VINFO = [
    null, null, null, null, null, null, null,
    0x07C94, 0x085BC, 0x09A99, 0x0A4D3, 0x0BBF6, 0x0C762, 0x0D847,
    0x0E60D, 0x0F928, 0x10B78, 0x1145D, 0x12A17, 0x13532, 0x149A6,
  ];

  var FMT = [0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976];

  function encode(text) {
    var bytes = new TextEncoder().encode(text);
    var ver = -1;
    for (var v = 1; v < V.length; v++) {
      var capCW = V[v][0];
      var overhead = 4 + (v < 10 ? 8 : 16);
      if (overhead + bytes.length * 8 <= capCW * 8) { ver = v; break; }
    }
    if (ver < 0) return null;

    var info = V[ver];
    var totalDataCW = info[0];
    var blocks = info[1];
    var ecPerBlock = info[2];

    var bits = [];
    function put(val, n) { for (var i = n - 1; i >= 0; i--) bits.push((val >> i) & 1); }
    put(4, 4);
    put(bytes.length, ver < 10 ? 8 : 16);
    for (var i = 0; i < bytes.length; i++) put(bytes[i], 8);

    var capBits = totalDataCW * 8;
    var term = Math.min(4, capBits - bits.length);
    for (var i = 0; i < term; i++) bits.push(0);
    while (bits.length % 8) bits.push(0);
    var pad = [0xEC, 0x11], pi = 0;
    while (bits.length < capBits) put(pad[pi++ % 2], 8);

    var dataBytes = new Uint8Array(totalDataCW);
    for (var i = 0; i < totalDataCW; i++) {
      var b = 0;
      for (var j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
      dataBytes[i] = b;
    }

    var blkList = [], off = 0;
    for (var bi = 0; bi < blocks.length; bi++) {
      var cnt = blocks[bi][0], blen = blocks[bi][1];
      for (var k = 0; k < cnt; k++) {
        var d = dataBytes.slice(off, off + blen);
        off += blen;
        blkList.push({ data: d, ec: new Uint8Array(rsEnc(Array.from(d), ecPerBlock)) });
      }
    }

    var maxDL = 0;
    for (var i = 0; i < blkList.length; i++) if (blkList[i].data.length > maxDL) maxDL = blkList[i].data.length;
    var inter = [];
    for (var i = 0; i < maxDL; i++) for (var b = 0; b < blkList.length; b++) {
      if (i < blkList[b].data.length) inter.push(blkList[b].data[i]);
    }
    for (var i = 0; i < ecPerBlock; i++) for (var b = 0; b < blkList.length; b++) inter.push(blkList[b].ec[i]);
    return buildMatrix(ver, new Uint8Array(inter));
  }

  function buildMatrix(ver, bytes) {
    var size = ver * 4 + 17;
    var mat = []; for (var i = 0; i < size; i++) mat.push(new Uint8Array(size));
    var res = []; for (var i = 0; i < size; i++) res.push(new Uint8Array(size));

    function placeFinder(r0, c0) {
      for (var dr = -1; dr <= 7; dr++) for (var dc = -1; dc <= 7; dc++) {
        var r = r0 + dr, c = c0 + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        var on =
          (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6)) ||
          (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6)) ||
          (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
        mat[r][c] = on ? 1 : 2;
        res[r][c] = 1;
      }
    }
    placeFinder(0, 0); placeFinder(0, size - 7); placeFinder(size - 7, 0);

    var apos = APOS[ver];
    for (var i = 0; i < apos.length; i++) for (var j = 0; j < apos.length; j++) {
      var r0 = apos[i], c0 = apos[j];
      if ((r0 <= 8 && c0 <= 8) || (r0 <= 8 && c0 >= size - 9) || (r0 >= size - 9 && c0 <= 8)) continue;
      for (var dr = -2; dr <= 2; dr++) for (var dc = -2; dc <= 2; dc++) {
        var on = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
        mat[r0 + dr][c0 + dc] = on ? 1 : 2;
        res[r0 + dr][c0 + dc] = 1;
      }
    }

    for (var i = 8; i < size - 8; i++) {
      mat[6][i] = (i % 2 === 0) ? 1 : 2; res[6][i] = 1;
      mat[i][6] = (i % 2 === 0) ? 1 : 2; res[i][6] = 1;
    }

    mat[size - 8][8] = 1; res[size - 8][8] = 1;

    for (var i = 0; i < 9; i++) { res[8][i] = 1; res[i][8] = 1; }
    for (var i = 0; i < 8; i++) { res[8][size - 1 - i] = 1; res[size - 1 - i][8] = 1; }
    if (ver >= 7) {
      for (var i = 0; i < 6; i++) for (var j = 0; j < 3; j++) {
        res[size - 11 + j][i] = 1;
        res[i][size - 11 + j] = 1;
      }
    }

    var bitIdx = 0, totalBits = bytes.length * 8;
    function getBit(i) { return i < totalBits ? (bytes[i >> 3] >> (7 - (i & 7))) & 1 : 0; }
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vert : vert;
          if (!res[y][x]) mat[y][x] = getBit(bitIdx++) ? 1 : 2;
        }
      }
    }

    var bestMask = 0, bestScore = Infinity;
    for (var mask = 0; mask < 8; mask++) {
      var m = []; for (var i = 0; i < size; i++) m.push(new Uint8Array(mat[i]));
      applyMask(m, mask, res, size);
      placeFormat(m, mask, size);
      if (ver >= 7) placeVersion(m, ver, size);
      var s = evalMask(m, size);
      if (s < bestScore) { bestScore = s; bestMask = mask; }
    }
    var fm = []; for (var i = 0; i < size; i++) fm.push(new Uint8Array(mat[i]));
    applyMask(fm, bestMask, res, size);
    placeFormat(fm, bestMask, size);
    if (ver >= 7) placeVersion(fm, ver, size);
    return fm;
  }

  function applyMask(m, mask, res, size) {
    for (var r = 0; r < size; r++) for (var c = 0; c < size; c++) {
      if (res[r][c]) continue;
      var flip;
      switch (mask) {
        case 0: flip = (r + c) % 2 === 0; break;
        case 1: flip = r % 2 === 0; break;
        case 2: flip = c % 3 === 0; break;
        case 3: flip = (r + c) % 3 === 0; break;
        case 4: flip = (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0; break;
        case 5: flip = (r * c) % 2 + (r * c) % 3 === 0; break;
        case 6: flip = ((r * c) % 2 + (r * c) % 3) % 2 === 0; break;
        case 7: flip = ((r + c) % 2 + (r * c) % 3) % 2 === 0; break;
      }
      if (flip) m[r][c] ^= 3;
    }
  }

  function placeFormat(m, mask, size) {
    var f = FMT[mask];
    for (var i = 0; i <= 5; i++) m[8][i] = ((f >> (14 - i)) & 1) ? 1 : 2;
    m[8][7] = ((f >> 8) & 1) ? 1 : 2;
    m[8][8] = ((f >> 7) & 1) ? 1 : 2;
    m[7][8] = ((f >> 6) & 1) ? 1 : 2;
    for (var i = 0; i <= 5; i++) m[5 - i][8] = ((f >> i) & 1) ? 1 : 2;
    for (var i = 0; i <= 7; i++) m[8][size - 1 - i] = ((f >> (14 - i)) & 1) ? 1 : 2;
    for (var i = 0; i <= 6; i++) m[size - 1 - i][8] = ((f >> i) & 1) ? 1 : 2;
    m[size - 8][8] = 1;
  }

  function placeVersion(m, ver, size) {
    var v = VINFO[ver];
    for (var i = 0; i < 18; i++) {
      var bit = (v >> i) & 1;
      var r = Math.floor(i / 3), c = i % 3;
      m[size - 11 + c][r] = bit ? 1 : 2;
      m[r][size - 11 + c] = bit ? 1 : 2;
    }
  }

  function evalMask(m, size) {
    var score = 0;
    for (var r = 0; r < size; r++) {
      var last = -1, run = 0;
      for (var c = 0; c < size; c++) {
        if (m[r][c] === last) run++;
        else { if (run >= 5) score += run - 2; last = m[r][c]; run = 1; }
      }
      if (run >= 5) score += run - 2;
    }
    for (var c = 0; c < size; c++) {
      var last = -1, run = 0;
      for (var r = 0; r < size; r++) {
        if (m[r][c] === last) run++;
        else { if (run >= 5) score += run - 2; last = m[r][c]; run = 1; }
      }
      if (run >= 5) score += run - 2;
    }
    return score;
  }

  function toSVG(mat) {
    var size = mat.length;
    var path = '';
    for (var r = 0; r < size; r++) for (var c = 0; c < size; c++) {
      if (mat[r][c] === 1) path += 'M' + c + ' ' + r + 'h1v1h-1z';
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" shape-rendering="crispEdges">' +
      '<rect width="' + size + '" height="' + size + '" fill="#fff"/>' +
      '<path d="' + path + '" fill="#000"/></svg>';
  }

  return {
    render: function (text) {
      var mat = encode(text);
      if (!mat) return null;
      return toSVG(mat);
    }
  };
})();

(function () {
  var $ = function (id) { return document.getElementById(id); };
  var pn = $('pn');
  var genBtn = $('gen-btn');
  var qrBtn = $('qr-btn');
  var dirty = false;
  var qrVisible = false;
  var lastVless = '';

  function togglePanel(show) { pn.style.display = show ? 'block' : 'none'; }
  $('trigger').addEventListener('click', function () {
    togglePanel(pn.style.display !== 'block');
  });
  $('pnc').addEventListener('click', function () { togglePanel(false); });

  var _k = ${JSON.stringify(b64sid)};
  function uuid() { try { return atob(_k); } catch (e) { return ''; } }

  function renderMeta() {
    var u = uuid() || '未设置';
    var h = location.host || '未知';
    $('meta').innerHTML =
      '<div class="k">UUID</div><div class="v">' + u + '</div>' +
      '<div class="k">Host</div><div class="v">' + h + '</div>';
  }

  function markDirty() {
    if (dirty) return;
    dirty = true;
    genBtn.classList.add('dirty');
    genBtn.textContent = '参数已变更 · 点击更新';
  }

  function clearDirty() {
    dirty = false;
    genBtn.classList.remove('dirty');
    genBtn.textContent = '生成';
  }

  function parseProxyURL(raw) {
    if (!raw) return null;
    var m = raw.match(/^(socks5?|https?):[/]{2}(.+)$/i);
    if (!m) return null;
    var proto = m[1].toLowerCase();
    var rest = m[2];
    var user = '', pass = '', hostPart = rest;
    var at = rest.lastIndexOf('@');
    if (at !== -1) {
      var authPart = rest.substring(0, at);
      hostPart = rest.substring(at + 1);
      var c = authPart.indexOf(':');
      if (c !== -1) { user = authPart.substring(0, c); pass = authPart.substring(c + 1); }
      else { user = authPart; }
    }
    var host = hostPart, port = '';
    if (hostPart.charAt(0) === '[') {
      var cm = hostPart.match(/^\\[(.+?)\\](?::(\\d+))?$/);
      if (cm) { host = '[' + cm[1] + ']'; port = cm[2] || ''; }
    } else {
      var ci = hostPart.lastIndexOf(':');
      if (ci !== -1) { host = hostPart.substring(0, ci); port = hostPart.substring(ci + 1); }
    }
    return { proto: proto, user: user, pass: pass, host: host, port: port };
  }

  function applyLink(raw) {
    var p = parseProxyURL(raw.trim());
    if (!p) return false;
    $('pr-host').value = p.host + (p.port ? ':' + p.port : '');
    $('pr-user').value = p.user;
    $('pr-pass').value = p.pass;
    var isSocks = /socks/.test(p.proto);
    var cur = $('ptype').value;
    var isGlobal = (cur === 'g5' || cur === 'gh');
    $('ptype').value = isGlobal
      ? (isSocks ? 'g5' : 'gh')
      : (isSocks ? 's5' : 'h');
    return true;
  }

  function genPath() {
    var t = $('ptype').value;
    var params = ['ed=2560'];
    if ($('lowlat').checked) params.push('ll=1');
    if (t === 'ip') {
      var ip = $('ip-host').value.trim();
      if (ip) params.push('ip=' + encodeURIComponent(ip));
    } else if (t === 's5' || t === 'h' || t === 'g5' || t === 'gh') {
      var host = $('pr-host').value.trim();
      var user = $('pr-user').value.trim();
      var pass = $('pr-pass').value.trim();
      if (host) {
        var proto = (t === 's5' || t === 'g5') ? 'socks5://' : 'http://';
        var auth = '';
        if (user && pass) auth = user + ':' + pass + '@';
        else if (user) auth = user + '@';
        params.push(t + '=' + encodeURIComponent(proto + auth + host));
      }
    }
    return '${CFG.pathPrefix}?' + params.join('&');
  }

  function genVless() {
    var h = location.host;
    var u = uuid();
    var p = genPath();
    var n = $('nm').value || 'SuperEdge';
    if (!u) return 'UUID 未设置（请与 CFG.id 同步）';
    var q = 'encryption=none&security=tls&sni=' + encodeURIComponent(h) +
            '&type=ws&host=' + encodeURIComponent(h) +
            '&path=' + encodeURIComponent(p);
    return 'vless://' + u + '@' + h + ':443?' + q + '#' + encodeURIComponent(n);
  }

  function updateQR() {
    var box = $('qr-box');
    var note = $('qr-note');
    if (!qrVisible) return;
    if (!lastVless) { box.innerHTML = ''; note.className = 'qr-err'; note.textContent = '请先生成 VLESS 链接'; return; }
    var svg;
    try { svg = QR.render(lastVless); } catch (e) { svg = null; }
    if (!svg) {
      box.innerHTML = '';
      note.className = 'qr-err';
      note.textContent = '链接过长，超出内置二维码容量上限（约 660 字节）';
    } else {
      box.innerHTML = svg;
      note.className = 'qr-note';
      note.textContent = '本地生成 · 链接不会上传';
    }
  }

  function doGenerate() {
    var path = genPath();
    var vless = genVless();
    $('out-path').value = path;
    $('out-vless').value = vless;
    lastVless = vless;
    clearDirty();
    updateQR();
  }

  function resetAll() {
    $('ptype').value = 'direct';
    $('ip-host').value = '';
    $('pr-link').value = '';
    $('pr-host').value = '';
    $('pr-user').value = '';
    $('pr-pass').value = '';
    $('nm').value = 'SuperEdge';
    $('lowlat').checked = false;
    updateFields();
    doGenerate();
  }

  function updateFields() {
    var t = $('ptype').value;
    $('f-ip').classList.toggle('open', t === 'ip');
    $('f-proxy').classList.toggle('open', t === 's5' || t === 'h' || t === 'g5' || t === 'gh');
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

  $('ptype').addEventListener('change', function () { updateFields(); markDirty(); });

  ['ip-host', 'pr-host', 'pr-user', 'pr-pass', 'nm'].forEach(function (id) {
    $(id).addEventListener('input', markDirty);
  });
  $('lowlat').addEventListener('change', markDirty);

  genBtn.addEventListener('click', doGenerate);
  $('reset-btn').addEventListener('click', resetAll);

  qrBtn.addEventListener('click', function () {
    qrVisible = !qrVisible;
    $('qr-wrap').classList.toggle('show', qrVisible);
    qrBtn.textContent = qrVisible ? '隐藏二维码' : '显示二维码';
    if (qrVisible) {
      if (!lastVless) doGenerate();
      else updateQR();
    }
  });

  var _prTimer = 0;
  $('pr-link').addEventListener('input', function () {
    var self = this;
    clearTimeout(_prTimer);
    _prTimer = setTimeout(function () {
      var v = self.value.trim();
      if (!v) return;
      if (applyLink(v)) {
        self.value = '';
        updateFields();
        doGenerate();
      }
    }, 300);
  });

  $('cp-path').addEventListener('click', function () { copyFrom('out-path', 'ok-path'); });
  $('cp-vless').addEventListener('click', function () { copyFrom('out-vless', 'ok-vless'); });

  updateFields();
  renderMeta();
  doGenerate();
})();
</script>
</body>
</html>`;

let _html502 = null;
const get502 = () => _html502 ||= render502(btoa(CFG.id));

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
      return new Response(get502(), { status: 502, headers: HTML_HEADERS });
    }

    if (!url.pathname.startsWith(CFG.pathPrefix)) {
      return new Response(get502(), { status: 502, headers: HTML_HEADERS });
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
