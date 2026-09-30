import { connect } from 'cloudflare:sockets';

const CFG = {
  // ─── 身份 ───
  id: 'UUID',                       // ← 部署时需改成你自己的 UUID（标准 36 位带连字符），不要带空格
  // ─── 面板安全 ───
  panelKey: 'admin',                // ← 关卡 1：路由暗号，访问 /?panel=admin 才看到面板，部署时需改
  panelPin: 'mykey123',             // ← 关卡 2：解锁 PIN，必须 ≥8 位，部署时需改
  
  maxED: 8 * 1024,
  concur: 1,
  directLoserTimeout: 1500,
  failTTL: 30_000,
  failCacheMax: 512,
  maxStages: 5,
  dnStall: 30_000,
  memBudget: 96 * 1024 * 1024,
  minPerSession: 4 * 1024 * 1024,
  pathPrefix: '/api/v1/chat',
};

const PROFILES = {
  default: {
    chunk: 64 * 1024,
    dnPack: 32 * 1024,
    dnTail: 512,
    dnQr: 4,
    lowLat: false,
    upPack: 20 * 1024,
    dnHigh: 4 * 1024 * 1024,
    dnLow: 1 * 1024 * 1024,
    stagger: 1200,
    totalTimeout: 6000,
  },
  lowLat: {
    chunk: 16 * 1024,
    dnPack: 2 * 1024,
    dnTail: 64,
    dnQr: 0,
    lowLat: true,
    upPack: 4 * 1024,
    dnHigh: 512 * 1024,
    dnLow: 128 * 1024,
    stagger: 200,
    totalTimeout: 2000,
  },
  highSpeed: {
    chunk: 256 * 1024,
    dnPack: 256 * 1024,
    dnTail: 8 * 1024,
    dnQr: 8,
    lowLat: false,
    upPack: 64 * 1024,
    dnHigh: 8 * 1024 * 1024,
    dnLow: 2 * 1024 * 1024,
    stagger: 2000,
    totalTimeout: 12000,
  },
};

const LL_MAP = {
  '0': 'default',
  '1': 'lowLat',
  '2': 'highSpeed',
};

if (!/^[0-9a-fA-F-]{32,36}$/.test(CFG.id)) {
  throw new Error('CFG.id 未设置或格式错误（应为标准 UUID，如 12345678-1234-1234-1234-123456789abc）');
}
if (!CFG.panelPin || CFG.panelPin.length < 8) {
  throw new Error('CFG.panelPin 必须 ≥8 位');
}
if (CFG.panelPin === 'change-me-to-a-strong-pin-12+chars') {
  throw new Error('CFG.panelPin 未修改，请设置你自己的 PIN');
}
if (!CFG.panelKey) {
  throw new Error('CFG.panelKey 不能为空');
}

let activeSessions = 0;
const getSessionLimit = () => Math.max(
  CFG.minPerSession,
  Math.floor(CFG.memBudget / Math.max(1, activeSessions))
);

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const S5_GREET_NOAUTH = new Uint8Array([5, 1, 0]);
const S5_GREET_AUTH   = new Uint8Array([5, 2, 0, 2]);

const HTTP_TAIL = ENC.encode('User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n');

const VLESS_RESP_V0 = new Uint8Array([0, 0]);
const VLESS_RESP_V1 = new Uint8Array([1, 0]);

const logEvent = (ev, extra) => {
  try {
    console.log(JSON.stringify({ ev, ts: Date.now(), ...extra }));
  } catch {
    console.log(`[${ev}]`, extra);
  }
};

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
  if (o + 3 > c.length) return null;
  const cmd = c[o - 1];
  const p = (c[o] << 8) | c[o + 1];
  const t = c[o + 2];
  const a = parseAddr(c, o + 3, t);
  return a ? { cmd, addrType: t, ...a, port: p } : null;
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
      buf[0] = 1; buf[1] = ub.length; buf.set(ub, 2);
      buf[2 + ub.length] = pb.length; buf.set(pb, 3 + ub.length);
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
  else if (type === 2) { hostBytes = ENC.encode(addressRemote); len = 7 + hostBytes.length; }
  else if (type === 3) len = 22;
  else throw new Error('Unsupported address type');

  const buf = new Uint8Array(len);
  buf[0] = 5; buf[1] = 1; buf[2] = 0;
  let o = 3;
  if (type === 1) {
    buf[o++] = 1;
    const p = addressRemote.split('.');
    buf[o++] = +p[0]; buf[o++] = +p[1]; buf[o++] = +p[2]; buf[o++] = +p[3];
  } else if (type === 2) {
    buf[o++] = 3; buf[o++] = hostBytes.length;
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
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) return i + 4;
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
  req.set(headBytes); req.set(HTTP_TAIL, headBytes.length);

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
      if (!/^HTTP\/1\.[01]\s+2\d\d/.test(status)) throw new Error(`Tunnel refused: ${status}`);
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

    const finish = r => {
      const s = r?.sock ?? r;
      if (settled) { try { s?.close(); } catch {} return; }
      settled = true;
      cleanup();
      resolve(r);
    };

    const launch = () => {
      if (settled) return;
      if (timer) { clearTimeout(timer); timer = 0; }
      if (nextIdx >= stages.length) return;

      const idx = nextIdx++;
      stages[idx]().then(finish, err => {
        if (settled) return;
        logEvent('race_stage_fail', { idx, err: err?.message || String(err) });
        failed++;
        if (failed === stages.length) {
          settled = true;
          cleanup();
          reject(new Error('all outbound stages failed'));
          return;
        }
        launch();
      });

      if (nextIdx < stages.length) timer = setTimeout(launch, staggerMs);
    };

    deadline = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      logEvent('race_timeout', { total: stages.length, failed, launched: nextIdx });
      reject(new Error('happy-eyeballs timeout'));
    }, totalTimeoutMs);

    launch();
  });
};

const connectWithTimeout = (fn, ms, label) => {
  let timedOut = false;
  let timer = 0;
  const p = Promise.resolve().then(fn).then(sock => {
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
  const { globalGW, localSocks, localHttp, gwIP, concur, profile } = strategy;
  const { stagger, totalTimeout } = profile;

  if (globalGW) {
    const fn = globalGW.type === 'S5'
      ? () => s5Connect(addressType, host, port, globalGW.cfg)
      : () => hTunnelConnect(addressType, host, port, globalGW.cfg);
    return connectWithTimeout(fn, totalTimeout, 'globalGW');
  }

  const key = `${host}:${port}`;
  const mkStage = (fn, via) => () => fn().then(sock => ({ sock, via }));

  const directStage = mkStage(() => raceDirect(host, port, concur), 'direct');
  const backupStages = [];
  if (localSocks) backupStages.push(mkStage(() => s5Connect(addressType, host, port, localSocks.cfg), 'backup'));
  if (localHttp)  backupStages.push(mkStage(() => hTunnelConnect(addressType, host, port, localHttp.cfg), 'backup'));
  if (gwIP)       backupStages.push(mkStage(() => sproutIP(gwIP), 'backup'));

  if (!backupStages.length) return (await directStage()).sock;

  const ordered = isFailed(key)
    ? [...backupStages, directStage]
    : [directStage, ...backupStages];

  if (ordered.length > CFG.maxStages) ordered.length = CFG.maxStages;

  try {
    const { sock, via } = await raceHappy(ordered, stagger, totalTimeout);
    if (via === 'direct') FAIL_CACHE.delete(key);
    else markFail(key);
    return sock;
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

const mkDn = (w, profile) => {
  const cap = profile.dnPack;
  const tail = profile.dnTail;
  const maxRetry = profile.dnQr;
  const lowLat = profile.lowLat;
  const low = Math.max(4096, tail * 12);
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
    if (lowLat || maxRetry === 0) return reap();
    tp = setTimeout(() => {
      tp = 0;
      if (k.e()) return;
      if (k.b >= cap || cap - k.b < tail) return reap();
      if (qr < maxRetry && (gen !== qk || k.b < low)) { qr++; qk = gen; return ripen(); }
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

const drainDownstream = async (w, profile) => {
  if (typeof w.bufferedAmount !== 'number' || w.bufferedAmount <= profile.dnHigh) return;
  const t0 = Date.now();
  let delay = 1;
  while (w.bufferedAmount > profile.dnLow) {
    if (w.readyState !== 1) throw new Error('ws closed during drain');
    if (Date.now() - t0 > CFG.dnStall) throw new Error('downstream stalled');
    await new Promise(r => setTimeout(r, delay));
    delay = Math.min(delay * 1.5, 20);
  }
};

const mill = async (rd, w, profile) => {
  const chunkSize = profile.chunk;
  const r = rd.getReader({ mode: 'byob' });
  const tx = mkDn(w, profile);
  let buf = new ArrayBuffer(chunkSize);
  try {
    for (;;) {
      await drainDownstream(w, profile);
      const { done, value: v } = await r.read(new Uint8Array(buf, 0, chunkSize));
      if (done) break;
      if (!v?.byteLength) continue;
      if (v.byteLength >= (chunkSize >> 1)) {
        tx.reap(); w.send(v); buf = new ArrayBuffer(chunkSize);
      } else {
        tx.send(v.slice()); buf = v.buffer;
      }
    }
    tx.reap();
  } catch (e) {
    logEvent('mill_err', { err: e?.message || String(e) });
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
  activeSessions++;
  const ed = parseED(req);

  const profile = strategy.profile;
  const uq = mkQ(profile.upPack);

  let curW = null, sock = null, closed = false, busy = false;

  const wither = () => {
    if (closed) return;
    closed = true;
    activeSessions--;
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
    const limit = getSessionLimit();
    if (uq.b + n > limit) {
      logEvent('maxuq_exceeded', { q: uq.b, n, limit });
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
          if (!r) { logEvent('invalid_vless'); wither(); break; }

          const host = addr(r.addrType, r.targetAddrBytes);
          const port = r.port;

          if (r.cmd !== 1) {
            logEvent('invalid_cmd', { cmd: r.cmd, host, port });
            wither();
            break;
          }

          server.send(d[0] === 0 ? VLESS_RESP_V0 : d[0] === 1 ? VLESS_RESP_V1 : new Uint8Array([d[0], 0]));

          const payload = d.subarray(r.dataOffset);

          try {
            sock = await connectToTarget(host, port, r.addrType, strategy);
            if (!sock) { wither(); break; }

            const pfx = PREFIX_MAP.get(sock);
            if (pfx) { PREFIX_MAP.delete(sock); try { server.send(pfx); } catch {} }

            curW = sock.writable.getWriter();
            if (payload?.byteLength) await curW.write(payload);

            mill(sock.readable, server, profile).finally(() => wither());
          } catch (e) {
            logEvent('connect_fail', { host, port, err: e?.message || String(e) });
            wither();
            break;
          }
          continue;
        }

        const [d] = uq.bundle();
        if (!d) break;
        try { await curW.write(d); }
        catch (e) {
          logEvent('write_fail', { err: e?.message || String(e) });
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
    logEvent('ws_error', { err: e?.message || String(e) });
    wither();
  });
};

const parseStrategy = searchParams => {
  const llRaw = searchParams.get('ll') || '0';
  const profileKey = LL_MAP[llRaw] || 'default';
  const profile = PROFILES[profileKey];

  const s = {
    profile,
    profileKey,
    globalGW: null,
    localSocks: null,
    localHttp: null,
    gwIP: null,
    concur: CFG.concur,
  };

  const rawS5 = searchParams.get('s5');
  if (rawS5) { const p = parseProxyURL(rawS5); if (p && p.type === 'S5') s.localSocks = p; }
  const rawH = searchParams.get('h');
  if (rawH) { const p = parseProxyURL(rawH); if (p && p.type === 'H') s.localHttp = p; }
  const rawG5 = searchParams.get('g5');
  if (rawG5) { const p = parseProxyURL(rawG5); if (p && p.type === 'S5') s.globalGW = p; }
  const rawGH = searchParams.get('gh');
  if (rawGH) { const p = parseProxyURL(rawGH); if (p && p.type === 'H') s.globalGW = p; }

  const ipRaw = searchParams.get('ip') || searchParams.get('proxyip');
  if (ipRaw) {
    const [a, p = 443] = parseAddressPort(ipRaw);
    s.gwIP = { address: a.startsWith('[') ? a.slice(1, -1) : a, port: +p };
  }

  return s;
};

let _encUuid = null;

const getEncryptedUuid = async () => {
  if (_encUuid) return _encUuid;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const keyMat = await crypto.subtle.importKey(
    'raw', ENC.encode(CFG.panelPin), 'PBKDF2', false, ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    ENC.encode(CFG.id)
  );

  const toB64 = u8 => btoa(String.fromCharCode(...u8));
  _encUuid = {
    salt: toB64(salt),
    iv: toB64(iv),
    ct: toB64(new Uint8Array(ct)),
  };
  return _encUuid;
};

const PANEL_INNER_HTML = `<h3>节点生成器</h3>
<div class=meta id=meta></div>
<div class=field><label>代理类型</label><select id=ptype><option value=direct>纯直连</option><option value=ip>proxyip 备用</option><option value=s5>局部 SOCKS5</option><option value=h>局部 HTTP</option><option value=g5>全局 SOCKS5</option><option value=gh>全局 HTTP</option></select></div>
<div id=f-ip class="field collapse"><label>proxyip 地址</label><input id=ip-host type=text placeholder="1.2.3.4:443 或 [2400::1]:443"></div>
<div id=f-proxy class=collapse>
<div class=field><label>粘贴完整链接（自动识别）</label><input id=pr-link type=text placeholder="socks5://user:pass@1.2.3.4:1080"></div>
<div class=field><label>代理服务器</label><input id=pr-host type=text placeholder=1.2.3.4:1080></div>
<div class=row><div class=field><label>用户名</label><input id=pr-user type=text placeholder=可选></div><div class=field><label>密码</label><input id=pr-pass type=text placeholder=可选></div></div></div>
<div class=field><label>节点名称</label><input id=nm type=text value=SuperEdge></div>
<div class=field><label>下行模式</label><select id=ll-mode><option value=0>均衡模式（推荐 · 默认）</option><option value=1>低延迟模式 · ⚠️ 激进</option><option value=2>高速下载模式 · ⚠️ 激进</option></select><div id=ll-hint class=ll-hint></div></div>
<div class=divider><h4>生成结果</h4>
<button id=gen-btn class=gen>生成</button>
<div class=actions><button id=reset-btn class=ghost>重置</button></div>
<div class=out-row><input id=out-path type=text readonly onclick=this.select() placeholder="Path 将在此显示"><button class=sec id=cp-path>复制</button><span class=ok id=ok-path></span></div>
<div class=out-row><input id=out-vless type=text readonly onclick=this.select() placeholder="VLESS 链接将在此显示"><button class=sec id=cp-vless>复制</button><span class=ok id=ok-vless></span></div></div>
<p class=foot><span class=warn>此页面包含你的 UUID，请勿公开分享</span><span class=ver>v1.8.6</span></p>`;

const render502 = (mode, encJson, panelHtmlJson) => {
  const isPanel = mode === 'panel';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>502 Bad Gateway</title>
<style>
:root{--bg:#f1f1f1;--ink:#333;--muted:#999;--line:#e5e7eb;--accent:#e05454;--accent-hover:#c94848;--warn:#f59e0b;--warn-hover:#d97706;--mono:ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:24px;line-height:1.5}
.container{text-align:center;max-width:600px;padding:40px}
h1{font-size:48px;margin:0 0 10px;color:var(--accent);font-weight:600}
h2{font-size:20px;margin:0 0 20px;color:#666;font-weight:400}
p{font-size:14px;color:var(--muted);line-height:1.6}
#trigger{transition:color .2s,font-weight .2s;user-select:none;cursor:${isPanel ? 'pointer' : 'default'}}
${isPanel ? '#trigger:hover{color:var(--accent);font-weight:600;text-decoration:underline}' : ''}
#pn{position:fixed;right:16px;top:16px;width:400px;max-width:calc(100vw - 32px);max-height:calc(100vh - 32px);overflow-y:auto;padding:18px;background:#fff;border-radius:10px;box-shadow:0 6px 28px rgba(0,0,0,.18);border:1px solid var(--line);display:none;text-align:left;font-size:13px;z-index:9999}
#pn h3{margin:0 0 10px;font-size:14px;font-weight:600}
#pn .close{float:right;cursor:pointer;color:#bbb;font-size:20px;line-height:1;user-select:none}
#pn .close:hover{color:#666}
.meta{display:grid;grid-template-columns:auto 1fr;column-gap:10px;row-gap:4px;align-items:baseline;font-size:11px;background:#fafafa;border:1px dashed var(--line);border-radius:5px;padding:8px 10px;margin-bottom:14px}
.meta .k{color:#999;white-space:nowrap}
.meta .v{color:var(--accent);font-family:var(--mono);font-weight:600;word-break:break-all;line-height:1.4}
.field{margin-bottom:12px}
label{display:block;font-size:12px;color:#666;margin-bottom:4px}
input[type=text],input[type=password],select{width:100%;padding:7px 9px;border:1px solid #ddd;border-radius:5px;font-size:12px;font-family:var(--mono);background:#fff;outline:none}
input[type=text]:focus,input[type=password]:focus,select:focus{border-color:var(--accent)}
.row{display:flex;gap:8px}
.row>.field{flex:1}
.collapse{display:none}
.collapse.open{display:block}
.divider{border-top:1px dashed #eee;margin:14px 0;padding-top:12px}
.divider h4{margin:0 0 10px;font-size:13px}
.out-row{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.out-row input{flex:1}
button{padding:7px 12px;border:none;border-radius:5px;background:var(--accent);color:#fff;cursor:pointer;font-size:12px;transition:background .15s}
button:hover{background:var(--accent-hover)}
button.sec{background:#666}
button.sec:hover{background:#555}
button.ghost{background:#fff;color:#666;border:1px solid #ddd}
button.ghost:hover{background:#f5f5f5;color:#333}
button.gen{width:100%;padding:10px 12px;font-size:13px;font-weight:600;margin-bottom:12px}
button.gen.dirty{background:var(--warn)}
button.gen.dirty:hover{background:var(--warn-hover)}
.actions{display:flex;gap:6px;margin-bottom:12px}
.actions button{flex:1}
.ok{color:#2a9d2a;font-size:11px;margin-left:6px}
.foot{margin-top:12px;padding-top:10px;border-top:1px dashed #eee;color:#aaa;font-size:11px;line-height:1.6}
.foot .warn{color:var(--accent);font-weight:600}
.foot .ver{float:right;color:#ccc}
.chk{display:flex;align-items:center;gap:6px;font-size:12px;color:#666}
.chk input{width:auto}
.ll-hint{margin-top:6px;font-size:11px;color:#888;line-height:1.5;padding:6px 8px;background:#fafafa;border-left:2px solid #ddd;border-radius:3px}
.ll-hint.warn{color:#b45309;background:#fffbeb;border-left-color:var(--warn)}
#lock-layer h3{margin:0 0 6px;font-size:14px;font-weight:600;color:var(--accent)}
#lock-layer p{font-size:12px;color:#666;margin:0 0 12px}
#lock-layer .row{display:flex;gap:6px}
#lock-layer input{flex:1}
#lock-layer .err{color:var(--accent);font-size:11px;margin-top:8px;min-height:15px}
</style></head><body>
<div class=container><h1>502</h1><h2>Bad Gateway</h2><p>The server encountered a temporary error and could not complete your request.<br>The client sent an error request to the <span id=trigger>HTTPS</span> server.</p></div>
${isPanel ? `<div id=pn><span class=close id=pnc>&times;</span>
<div id=lock-layer><h3>面板已锁定</h3><p>请输入 PIN 解锁节点生成面板</p>
<div class=row><input id=pin-input type=password placeholder="请输入 PIN" autocomplete=off spellcheck=false><button id=unlock-btn>解锁</button></div>
<div class=err id=lock-err></div></div>
<div id=panel-content></div></div>` : ''}
<script>
${isPanel ? `
var ENC_DATA=${encJson};
var PANEL_HTML=${panelHtmlJson};
var _uuid='';
function b64U8(b){var bin=atob(b),o=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)o[i]=bin.charCodeAt(i);return o}
async function tryDecrypt(pin){var en=new TextEncoder(),salt=b64U8(ENC_DATA.salt),iv=b64U8(ENC_DATA.iv),ct=b64U8(ENC_DATA.ct);var km=await crypto.subtle.importKey('raw',en.encode(pin),'PBKDF2',false,['deriveKey']);var key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);var p=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,ct);return new TextDecoder().decode(p)}
var _pi=false;
function initPanel(){if(_pi)return;_pi=true;var $=function(id){return document.getElementById(id)},GB=$('gen-btn'),dirty=false,TR=0;
var LL_HINT={'0':'均衡模式：通用场景，兼顾延迟与吞吐。推荐作为默认。','1':'⚠️ 激进 · 低延迟模式：适合 SSH / 游戏 / 实时通信。风险：备用路径频繁启动，可能误判慢服务器（2s 超时）。','2':'⚠️ 激进 · 高速下载模式：适合 GooglePlay / AppStore / 网盘下载器。风险：单会话内存约 8MB，建议并发 ≤8。'};
function md(){if(dirty)return;dirty=true;GB.classList.add('dirty');GB.textContent='参数已变更 · 点击更新'}
function cd(){dirty=false;GB.classList.remove('dirty');GB.textContent='生成'}
function pp(r){if(!r)return null;var m=r.match(/^(socks5?|https?):[/]{2}(.+)$/i);if(!m)return null;var pr=m[1].toLowerCase(),rest=m[2],u='',pw='',hp=rest;var at=rest.lastIndexOf('@');if(at!==-1){var a=rest.substring(0,at);hp=rest.substring(at+1);var c=a.indexOf(':');if(c!==-1){u=a.substring(0,c);pw=a.substring(c+1)}else u=a}var h=hp,po='';if(hp.charAt(0)==='['){var cm=hp.match(/^\\[(.+?)\\](?::(\\d+))?$/);if(cm){h='['+cm[1]+']';po=cm[2]||''}}else{var ci=hp.lastIndexOf(':');if(ci!==-1){h=hp.substring(0,ci);po=hp.substring(ci+1)}}return{proto:pr,user:u,pass:pw,host:h,port:po}}
function al(r){var p=pp(r.trim());if(!p)return false;$('pr-host').value=p.host+(p.port?':'+p.port:'');$('pr-user').value=p.user;$('pr-pass').value=p.pass;var s=/socks/.test(p.proto),cu=$('ptype').value,gl=cu==='g5'||cu==='gh';$('ptype').value=gl?(s?'g5':'gh'):(s?'s5':'h');return true}
function gp(){var t=$('ptype').value,ps=['ed=2560'];var ll=$('ll-mode').value;if(ll!=='0')ps.push('ll='+ll);if(t==='ip'){var ip=$('ip-host').value.trim();if(ip)ps.push('ip='+encodeURIComponent(ip))}else if(t==='s5'||t==='h'||t==='g5'||t==='gh'){var h=$('pr-host').value.trim(),u=$('pr-user').value.trim(),pw=$('pr-pass').value.trim();if(h){var pr=t==='s5'||t==='g5'?'socks5://':'http://',a='';if(u&&pw)a=u+':'+pw+'@';else if(u)a=u+'@';ps.push(t+'='+encodeURIComponent(pr+a+h))}}return '${CFG.pathPrefix}?'+ps.join('&')}
function gv(){var h=location.host,u=_uuid,p=gp(),n=$('nm').value||'SuperEdge';if(!u)return 'UUID 未解锁';var q='encryption=none&security=tls&sni='+encodeURIComponent(h)+'&type=ws&host='+encodeURIComponent(h)+'&path='+encodeURIComponent(p);return 'vless://'+u+'@'+h+':443?'+q+'#'+encodeURIComponent(n)}
function dg(){var p=gp(),v=gv();$('out-path').value=p;$('out-vless').value=v;cd()}
function ra(){$('ptype').value='direct';$('ip-host').value='';$('pr-link').value='';$('pr-host').value='';$('pr-user').value='';$('pr-pass').value='';$('nm').value='SuperEdge';$('ll-mode').value='0';uf();uh();dg()}
function uf(){var t=$('ptype').value;$('f-ip').classList.toggle('open',t==='ip');$('f-proxy').classList.toggle('open',t==='s5'||t==='h'||t==='g5'||t==='gh')}
function uh(){var v=$('ll-mode').value,h=$('ll-hint');h.textContent=LL_HINT[v]||'';h.className='ll-hint'+(v==='0'?'':' warn')}
function cf(ii,oi){var el=$(ii),ok=$(oi);if(!el.value)return;var d=function(){ok.textContent='已复制';setTimeout(function(){ok.textContent=''},1500)};if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(el.value).then(d,function(){el.select();document.execCommand('copy');d()});else{el.select();document.execCommand('copy');d()}}
$('ptype').addEventListener('change',function(){uf();md()});
['ip-host','pr-host','pr-user','pr-pass','nm'].forEach(function(id){$(id).addEventListener('input',md)});
$('ll-mode').addEventListener('change',function(){uh();md()});
GB.addEventListener('click',dg);
$('reset-btn').addEventListener('click',ra);
$('pr-link').addEventListener('input',function(){var self=this;clearTimeout(TR);TR=setTimeout(function(){var v=self.value.trim();if(!v)return;if(al(v)){self.value='';uf();dg()}},300)});
$('cp-path').addEventListener('click',function(){cf('out-path','ok-path')});
$('cp-vless').addEventListener('click',function(){cf('out-vless','ok-vless')});
function rm(){$('meta').innerHTML='<div class=k>UUID</div><div class=v>'+(_uuid||'未解锁')+'</div><div class=k>Host</div><div class=v>'+(location.host||'未知')+'</div>'}
uf();uh();rm();dg()}
async function tryUnlock(){var pi=document.getElementById('pin-input'),ee=document.getElementById('lock-err'),pin=pi.value;
if(!pin){ee.textContent='请输入 PIN';return}
if(pin.length<8){ee.textContent='PIN 至少 8 位';return}
ee.textContent='正在验证…';ee.style.color='#666';
try{var uuid=await tryDecrypt(pin);if(!uuid||uuid.length<32)throw new Error('解密结果异常');
_uuid=uuid;
var pc=document.getElementById('panel-content');pc.innerHTML=PANEL_HTML;
document.getElementById('lock-layer').style.display='none';
initPanel()}
catch(e){ee.textContent='PIN 错误，请重试';ee.style.color='#e05454';pi.value='';pi.focus()}}
(function(){var pn=document.getElementById('pn'),tr=document.getElementById('trigger');
function tp(s){pn.style.display=s?'block':'none'}
tr.addEventListener('click',function(){tp(pn.style.display!=='block')});
document.getElementById('pnc').addEventListener('click',function(){tp(false)});
document.getElementById('unlock-btn').addEventListener('click',tryUnlock);
document.getElementById('pin-input').addEventListener('keydown',function(e){if(e.key==='Enter')tryUnlock()});
document.getElementById('pin-input').focus()})();
` : `
(function(){var t=document.getElementById('trigger');if(t){t.addEventListener('click',function(e){e.preventDefault();e.stopPropagation()},true)}})();
`}
</script></body></html>`;
};

let _htmlBare = null;
const getBare502 = () => _htmlBare ||= render502('bare');

let _htmlPanel = null;
const getPanel502 = async () => {
  if (_htmlPanel) return _htmlPanel;
  const enc = await getEncryptedUuid();
  _htmlPanel = render502('panel', JSON.stringify(enc), JSON.stringify(PANEL_INNER_HTML));
  return _htmlPanel;
};

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
      const isPanel = url.searchParams.get('panel') === CFG.panelKey;
      const html = isPanel ? await getPanel502() : getBare502();
      return new Response(html, { status: 502, headers: HTML_HEADERS });
    }

    if (!url.pathname.startsWith(CFG.pathPrefix)) {
      return new Response(getBare502(), { status: 502, headers: HTML_HEADERS });
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