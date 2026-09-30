# SuperEdge v1.8.7

> 部署在 Cloudflare Workers 上的轻量级 VLESS-over-WebSocket 节点服务

[![Version](https://img.shields.io/badge/version-v1.8.7-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Cloudflare%20Workers-orange.svg)]()
[![License](https://img.shields.io/badge/license-Personal%20Use-lightgrey.svg)]()

特别说明：v1.8.7 版本在高速下载时更保守。对于单用户极限下载，v1.8.6 版本可能略微激进一点；但对于多人长期使用，v1.8.7 版本更稳。

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [参数详解](#参数详解)
- [性能特性](#性能特性)
- [安全设计](#安全设计)
- [版本历史](#版本历史)
- [注意事项](#注意事项)

---

## 项目简介

**SuperEdge** 是一个部署在 **Cloudflare Workers** 上的轻量级 **VLESS-over-WebSocket** 节点服务。它将 Cloudflare 的边缘网络作为代理入口，把 VLESS 协议封装在 WebSocket 之上，利用 Workers 的全球分布特性，为客户端提供低延迟、高可用的代理通道。

### 核心定位

> 一个 5 分钟部署、单文件、零依赖的 VLESS-WS 节点，附带双层安全面板与三档性能模式。

### 不追求

- ❌ 多协议支持（Trojan / VMess / Shadowsocks）
- ❌ 用户管理 / 流量统计 / 订阅系统
- ❌ 复杂的插件架构

### 适合

- ✅ 个人 / 小团队（5-20 人）
- ✅ 家庭 / 跨境访问 / 开发调试
- ✅ 需要快速搭建、无运维成本的场景

---

## 核心特性

### 1. VLESS over WebSocket

- 标准 VLESS 协议，兼容 Xray / Sing-box / v2rayN / Clash Meta 等主流客户端
- WebSocket 封装，天然穿透 HTTP/CDN 层
- Early Data 支持，首包零往返
- 命令字校验，拒绝 UDP / Mux 等非 TCP 请求

### 2. 三种出站策略

| 策略 | 说明 |
|---|---|
| **纯直连** | Worker 直接连接目标服务器 |
| **proxyip 备用** | 直连失败时切换到指定 IP 中转 |
| **SOCKS5 / HTTP 代理** | 支持局部（仅失败时用）和全局（所有流量走代理） |

### 3. Happy Eyeballs 竞速

多条出站路径按时间梯度并发启动：

```
t=0          直连
t=stagger    启动 SOCKS5
t=2×stagger  启动 HTTP
t=3×stagger  启动 proxyip
```

任一路径先成功即采用，其余静默关闭。避免"串行等待"造成的延迟累积。

### 4. 三档下行模式

通过 URL 参数 `&ll=0/1/2` 切换：

| 模式 | 适用场景 | 特点 |
|---|---|---|
| **ll=0 均衡（默认）** | 通用 | 兼顾延迟与吞吐 |
| **ll=1 低延迟** | SSH / 游戏 / 实时通信 | 关合并、快切换、2s 超时 |
| **ll=2 高速下载** | GooglePlay / AppStore / 网盘 | 大缓冲、高吞吐、12s 容忍 |

### 5. 双层安全面板

- **关卡 1（路由）**：`?panel=<panelKey>` 才下发含面板的页面
- **关卡 2（加密）**：PIN 经 PBKDF2 → AES-GCM 解密 UUID

未解锁时：

- 源码中无 UUID 明文
- 面板 DOM 不存在
- 扫描器盲扫一无所获

### 6. 资源保护

| 机制 | 作用 |
|---|---|
| **下行背压** | 客户端慢时暂停读目标，避免内存堆积 |
| **上行动态上限** | 按活跃会话数分摊 96MB 内存预算 |
| **失败缓存** | 30s TTL + 128 条 LRU，避免重复竞速 |
| **全局超时** | 连接失败快速返回，不挂死 |

---

## 技术架构

```
┌────────────────────────────────────────────────────────────┐
│  客户端（Xray / Sing-box / v2rayN / Clash Meta）            │
│       ↓ VLESS over WebSocket (TLS)                          │
│  Cloudflare 边缘网络                                         │
│       ↓ 路由到 Worker isolate                                │
│  ┌──────────────────────────────────────────────────┐      │
│  │  Worker（本代码）                                  │      │
│  │    ├─ 入口：WebSocket 握手 / 502 页面              │      │
│  │    ├─ 协议层：VLESS 头解析 / UUID 校验             │      │
│  │    ├─ 会话层：打包引擎 / 上下行队列 / 背压         │      │
│  │    └─ 出站层：直连 / SOCKS5 / HTTP / proxyip       │      │
│  └──────────────────────────────────────────────────┘      │
│       ↓ TCP（Cloudflare Sockets API）                       │
│  目标服务器                                                  │
└────────────────────────────────────────────────────────────┘
```

### 技术栈

- **Cloudflare Workers** — 边缘运行时
- **`cloudflare:sockets`** — TCP 连接 API
- **WebSocket Pair** — 原生 WebSocket 支持
- **Web Crypto API** — AES-GCM / PBKDF2

### 单文件部署

整个项目就是一个 `.js` 文件，**无需构建、无需依赖、无需 npm**。

---

## 快速开始

### 步骤 1：获取代码

复制完整的 v1.8.7 源码（`SuperEdge_v1.8.7.js`）。

### 步骤 2：修改配置

打开代码头部 `CFG` 对象，修改 3 个字段：

```javascript
const CFG = {
  id: '你的UUID',              // ← 标准 36 位 UUID，带连字符
  panelKey: '你的面板暗号',     // ← 随机字符串，如 'p-a1b2c3d4'
  panelPin: '你的强PIN',        // ← ≥8 位非字典组合，如 'Xk9#mP2$'
  // 其他保持默认
};
```

#### 生成 UUID

```bash
# Linux / macOS
uuidgen

# 或在线工具
# https://www.uuidgenerator.net/
```

#### 强 PIN 建议

- ✅ 大小写字母 + 数字 + 符号
- ✅ 不在常见字典中
- ✅ 例：`Blue#7Fox` / `cat$Rain9` / `M7!kQ2p`

- ❌ 不要用 `mykey123` / `admin` / `12345678` 这类弱值

### 步骤 3：部署到 Workers

#### 方式 A：Cloudflare 控制台

1. 登录 [dash.cloudflare.com](https://dash.cloudflare.com)
2. **Workers & Pages** → **Create** → **Worker**
3. 粘贴完整代码
4. 保存并部署

#### 方式 B：Wrangler CLI

```bash
npm install -g wrangler
wrangler login
wrangler deploy worker.js
```

### 步骤 4：配置客户端

1. 浏览器访问 `https://你的域名/?panel=<panelKey>`
2. 点击正文中的 **HTTPS** 打开面板
3. 输入 PIN 解锁
4. 选择代理类型和下行模式
5. 点击"生成"得到 VLESS 链接
6. 复制链接导入客户端

---

## 使用说明

### URL 参数一览

| 参数 | 值 | 说明 |
|---|---|---|
| `ed` | `2560` | Early Data 长度（客户端自动使用） |
| `ll` | `0` / `1` / `2` | 下行模式，默认 0 |
| `s5` | URL-encoded | 局部 SOCKS5 代理 |
| `h` | URL-encoded | 局部 HTTP 代理 |
| `g5` | URL-encoded | 全局 SOCKS5 代理 |
| `gh` | URL-encoded | 全局 HTTP 代理 |
| `ip` | `host:port` | proxyip 备用地址 |

### Path 示例

#### 纯直连（默认）

```
/api/v1/chat?ed=2560
```

#### proxyip 备用

```
/api/v1/chat?ed=2560&ip=1.2.3.4:443
```

#### 局部 SOCKS5

```
/api/v1/chat?ed=2560&s5=socks5%3A%2F%2Fuser%3Apass%401.2.3.4%3A1080
```

#### 全局 SOCKS5 + 低延迟

```
/api/v1/chat?ed=2560&ll=1&g5=socks5%3A%2F%2Fuser%3Apass%401.2.3.4%3A1080
```

#### 高速下载

```
/api/v1/chat?ed=2560&ll=2
```

### 下行模式选择建议

| 你的使用场景 | 推荐模式 |
|---|---|
| 网页浏览、视频、日常代理 | `ll=0`（默认，不写 ll 参数） |
| SSH、远程桌面、游戏、实时通信 | `ll=1` |
| GooglePlay、AppStore、大文件下载 | `ll=2` |

> ⚠️ **注意**：`ll=2` 单会话内存约 7.5MB，建议同时下载人数 ≤8。

---

## 参数详解

### CFG（模式无关配置）

| 参数 | 默认 | 说明 |
|---|---|---|
| `id` | `'UUID'` | 你的 UUID，**必须修改** |
| `panelKey` | `'admin'` | 面板路由暗号，**必须修改** |
| `panelPin` | `'mykey123'` | 面板 PIN，**必须修改** |
| `maxED` | 8KB | Early Data 上限 |
| `concur` | 1 | 直连竞速路数 |
| `directLoserTimeout` | 1500ms | loser 关闭窗口 |
| `failTTL` | 30s | 失败缓存 TTL |
| `failCacheMax` | 128 | 失败缓存上限 |
| `maxStages` | 5 | 竞速 stage 上限 |
| `dnStall` | 30s | 下行停滞超时 |
| `memBudget` | 96MB | 内存预算 |
| `minPerSession` | 4MB | 单会话最小上行队列 |
| `pathPrefix` | `/api/v1/chat` | 路径前缀 |

### PROFILES（三档模式）

| 字段 | ll=0 均衡 | ll=1 低延迟 | ll=2 高速下载 |
|---|---|---|---|
| `chunk` | 64KB | 16KB | 256KB |
| `dnPack` | 32KB | 2KB | 256KB |
| `dnTail` | 512 | 64 | 8KB |
| `dnQr` | 4 | 0 | 8 |
| `lowLat` | false | true | false |
| `upPack` | 20KB | 4KB | 64KB |
| `dnHigh` | 4MB | 512KB | 7MB |
| `dnLow` | 1MB | 128KB | 1.75MB |
| `stagger` | 1200ms | 200ms | 2000ms |
| `totalTimeout` | 6000ms | 2000ms | 12000ms |

---

## 性能特性

### 资源占用

| 模式 | 单会话内存 | 单 isolate 建议并发 |
|---|---|---|
| ll=0 | ~4.2MB | 15-20 |
| ll=1 | ~0.6MB | 80-100 |
| ll=2 | ~7.5MB | 8-10 |

### 出站 TCP 限制

Cloudflare Workers 单请求最多 **6 条出站连接**。当前配置：

- 直连：1 条
- 备用：最多 3 条（s5 / h / ip）
- 总计：**≤4 条**，低于 6 条硬限制

### 上下行限制

| 方向 | 限制类型 | 触发后果 |
|---|---|---|
| **上行** | 队列上限（4-96MB 动态） | 超限**断连**（无缓冲） |
| **下行** | 背压高水位（512KB-7MB） | 超限**暂停读**（有缓冲） |

**核心区别**：

- **上行**：WebSocket `message` 事件无法暂停，只能硬断
- **下行**：可以 `await r.read()` 暂停，天然支持背压

### v1.8.7 关键优化

1. **删除全部日志** — 省 5-10% CPU，免费版 10ms 限制下关键
2. **ll=2 的 `dnHigh` 降到 7MB** — 并发场景留更多余量
3. **`activeSessions` try/finally 保护** — 消除计数器失准风险
4. **`sock` 泄漏修复** — 会话已关时立即释放 socket

---

## 安全设计

### 双层隔离

#### 关卡 1（路由隔离）

```
访问 /                  → 裸 502（无面板，无 UUID）
访问 /?panel=<panelKey> → 含面板的 502
```

#### 关卡 2（加密隔离）

```
面板 HTML 里只有 AES-GCM 密文
用户输入 PIN → PBKDF2 派生密钥 → 解密 UUID
PIN 正确前，面板 DOM 不存在
```

### 加密参数

| 项 | 值 |
|---|---|
| 加密算法 | AES-GCM 256 |
| 密钥派生 | PBKDF2 |
| 哈希 | SHA-256 |
| 迭代 | 100,000 |
| salt | 16 字节随机 |
| iv | 12 字节随机 |

### 强度分析

| PIN 类型 | 离线爆破耗时（100ms/次） |
|---|---|
| `123456`（6 位数字） | ~27 小时 |
| `mykey123`（字典+数字） | **秒级** ⚠️ |
| 8 位随机混合 | ~600 万年 |
| 12 位随机混合 | 天文数字 |

> **结论**：PIN 必须 ≥8 位且非字典词。

### 残留风险

| 风险 | 是否解决 |
|---|---|
| 扫描器盲扫 | ✅ 已解决 |
| 源码泄露 | ✅ 已解决（无明文） |
| DOM 检查 | ✅ 已解决（未解锁无面板） |
| `?panel=` 分享 | ⚠️ 部分解决（仍需 PIN） |
| PIN 在线爆破 | ⚠️ 未做速率限制 |
| 用户电脑被入侵 | ❌ 无法解决 |

---

## 版本历史

| 版本 | 主要变更 |
|---|---|
| **v1.8.6** | 三档下行模式：`ll=0` 均衡（默认）/ `ll=1` 低延迟 / `ll=2` 高速下载。参数归位 `PROFILES`，移除端口自动判定，面板改为下拉选择。 |
| **v1.8.7** | 极简优化：删除全部日志 / 调参 / 修 2 个潜在 bug。面向 5-20 人场景。 |

### v1.8.6 详细说明

**三档下行模式**

- `ll=0` 均衡：默认，不填等价，与旧版行为一致
- `ll=1` 低延迟：激进参数，SSH / 游戏 / 实时通信
- `ll=2` 高速下载：激进参数，GooglePlay / AppStore / 网盘下载器

**参数归位**

- 模式相关字段（`chunk` / `dnPack` / `dnTail` / `dnQr` / `lowLat` / `upPack` / `dnHigh` / `dnLow` / `stagger` / `totalTimeout`）从 `CFG` 迁入 `PROFILES`
- `CFG` 只保留模式无关字段

**移除端口自动判定**

- 删掉 `LOW_LAT_PORTS`，不再根据端口自动启用低延迟
- 模式完全由 `ll` 参数控制

**面板 UI 改造**

- "低延迟模式"复选框 → "下行模式"下拉选择
- 每档附带场景说明与风险提示
- 客户端 PIN 校验从 4 位改为 8 位，与后端一致

### v1.8.7 详细说明

**删除日志**

- 移除 `logEvent` 函数定义 + 9 处调用
- Workers Logs 不再输出，节省 5-10% CPU

**调参**

- `failCacheMax`: 512 → 128
- `highSpeed.dnHigh`: 8MB → 7MB
- `highSpeed.dnLow`: 2MB → 1.75MB
- `minPerSession`: 保持 4MB

**Bug 修复**

- `activeSessions` 加 try/finally 保护（防计数器失准）
- `sock` 泄漏修复（会话已关时立即释放 socket）

---

## 注意事项

### 部署时

1. **必须修改 3 个字段**：`id` / `panelKey` / `panelPin`
2. **PIN 不要用 `mykey123` 这类字典词**
3. **`panelKey` 建议加随机后缀**：如 `p-x7k9m2`
4. **首次部署后测试**：用客户端导入 VLESS 链接，确认能代理

### 使用时

1. **`ll=2` 场景下控制并发** — 建议 ≤8 个下载会话
2. **大文件上传注意目标速度** — 目标慢会导致队列堆积
3. **不要在公共场合分享 `?panel=` 链接**
4. **PIN 记忆在脑子里或离线保管**，不要存浏览器

### 已知限制

| 限制 | 说明 |
|---|---|
| 仅支持 TCP | UDP / Mux 请求会被拒绝 |
| 出站 ≤6 条 TCP | CF 平台硬限制 |
| 无日志 | 出问题只能靠客户端表现判断 |
| 无速率限制 | PIN 可被在线爆破（PBKDF2 拖慢） |
| 单 isolate 128MB | 高并发需注意内存 |

### 不适用场景

- ❌ 需要 UDP 转发的应用（如部分游戏 / DNS）
- ❌ 需要多用户隔离的生产环境
- ❌ 需要流量统计 / 审计的场景
- ❌ 需要动态配置（不重启改参数）的场景

---

## 一句话总结

**SuperEdge v1.8.7** 是一个**极简、单文件、零依赖**的 VLESS-WS 节点服务，通过**双层安全面板**保护 UUID，通过**三档下行模式**适配不同场景，通过**资源保护机制**在 Cloudflare Workers 的硬限制内稳定运行。

**面向 5-20 人的小规模使用场景，部署简单、维护省心、性能充足。**

**核心原则**：不追新功能，不扩协议，保持简单。

---

## 致谢

本项目融合了社区多个 VLESS-WS 实现的思路，感谢所有公开分享代码的开发者。

---

<p align="center">
  <b>SuperEdge v1.8.7</b><br>
  <sub>Deployed on Cloudflare Workers · For personal use only</sub>
</p>
