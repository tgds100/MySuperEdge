# SuperEdge · v1.8.3
> 基于 WebSocket 的 CF Workers VLESS 边缘节点服务

## 项目简介
一个部署在 Cloudflare Workers 上的轻量级 VLESS-over-WebSocket 节点服务。
支持直连、proxyip 备用、局部/全局 SOCKS5 与 HTTP 代理；
内置增强节点生成面板（自动识别代理链接、二维码本地生成、一键重置）。

## Path 格式
全部以 `/api/v1/chat` 开头

| 类型 | 路径参数 |
| ---- | ---- |
| 纯直连 | `?ed=2560` |
| proxyip 备用 | `?ed=2560&ip=1.2.3.4:443` |
| 局部 SOCKS5 | `?ed=2560&s5=<URL-encoded "socks5://user:pass@host:port">` |
| 局部 HTTP | `?ed=2560&h=<URL-encoded "http://user:pass@host:port">` |
| 全局 SOCKS5 | `?ed=2560&g5=<URL-encoded "socks5://user:pass@host:port">` |
| 全局 HTTP | `?ed=2560&gh=<URL-encoded "http://user:pass@host:port">` |
| 低延迟模式 | 在任意 path 末尾追加 `&ll=1`（适用于 SSH / 游戏 / 实时交互） |

## 出站优先级
- `g5 / gh`：单路径全局代理，不 fallback（带超时兜底）
- 其他：Happy Eyeballs，直连 / s5 / h / ip 按 stagger 梯度并发竞速

## 版本历史
- v1.0 VLESS-WS 基础实现
- v1.2 加入 SOCKS5 / HTTP / proxyip 串行 fallback
- v1.3 引入 Happy Eyeballs + 零分配握手 + IPv6 / leftover 修复
- v1.5 工程化命名，特性矩阵规范化
- v1.5.1 修复 raceDirect loser 泄漏 / hTunnelConnect 重复 release / raceHappy timer 失控
- v1.5.2 回滚 BYOB buffer 复用（detach 语义导致第二次 read 抛错）
- v1.7 融合 SuperNiulai 增强节点生成器：自动刷新、粘贴代理链接、元信息展示
- v1.8 性能优化：CFG 调优 / 全局代理超时 / 失败缓存 / 低延迟模式 / 502 懒加载
- v1.8.1 参数体系重构：移除 token=sg-*/wg-*，改为可读参数 s5 / h / g5 / gh / ll
- v1.8.2 面板交互重做：生成按钮 / top 定位 / pr-link 防抖 / 内联二维码 / 重置按钮
- v1.8.3 面板 UI 优化：
  - UUID / Host 分两行显示，长 UUID 不换行错位
  - 精简文案，标题去版本号，页脚改为自然语序
  - 按钮与标签统一短句风格
