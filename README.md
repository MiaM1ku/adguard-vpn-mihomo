# adg2mihomo

把 AdGuard VPN 订阅转成 **mihomo Proxy Provider**（`type: trusttunnel`，HTTPS/HTTP2 CONNECT）。

内核要求：**mihomo ≥ 1.19.21**。

凭证只保存在本地 `data/`，不会进 Git。上海节点不在海外 IP 的 locations API 里，后端会按 Android 客户端的伪装参数强制注入。

## 上海节点

| 字段 | 值 |
| --- | --- |
| Location ID | `Y25fc2hhbmdoYWk=` (`cn_shanghai`) |
| SNI / `:authority` | `superbaby.tv` |
| 证书 CN | `singlecustom.live` |
| 入口 IPv4 | `213.182.218.34`（香港 Datacamp） |
| Relay | `157.254.131.80` |

这是虚拟出口：hostname 决定出口品牌，物理机可以在香港。用户名/密码是账号级的，所有节点共用。locations API 会按**客户端公网 IP** 过滤，非 CN IP 看不到上海；手机在国内才能拉到。

## 凭据有效期

| 凭据 | 有效期 |
| --- | --- |
| VPN token | 账户许可证到期（当前约到 2030-12-24） |
| 代理用户名/密码 | 约 **7 天**，`/api/v1/proxy_credentials` 可刷新 |
| OAuth access_token | 约 30 天，只用来换 VPN token |

本服务会在代理密码剩余不足 12 小时时自动刷新。

## 本地运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m adg2mihomo status
python -m adg2mihomo serve --host 127.0.0.1 --port 8787
```

已有登录态会从 `data/` 或仓库根目录的 `.adguard_*.json` 导入。没有登录时：

```bash
python -m adg2mihomo login
```

浏览器打开打印出的 `https://auth.adguard.io/device_code?user_code=...`，确认后凭证写入 `data/`。

导出静态 YAML：

```bash
python -m adg2mihomo export -o dist --legacy
```

## mihomo 用法

```yaml
proxy-providers:
  adguard:
    type: http
    url: "http://127.0.0.1:8787/proxies.yaml"
    path: ./proxy_providers/adguard.yaml
    interval: 3600
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
      lazy: true
      expected-status: 204

proxy-groups:
  - name: PROXY
    type: select
    use: [adguard]
    proxies: [AUTO, DIRECT]
  - name: AUTO
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    use: [adguard]
```

也可直接拉完整配置：`http://127.0.0.1:8787/mihomo.yaml`。

只看上海：`http://127.0.0.1:8787/proxies.yaml?only=shanghai`。

设置 `ADG2MIHOMO_API_TOKEN` 后，provider 需要带：

```yaml
header:
  Authorization:
    - "Bearer <token>"
```

## API

| 路径 | 说明 |
| --- | --- |
| `GET /proxies.yaml` | mihomo proxy-provider 节点列表 |
| `GET /mihomo.yaml` | 引用该 provider 的完整配置 |
| `GET /mihomo.yaml?inline=true` | 内嵌 `proxies:` 的完整配置 |
| `GET /nodes.json` | 不含密码的节点清单 |
| `GET /status` | 登录状态和 TTL |
| `POST /auth/device/start` | 开始 device-code 登录 |
| `POST /auth/device/poll` | 轮询登录结果 |
| `POST /auth/refresh` | 强制刷新 token / 节点 |

## 本机 TUN 注意

如果本机 mihomo TUN 已经接管流量，直接连 `superbaby.tv` / `213.182.218.34` 可能被劫持到 Cloudflare 并返回 403。测试 TrustTunnel 时绕过 TUN，或把这些 IP/域名走 DIRECT。

## 免责

这是个人转换工具，不是 AdGuard 官方项目。不要把 `data/`、代理密码或许可证密钥推到公开仓库。
