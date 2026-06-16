# StellaVPN Gate

星渊 VPNGate 网关是一个基于 VPNGate 官方公开 API 的 OpenVPN 节点网关管理工具。它在 Linux VPS 上运行，拉取官方公开节点，筛选可用 OpenVPN 配置，并在本机提供 HTTP/SOCKS5 双协议代理出口。

本项目不是 GitHub Pages 静态站点，也不应部署到静态托管平台。真正运行环境必须是 Linux VPS，因为它需要 root 权限、OpenVPN、TUN/TAP、systemd、代理端口 `8888`、Web 后台端口 `8787` 和 Linux 策略路由。

## 安全说明

- 只使用 VPNGate 官方公开节点：`https://www.vpngate.net/api/iphone/`
- 不抓取免费住宅代理网站。
- 不扫描公网。
- 不收集来路不明的住宅 IP。
- 默认代理只监听 `127.0.0.1:8888`。
- 如果代理监听 `0.0.0.0` 或 `::`，必须设置代理用户名和密码，否则程序拒绝启动代理服务。
- Web 后台首次启动会生成随机安全路径和账号密码。
- 密码只保存在本地，Web 页面不会明文展示代理密码。
- 日志会避免输出敏感密码。

公共 VPNGate 节点稳定性和 IP 质量不可保证。本项目仅用于合法网络测试、代理出口管理和个人学习研究。

## 功能

- VPNGate 官方节点拉取和 CSV 解析
- OpenVPN 配置解码和本地保存
- 节点基础测速和状态维护
- OpenVPN 连接、断开和状态恢复
- 本地 HTTP/SOCKS5 双协议代理，默认 `127.0.0.1:8888`
- Web 管理后台，默认端口 `8787`
- 自动连接最佳节点和基础自动切换
- JSONL 日志
- 本地 JSON 状态和设置文件
- systemd 自启动
- `stella-vpn` 命令行管理工具
- GitHub Actions SSH 自动部署到 VPS

## 一键安装

首次部署请在 VPS 上执行：

```bash
bash install.sh
```

安装完成会输出：

```text
StellaVPN Gate 已安装完成

Web 管理后台：
http://your_server_ip:8787/randomSecretPath

管理账号：
admin

管理密码：
xxxxxxxxxxxx

本机代理：
HTTP/SOCKS5: 127.0.0.1:8888

命令行管理：
stella-vpn
```

## 手动安装

```bash
apt-get update
apt-get install -y openvpn curl git ca-certificates iptables iproute2 psmisc python3
mkdir -p /opt/stella-vpngate
cp -a . /opt/stella-vpngate/
cp /opt/stella-vpngate/systemd/stella-vpngate.service /etc/systemd/system/
ln -sf /opt/stella-vpngate/cli.py /usr/bin/stella-vpn
systemctl daemon-reload
systemctl enable --now stella-vpngate
```

## 后续更新

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
```

## GitHub Actions 自动部署

GitHub 只用于源码、版本管理、Issue、README、Release 和自动部署到 VPS。Actions 不会在 GitHub Runner 上运行 OpenVPN、代理服务或节点连接测试。

需要在仓库 Secrets 中设置：

- `VPS_HOST`
- `VPS_PORT`
- `VPS_USER`
- `VPS_SSH_KEY`
- `DEPLOY_PATH`

当 `main` 分支 push 后，`.github/workflows/deploy.yml` 会通过 SSH 进入 VPS，执行：

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
systemctl status stella-vpngate --no-pager
```

## 使用代理

curl 示例：

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org
```

Python requests 示例：

```python
import requests

proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

response = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=15)
print(response.text)
```

Shell 环境变量示例：

```bash
export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
```

## Web 后台

默认地址：

```text
http://your_server_ip:8787/randomSecretPath
```

页面包括：

- Dashboard：连接状态、出口 IP、代理状态、节点统计和操作按钮
- 节点列表：筛选、排序、连接、收藏、拉黑、下载 `.ovpn`
- 设置：路由模式、固定国家、固定节点、代理监听、认证和检测间隔
- 日志：查看、过滤、复制、清空最近 JSONL 日志

IP 类型判断来自第三方数据库，仅供参考，不代表真实平台风控结果。

## 命令行

```bash
stella-vpn
stella-vpn status
stella-vpn url
stella-vpn account
stella-vpn reset-password
stella-vpn reset-path
stella-vpn restart
stella-vpn logs
stella-vpn public-proxy-on
stella-vpn set-proxy-auth
stella-vpn uninstall
```

## systemd 管理

```bash
systemctl status stella-vpngate --no-pager
systemctl restart stella-vpngate
systemctl stop stella-vpngate
journalctl -u stella-vpngate -f
```

## 常见问题

TUN/TAP 不可用：

```bash
ls -l /dev/net/tun
modprobe tun
```

OpenVPN 未安装：

```bash
apt-get install -y openvpn
```

代理端口占用：

```bash
ss -lntp | grep 8888
```

Web 后台端口占用：

```bash
ss -lntp | grep 8787
```

公网代理监听失败：

程序会拒绝在未设置认证时监听 `0.0.0.0` 或 `::`。请先运行：

```bash
stella-vpn set-proxy-auth
stella-vpn public-proxy-on
systemctl restart stella-vpngate
```

## 卸载

```bash
bash uninstall.sh
```

卸载脚本会停止并禁用 systemd 服务、删除命令行入口、清理 OpenVPN 进程和策略路由，并询问是否删除 `/opt/stella-vpngate` 数据。

## 免责声明

本项目只使用 VPNGate 官方公开节点，不抓取免费住宅代理，不扫描公网。请只在合法授权的网络环境中使用。公共 VPN 节点可能不稳定，出口 IP 类型、ASN、地区等信息来自第三方数据库，仅供参考。
