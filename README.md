# StellaVPN Gate

> 星渊 VPNGate 网关：一个面向 Linux VPS 的 VPNGate OpenVPN 节点网关管理器。

StellaVPN Gate 基于 [VPNGate 官方公开 API](https://www.vpngate.net/api/iphone/) 拉取公开 OpenVPN 节点，在 VPS 上完成节点解析、测速、连接和代理出口管理。它会在本机启动一个默认仅监听 `127.0.0.1:8888` 的 HTTP/SOCKS5 双协议代理，并提供 Web 管理后台。

这个项目适合用来做个人学习、合法网络测试、OpenVPN 节点管理和 VPS 本地代理出口管理。

## 项目定位

StellaVPN Gate 不是免费住宅 IP 抓取器，也不是公网扫描器。

它只做三件事：

- 从 VPNGate 官方公开 API 获取节点。
- 在 Linux VPS 本机通过 OpenVPN 建立连接。
- 将本机代理出口统一暴露为 `127.0.0.1:8888`。

它明确不做：

- 不抓取免费代理网站。
- 不扫描公网 IP。
- 不收集来路不明的住宅 IP。
- 不提供批量注册、刷量、绕过风控、垃圾邮件等功能。
- 不上传用户配置、密码、节点信息或运行日志。

## 运行环境

本项目不是 GitHub Pages 静态站点，也不适合部署到静态托管平台。

真正运行环境必须是 Linux VPS，因为它依赖：

- root 权限
- OpenVPN
- TUN/TAP
- systemd
- Linux 策略路由
- 本地代理端口 `8888`
- Web 后台端口 `8787`

优先支持 Ubuntu 22.04 / Debian 12，后续兼容 CentOS、Rocky、AlmaLinux 和 Alpine。

## 功能概览

- VPNGate 官方节点拉取与 CSV 解析
- OpenVPN 配置解码和本地保存
- 节点基础连通性检测和延迟记录
- Web 管理后台，默认端口 `8787`
- 本地 HTTP/SOCKS5 双协议代理，默认 `127.0.0.1:8888`
- 连接指定节点、断开节点、自动选择最佳节点
- 路由模式：自动、固定地区、固定节点、收藏节点
- 代理出口 IP 检测
- IP 类型识别提示：住宅、机房、移动网络或未知，结果仅供参考
- JSON 文件保存状态和配置
- JSONL 本地日志
- systemd 自启动
- `stella-vpn` 命令行管理工具
- GitHub Actions 自动部署到 VPS

## 安全默认值

StellaVPN Gate 默认按“本地代理工具”设计，而不是公网代理服务。

- 代理默认只监听 `127.0.0.1:8888`。
- Web 后台首次启动会生成随机安全路径。
- Web 后台默认生成随机密码。
- 如果代理监听 `0.0.0.0` 或 `::`，必须设置代理用户名和密码。
- 未设置代理认证时，程序会拒绝启动公网代理监听。
- 敏感配置只保存在本机。
- Web 页面不会明文展示代理密码。
- 日志会避免输出密码、Authorization 等敏感字段。

## 快速开始

在 VPS 上以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Ralph179/stella-vpngate/main/install.sh | sudo bash
```

安装脚本会安装依赖、初始化数据目录、创建 systemd 服务、启动后台，并输出 Web 后台地址和初始登录信息。

安装完成示例：

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

## 使用代理

curl：

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org
```

Python requests：

```python
import requests

proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

response = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=15)
print(response.text)
```

Shell：

```bash
export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
```

## Web 后台

默认访问地址：

```text
http://your_server_ip:8787/randomSecretPath
```

后台页面包含：

- 控制台：当前连接节点、出口 IP、代理状态、节点统计和快捷操作。
- 节点列表：国家/地区、IP、协议、端口、延迟、评分、速度、会话数、IP 类型、收藏、屏蔽和操作按钮。
- 设置：路由模式、固定国家、固定节点、代理监听地址、代理认证和检测间隔。
- 日志：查看、过滤、复制和清空本地运行日志。

IP 类型判断来自第三方数据库，仅供参考，不代表真实平台风控结果。

## 命令行管理

```bash
stella-vpn
stella-vpn status
stella-vpn url
stella-vpn account
stella-vpn reset-password
stella-vpn reset-path
stella-vpn restart
stella-vpn logs
stella-vpn check-ip-types
stella-vpn public-proxy-on
stella-vpn set-proxy-auth
stella-vpn uninstall
```

## 后续更新

在 VPS 上进入安装目录：

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
```

## GitHub Actions 自动部署

GitHub 只用于源码托管、版本管理、Issue、README、Release 和自动部署到 VPS。

Actions 不会在 GitHub Runner 上运行 OpenVPN、代理服务或节点连接测试。它只通过 SSH 进入 VPS，同步代码并重启 systemd 服务。

需要配置 GitHub Secrets：

- `VPS_HOST`
- `VPS_PORT`
- `VPS_USER`
- `VPS_SSH_KEY`
- `DEPLOY_PATH`

push 到 `main` 后会执行：

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
systemctl status stella-vpngate --no-pager
```

## 手动安装

```bash
git clone https://github.com/Ralph179/stella-vpngate.git
cd stella-vpngate
bash install.sh
```

也可以手动安装依赖并注册 systemd 服务：

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

## systemd

```bash
systemctl status stella-vpngate --no-pager
systemctl restart stella-vpngate
systemctl stop stella-vpngate
journalctl -u stella-vpngate -f
```

## 常见问题

后台密码无法登录：

```bash
sudo env VPNGATE_DATA_DIR=/opt/stella-vpngate/data stella-vpn reset-password
sudo systemctl restart stella-vpngate
```

然后重新打开：

```bash
stella-vpn url
```

检查 TUN/TAP：

```bash
ls -l /dev/net/tun
modprobe tun
```

安装 OpenVPN：

```bash
apt-get install -y openvpn
```

检查代理端口：

```bash
ss -lntp | grep 8888
```

检查 Web 后台端口：

```bash
ss -lntp | grep 8787
```

开启公网代理监听：

```bash
stella-vpn set-proxy-auth
stella-vpn public-proxy-on
systemctl restart stella-vpngate
```

未设置认证时，程序会拒绝监听 `0.0.0.0` 或 `::`。

## 卸载

```bash
bash uninstall.sh
```

卸载脚本会停止并禁用 systemd 服务、删除命令行入口、清理 OpenVPN 进程和策略路由，并询问是否删除 `/opt/stella-vpngate` 数据。

## 目录结构

```text
stella-vpngate/
├── install.sh
├── uninstall.sh
├── stella_vpngate.py
├── proxy_server.py
├── vpn_utils.py
├── cli.py
├── README.md
├── systemd/
│   └── stella-vpngate.service
├── .github/
│   └── workflows/
│       └── deploy.yml
└── data/
    └── .gitkeep
```

## 免责声明

本项目仅用于合法网络测试、代理出口管理和个人学习研究。公共 VPNGate 节点由第三方志愿者提供，稳定性、速度、出口地区和 IP 质量不可保证。

请遵守所在地法律法规、服务条款和网络使用规范。项目作者不对任何滥用行为负责。
