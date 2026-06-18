# StellaVPN Gate：把 VPNGate 变成本地代理

StellaVPN Gate 是一个运行在 Linux VPS 上的 VPNGate 代理网关工具。

它会自动获取 VPNGate 公共 OpenVPN 节点，检测节点是否可用，连接你选择的节点，然后在 VPS 本机生成一个代理入口：

```text
127.0.0.1:8888
```

脚本、终端命令、浏览器或其他程序只要走这个代理，就会通过当前 VPNGate 节点出站。

## 它适合做什么？

StellaVPN Gate 主要解决三件事：

1. 自动获取节点
   不需要手动打开 VPNGate 网站，一个个下载 OpenVPN 配置。

2. 自动检测节点
   后台可以检测节点是否可用、延迟情况和 IP 类型，并自动屏蔽不可用节点。

3. 提供本地代理
   连接节点后，本机提供 HTTP/SOCKS5 代理：

```text
127.0.0.1:8888
```

默认以人工选择节点为主。你也可以在节点页打开“自动选择节点”，让系统自动连接最佳可用节点。

## 运行要求

本项目不是 GitHub Pages 静态页面，不能部署到静态托管平台。

真正运行环境必须是 Linux VPS，因为它需要：

- root 权限
- OpenVPN
- TUN/TAP
- systemd
- Linux 策略路由
- 本地代理端口 `8888`
- Web 后台端口 `8787`

推荐使用 Ubuntu 22.04 / Debian 12。

## 一键安装

在 VPS 上使用 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Ralph179/stella-vpngate/main/install.sh)
```

安装完成后，终端会显示：

```text
Web 后台地址
管理账号
管理密码
本地代理地址
```

后台地址格式类似：

```text
http://你的服务器IP:8787/随机路径
```

## 后台怎么用？

登录后台后，常用流程是：

1. 进入“节点”
2. 点击“更新节点”
3. 点击“立即检测”
4. 在可用节点里选择一个节点
5. 点击“连接”

节点页只保留核心信息：

```text
状态 / 国家或地区 / IP / 延迟 / IP 类型 / 操作
```

IP 类型会显示为住宅、机房、移动网络、未知或未检测。这个判断来自第三方数据库，仅供参考。

## 测试代理是否生效

连接节点后，在 VPS 上执行：

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org
```

如果返回的 IP 不是 VPS 本机 IP，而是当前节点 IP，说明代理已经生效。

## 程序怎么使用这个代理？

代理地址是：

```text
http://127.0.0.1:8888
```

Python 示例：

```python
import requests

proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

print(requests.get("https://api.ipify.org", proxies=proxies, timeout=15).text)
```

终端示例：

```bash
export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
```

curl 示例：

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org
```

## Web 后台

默认端口：

```text
8787
```

后台包含：

- 控制台：当前节点、自动选择状态、本机 IP、代理状态、代理延迟。
- 节点：节点更新、全量检测、IP 类型检测、自动选择开关、连接和屏蔽操作。
- 日志：查看、复制和清空运行日志。

控制台中的“本地代理”面板会显示：

```text
HTTP/SOCKS5：127.0.0.1:8888
代理 IP：当前连接节点的 IP
```

## 命令行管理

安装后会提供 `stella-vpn` 命令：

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

常用命令：

```bash
stella-vpn url
stella-vpn account
stella-vpn reset-password
systemctl restart stella-vpngate
```

## 后续更新

进入安装目录：

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
systemctl status stella-vpngate --no-pager
```

## GitHub Actions 自动部署

GitHub 只用于：

1. 存放源码
2. 版本管理
3. Issue / README / Release
4. GitHub Actions 自动部署到 VPS

Actions 不会在 GitHub Runner 上运行 OpenVPN、代理服务或节点连接测试。它只会通过 SSH 进入 VPS，同步代码并重启 systemd 服务。

需要配置 GitHub Secrets：

```text
VPS_HOST
VPS_PORT
VPS_USER
VPS_SSH_KEY
DEPLOY_PATH
```

push 到 `main` 后会执行类似流程：

```bash
cd /opt/stella-vpngate
git pull origin main
python3 -m compileall stella_vpngate.py proxy_server.py vpn_utils.py cli.py
systemctl restart stella-vpngate
systemctl status stella-vpngate --no-pager
```

## 常见问题

后台密码忘了：

```bash
sudo env VPNGATE_DATA_DIR=/opt/stella-vpngate/data stella-vpn reset-password
sudo systemctl restart stella-vpngate
```

检查 TUN/TAP：

```bash
ls -l /dev/net/tun
modprobe tun
```

检查代理端口：

```bash
ss -lntp | grep 8888
```

检查 Web 后台端口：

```bash
ss -lntp | grep 8787
```

查看服务日志：

```bash
journalctl -u stella-vpngate -f
```

## 安全说明

StellaVPN Gate 默认是本地代理工具，不是公网开放代理。

- 代理默认只监听 `127.0.0.1:8888`。
- Web 后台首次启动会生成随机路径和随机密码。
- 如果要把代理开放到公网，必须先设置代理认证。
- 敏感配置保存在 VPS 本机，不会上传到 GitHub。
- 日志会避免输出密码、Authorization 等敏感字段。

## 免责声明

StellaVPN Gate 仅用于合法网络测试、代理出口管理和个人学习研究。

VPNGate 节点由第三方志愿者提供，稳定性、速度、出口地区和 IP 质量都不可保证。请遵守所在地法律法规、服务条款和网络使用规范。项目作者不对任何滥用行为负责。
