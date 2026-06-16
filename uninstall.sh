#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/stella-vpngate}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 执行卸载脚本"
  exit 1
fi

systemctl stop stella-vpngate 2>/dev/null || true
systemctl disable stella-vpngate 2>/dev/null || true
rm -f /etc/systemd/system/stella-vpngate.service
rm -f /usr/bin/stella-vpn
systemctl daemon-reload || true
pkill -f "stella-vpngate.*openvpn" 2>/dev/null || true
pkill -f "openvpn.*stella" 2>/dev/null || true
ip rule del fwmark 0x64 table 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

read -r -p "是否删除 ${INSTALL_DIR} 及本地数据？[y/N] " answer
case "$answer" in
  y|Y|yes|YES) rm -rf "$INSTALL_DIR"; echo "已删除安装目录" ;;
  *) echo "已保留安装目录和数据：$INSTALL_DIR" ;;
esac

echo "StellaVPN Gate 已卸载"
