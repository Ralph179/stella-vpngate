#!/usr/bin/env bash
set -euo pipefail

APP_NAME="stella-vpngate"
INSTALL_DIR="${INSTALL_DIR:-/opt/stella-vpngate}"
REPO_URL="${REPO_URL:-https://github.com/Ralph179/stella-vpngate.git}"
SERVICE_FILE="/etc/systemd/system/stella-vpngate.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 执行安装脚本"
  exit 1
fi

detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  elif command -v apk >/dev/null 2>&1; then echo apk
  else echo unknown
  fi
}

install_deps() {
  pm="$(detect_pm)"
  case "$pm" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn curl git ca-certificates iptables iproute2 psmisc python3
      ;;
    dnf) dnf install -y openvpn curl git ca-certificates iptables iproute psmisc python3 ;;
    yum) yum install -y openvpn curl git ca-certificates iptables iproute psmisc python3 ;;
    apk) apk add --no-cache openvpn curl git ca-certificates iptables iproute2 psmisc python3 ;;
    *) echo "不支持的系统：找不到 apt/dnf/yum/apk"; exit 1 ;;
  esac
}

install_deps
mkdir -p "$INSTALL_DIR"

resolve_source_dir() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  if [ -n "$script_dir" ] && [ -f "$script_dir/stella_vpngate.py" ]; then
    echo "$script_dir"
    return
  fi
  if [ -f "./stella_vpngate.py" ]; then
    pwd
    return
  fi
  local tmp_dir
  tmp_dir="$(mktemp -d /tmp/stella-vpngate-src.XXXXXX)"
  git clone --depth 1 "$REPO_URL" "$tmp_dir"
  echo "$tmp_dir"
}

SRC_DIR="$(resolve_source_dir)"
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude data/ --exclude .git/ "$SRC_DIR"/ "$INSTALL_DIR"/
  else
    (cd "$SRC_DIR" && tar --exclude="./data" --exclude="./.git" -cf - .) | (cd "$INSTALL_DIR" && tar -xf -)
  fi
fi

mkdir -p "$INSTALL_DIR/data/logs" "$INSTALL_DIR/data/configs"
chmod 700 "$INSTALL_DIR/data"
cp "$INSTALL_DIR/systemd/stella-vpngate.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
rm -f /usr/bin/stella-vpn
cat > /usr/bin/stella-vpn <<EOF
#!/usr/bin/env sh
exec python3 "$INSTALL_DIR/cli.py" "\$@"
EOF
chmod 755 /usr/bin/stella-vpn

cd "$INSTALL_DIR"
python3 - <<PY
from vpn_utils import DATA_DIR, ensure_dirs, ensure_ui_auth
ensure_dirs(DATA_DIR)
ensure_ui_auth(DATA_DIR)
PY

systemctl daemon-reload
systemctl enable stella-vpngate
systemctl restart stella-vpngate

AUTH_JSON="$INSTALL_DIR/data/ui_auth.json"
USER_NAME="$(python3 - <<PY
import json
print(json.load(open("$AUTH_JSON"))["username"])
PY
)"
PASSWORD="$(python3 - <<PY
import json
print(json.load(open("$AUTH_JSON")).get("initial_password", "请运行 stella-vpn reset-password 重置"))
PY
)"
SECRET="$(python3 - <<PY
import json
print(json.load(open("$AUTH_JSON"))["secret_path"])
PY
)"
SERVER_IP="$(curl -fsS --max-time 5 https://api.ipify.org || echo your_server_ip)"

cat <<EOF

StellaVPN Gate 已安装完成

Web 管理后台：
http://${SERVER_IP}:8787/${SECRET}

管理账号：
${USER_NAME}

管理密码：
${PASSWORD}

本机代理：
HTTP/SOCKS5: 127.0.0.1:8888

命令行管理：
stella-vpn
EOF
