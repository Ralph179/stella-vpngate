#!/usr/bin/env python3
"""Command line management tool for StellaVPN Gate."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

if "VPNGATE_DATA_DIR" not in os.environ and Path("/opt/stella-vpngate/data").exists():
    os.environ["VPNGATE_DATA_DIR"] = "/opt/stella-vpngate/data"

from vpn_utils import DATA_DIR, ensure_ui_auth, load_nodes, load_state, logger, public_server_ip, reset_secret_path, reset_ui_password, save_settings


SERVICE = "stella-vpngate"


def run_cmd(args: list[str]) -> int:
    proc = subprocess.run(args, text=True)
    return proc.returncode


def service_status() -> None:
    state = load_state(DATA_DIR)
    nodes = load_nodes(DATA_DIR)
    active = state.get("active_openvpn_node_id") or "未连接"
    print(f"服务: {SERVICE}")
    print(f"当前节点: {active}")
    print(f"代理: http://127.0.0.1:8888")
    print(f"节点总数: {len(nodes)}")
    print(f"代理状态: {'正常' if state.get('proxy_ok') else '未知/异常'} {state.get('proxy_ip','')}")
    run_cmd(["systemctl", "status", SERVICE, "--no-pager"])


def show_url() -> None:
    auth = ensure_ui_auth(DATA_DIR)
    print(f"http://{public_server_ip()}:8787/{auth['secret_path']}")


def show_account() -> None:
    auth = ensure_ui_auth(DATA_DIR)
    print(f"用户名: {auth.get('username', 'admin')}")
    if auth.get("initial_password"):
        print(f"初始密码: {auth['initial_password']}")
    else:
        print("密码不会明文保存；如遗忘请运行 stella-vpn reset-password")


def logs() -> None:
    today = sorted((DATA_DIR / "logs").glob("*.jsonl"))
    if not today:
        print("暂无日志")
        return
    subprocess.run(["tail", "-n", "120", str(today[-1])])


def public_proxy(enable: bool) -> None:
    settings = {"local_proxy_host": "0.0.0.0" if enable else "127.0.0.1"}
    save_settings(settings, DATA_DIR)
    print("已保存设置。公网监听需要代理认证；请运行 stella-vpn set-proxy-auth 后重启服务。")


def set_proxy_auth() -> None:
    user = input("代理用户名: ").strip()
    password = input("代理密码: ").strip()
    if not user or not password:
        print("用户名和密码不能为空")
        sys.exit(1)
    save_settings({"local_proxy_user": user, "local_proxy_password": password}, DATA_DIR)
    print("代理认证已保存。请重启服务生效。")


def menu() -> None:
    items = [
        ("查看服务状态", service_status),
        ("查看 Web 后台地址", show_url),
        ("查看管理账号", show_account),
        ("重置管理密码", lambda: print(reset_ui_password(DATA_DIR))),
        ("重置安全路径", lambda: print(reset_secret_path(DATA_DIR))),
        ("查看当前连接节点", lambda: print(load_state(DATA_DIR).get("active_openvpn_node_id") or "未连接")),
        ("手动更新节点", lambda: run_cmd(["curl", "-fsS", "-X", "POST", f"http://127.0.0.1:8787/{ensure_ui_auth(DATA_DIR)['secret_path']}/api/fetch"])),
        ("重启服务", lambda: run_cmd(["systemctl", "restart", SERVICE])),
        ("停止服务", lambda: run_cmd(["systemctl", "stop", SERVICE])),
        ("查看日志", logs),
        ("开启公网代理监听", lambda: public_proxy(True)),
        ("关闭公网代理监听", lambda: public_proxy(False)),
        ("设置代理认证", set_proxy_auth),
        ("卸载", lambda: run_cmd(["bash", "/opt/stella-vpngate/uninstall.sh"])),
    ]
    for i, (name, _) in enumerate(items, 1):
        print(f"{i}. {name}")
    choice = input("请选择: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(items):
        items[int(choice) - 1][1]()


def main() -> None:
    parser = argparse.ArgumentParser(prog="stella-vpn")
    parser.add_argument("command", nargs="?", choices=[
        "status", "url", "account", "reset-password", "reset-path", "restart", "stop", "logs",
        "public-proxy-on", "public-proxy-off", "set-proxy-auth", "uninstall",
    ])
    args = parser.parse_args()
    if not args.command:
        menu()
    elif args.command == "status":
        service_status()
    elif args.command == "url":
        show_url()
    elif args.command == "account":
        show_account()
    elif args.command == "reset-password":
        print(reset_ui_password(DATA_DIR))
    elif args.command == "reset-path":
        print(reset_secret_path(DATA_DIR))
    elif args.command == "restart":
        sys.exit(run_cmd(["systemctl", "restart", SERVICE]))
    elif args.command == "stop":
        sys.exit(run_cmd(["systemctl", "stop", SERVICE]))
    elif args.command == "logs":
        logs()
    elif args.command == "public-proxy-on":
        public_proxy(True)
    elif args.command == "public-proxy-off":
        public_proxy(False)
    elif args.command == "set-proxy-auth":
        set_proxy_auth()
    elif args.command == "uninstall":
        sys.exit(run_cmd(["bash", "/opt/stella-vpngate/uninstall.sh"]))


if __name__ == "__main__":
    main()
