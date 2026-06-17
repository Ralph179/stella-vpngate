#!/usr/bin/env python3
"""StellaVPN Gate web service and supervisor."""

from __future__ import annotations

import json
import os
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, urlparse

from proxy_server import DualProxyServer, ProxyConfig
from vpn_utils import (
    CHECK_INTERVAL_SECONDS,
    DATA_DIR,
    FETCH_INTERVAL_SECONDS,
    LOCAL_PROXY_HOST,
    LOCAL_PROXY_PORT,
    UI_HOST,
    UI_PORT,
    check_nodes,
    check_proxy_health,
    connect_node,
    disconnect_current,
    drop_session,
    ensure_dirs,
    ensure_ui_auth,
    fetch_vpngate_nodes,
    load_nodes,
    load_settings,
    load_state,
    logger,
    lookup_ip_info,
    make_session,
    public_server_ip,
    reset_secret_path,
    reset_ui_password,
    save_nodes,
    save_settings,
    save_state,
    select_best_node,
    valid_session,
    verify_ui_password,
)


APP_NAME = "StellaVPN Gate"
CN_NAME = "星渊 VPNGate 网关"


class StellaRuntime:
    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        ensure_dirs(data_dir)
        self.auth = ensure_ui_auth(data_dir)
        self.proxy_thread: threading.Thread | None = None
        self.proxy_server: DualProxyServer | None = None
        self.maintenance_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()

    def start_proxy(self) -> None:
        settings = load_settings(self.data_dir)
        config = ProxyConfig(
            host=os.getenv("LOCAL_PROXY_HOST", str(settings.get("local_proxy_host", LOCAL_PROXY_HOST))),
            port=int(os.getenv("LOCAL_PROXY_PORT", str(settings.get("local_proxy_port", LOCAL_PROXY_PORT)))),
            user=os.getenv("LOCAL_PROXY_USER", str(settings.get("local_proxy_user", ""))),
            password=os.getenv("LOCAL_PROXY_PASSWORD", str(settings.get("local_proxy_password", ""))),
        )
        self.proxy_server = DualProxyServer(config)
        self.proxy_thread = threading.Thread(target=self.proxy_server.start, daemon=True, name="stella-proxy")
        self.proxy_thread.start()

    def start_maintenance(self) -> None:
        self.maintenance_thread = threading.Thread(target=self.maintenance_loop, daemon=True, name="stella-maintenance")
        self.maintenance_thread.start()

    def maintenance_loop(self) -> None:
        last_fetch = 0
        last_check = 0
        switch_failures = 0
        while not self.stop_event.is_set():
            state = load_state(self.data_dir)
            now = int(time.time())
            try:
                if now - last_fetch > int(os.getenv("FETCH_INTERVAL_SECONDS", str(FETCH_INTERVAL_SECONDS))) and not load_nodes(self.data_dir):
                    fetch_vpngate_nodes(self.data_dir)
                    last_fetch = now
                if now - last_check > int(os.getenv("CHECK_INTERVAL_SECONDS", str(CHECK_INTERVAL_SECONDS))) and load_nodes(self.data_dir):
                    check_nodes(self.data_dir, openvpn=False)
                    last_check = now
                if state.get("connection_enabled") and state.get("active_openvpn_node_id"):
                    health = check_proxy_health("127.0.0.1", int(os.getenv("LOCAL_PROXY_PORT", str(LOCAL_PROXY_PORT))))
                    state.update({
                        "proxy_ok": health["ok"],
                        "proxy_ip": health["ip"],
                        "proxy_latency_ms": health["latency_ms"],
                        "proxy_error": health["error"],
                    })
                    save_state(state, self.data_dir)
                    if not health["ok"] and switch_failures < 3:
                        switch_failures += 1
                        self.mark_active_failed(health["error"])
                        node = select_best_node(self.data_dir)
                        if node:
                            connect_node(node["id"], self.data_dir)
                    elif health["ok"]:
                        switch_failures = 0
            except Exception as exc:
                logger.write("ERROR", "Main", "Maintenance loop error", error=str(exc))
            self.stop_event.wait(10)

    def mark_active_failed(self, message: str) -> None:
        state = load_state(self.data_dir)
        active = state.get("active_openvpn_node_id")
        if not active:
            return
        nodes = load_nodes(self.data_dir)
        for node in nodes:
            if node.get("id") == active:
                node.update({"probe_status": "unavailable", "probe_message": message, "active": False})
        save_nodes(nodes, self.data_dir)


RUNTIME = StellaRuntime(DATA_DIR)


class DualStackServer(ThreadingHTTPServer):
    address_family = 10

    def server_bind(self) -> None:
        try:
            self.socket.setsockopt(41, 26, 0)
        except OSError:
            pass
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    server_version = "StellaVPNGate/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.write("INFO", "UI", fmt % args)

    def do_GET(self) -> None:
        if self.is_secret_root():
            if valid_session(self.session_token(), DATA_DIR):
                self.send_html(self.render_app())
            else:
                self.send_html(self.render_login())
            return
        if not self.require_auth():
            return
        route = self.route_path()
        if route == "/":
            self.send_html(self.render_app())
        elif route == "/api/state":
            self.send_json(load_state(DATA_DIR))
        elif route == "/api/nodes":
            self.send_json(load_nodes(DATA_DIR))
        elif route == "/api/logs":
            qs = parse_qs(urlparse(self.path).query)
            self.send_json(logger.tail(
                limit=int((qs.get("limit") or ["200"])[0]),
                level=(qs.get("level") or [""])[0],
                module=(qs.get("module") or [""])[0],
            ))
        elif route.startswith("/api/download/"):
            node_id = route.rsplit("/", 1)[-1]
            node = next((n for n in load_nodes(DATA_DIR) if n.get("id") == node_id), None)
            if not node:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-openvpn-profile")
            self.send_header("Content-Disposition", f"attachment; filename=\"{node_id}.ovpn\"")
            self.end_headers()
            self.wfile.write(Path(node["config_file"]).read_bytes())
        else:
            if route.startswith("/api/"):
                self.send_error(404)
            else:
                self.send_response(302)
                self.send_header("Location", f"/{ensure_ui_auth(DATA_DIR)['secret_path']}")
                self.end_headers()

    def do_POST(self) -> None:
        if not self.require_auth(allow_login=True):
            return
        route = self.route_path()
        body = self.read_json()
        try:
            if route == "/api/login":
                username = str(body.get("username", ""))
                password = str(body.get("password", ""))
                if verify_ui_password(username, password, DATA_DIR):
                    token = make_session(DATA_DIR)
                    self.send_json({"ok": True}, headers={"Set-Cookie": f"stella_session={token}; HttpOnly; SameSite=Lax; Path=/"})
                else:
                    self.send_json({"ok": False, "error": "invalid credentials"}, status=403)
            elif route == "/api/logout":
                drop_session(self.session_token(), DATA_DIR)
                self.send_json({"ok": True}, headers={"Set-Cookie": "stella_session=; Max-Age=0; Path=/"})
            elif route == "/api/fetch":
                nodes = fetch_vpngate_nodes(DATA_DIR)
                self.send_json({"ok": True, "count": len(nodes)})
            elif route == "/api/check":
                nodes = check_nodes(DATA_DIR, openvpn=bool(body.get("openvpn", False)))
                self.send_json({"ok": True, "available": sum(1 for n in nodes if n.get("probe_status") == "available")})
            elif route == "/api/connect":
                ok, message = connect_node(str(body.get("node_id", "")), DATA_DIR)
                self.send_json({"ok": ok, "message": message}, status=200 if ok else 400)
            elif route == "/api/disconnect":
                disconnect_current(DATA_DIR)
                self.send_json({"ok": True})
            elif route == "/api/auto-connect":
                node = select_best_node(DATA_DIR)
                if not node:
                    self.send_json({"ok": False, "error": "no available node"}, status=400)
                else:
                    ok, message = connect_node(node["id"], DATA_DIR)
                    self.send_json({"ok": ok, "node_id": node["id"], "message": message}, status=200 if ok else 400)
            elif route == "/api/check-proxy":
                health = check_proxy_health("127.0.0.1", int(os.getenv("LOCAL_PROXY_PORT", str(LOCAL_PROXY_PORT))))
                state = load_state(DATA_DIR)
                state.update({"proxy_ok": health["ok"], "proxy_ip": health["ip"], "proxy_latency_ms": health["latency_ms"], "proxy_error": health["error"]})
                save_state(state, DATA_DIR)
                if health["ok"] and health["ip"]:
                    info = lookup_ip_info(health["ip"])
                    health["ip_info"] = info
                self.send_json(health)
            elif route == "/api/settings":
                self.save_settings(body)
                self.send_json({"ok": True})
            elif route == "/api/favorite":
                self.toggle_node(body, "favorite")
            elif route == "/api/blacklist":
                self.toggle_node(body, "blacklist")
            elif route == "/api/reset-password":
                password = reset_ui_password(DATA_DIR)
                self.send_json({"ok": True, "password": password})
            elif route == "/api/reset-path":
                path = reset_secret_path(DATA_DIR)
                self.send_json({"ok": True, "secret_path": path})
            elif route == "/api/clear-logs":
                for p in (DATA_DIR / "logs").glob("*.jsonl"):
                    p.unlink()
                self.send_json({"ok": True})
            else:
                self.send_error(404)
        except Exception as exc:
            logger.write("ERROR", "UI", "API request failed", route=route, error=str(exc))
            self.send_json({"ok": False, "error": str(exc)}, status=500)

    def route_path(self) -> str:
        parsed = urlparse(self.path)
        secret = ensure_ui_auth(DATA_DIR)["secret_path"]
        prefix = f"/{secret}"
        if parsed.path.startswith(prefix):
            rest = parsed.path[len(prefix):] or "/"
            return rest
        return parsed.path

    def is_secret_root(self) -> bool:
        parsed = urlparse(self.path)
        secret = ensure_ui_auth(DATA_DIR)["secret_path"]
        return parsed.path.rstrip("/") == f"/{secret}"

    def session_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return ""
        morsel = jar.get("stella_session")
        return morsel.value if morsel else ""

    def require_auth(self, allow_login: bool = False) -> bool:
        route = self.route_path()
        if allow_login and route == "/api/login":
            return True
        if valid_session(self.session_token(), DATA_DIR):
            return True
        if route.startswith("/api/"):
            self.send_json({"ok": False, "error": "unauthorized"}, status=401)
        else:
            self.send_response(302)
            self.send_header("Location", f"/{ensure_ui_auth(DATA_DIR)['secret_path']}")
            self.end_headers()
        return False

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if not length:
            return {}
        data = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(data or "{}")

    def send_json(self, value: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def send_html(self, html: str) -> None:
        payload = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def save_settings(self, body: dict[str, Any]) -> None:
        allowed = {
            "routing_mode", "force_country", "fixed_node_id", "favorite_node_ids",
            "favorites_fallback", "connection_enabled", "local_proxy_host",
            "local_proxy_port", "local_proxy_user", "local_proxy_password",
            "max_scan_rows", "target_valid_nodes", "fetch_interval_seconds",
            "check_interval_seconds", "openvpn_upstream_http", "openvpn_upstream_socks",
        }
        settings = load_settings(DATA_DIR)
        settings.update({k: v for k, v in body.items() if k in allowed})
        save_settings(settings, DATA_DIR)
        state = load_state(DATA_DIR)
        for key in ("routing_mode", "force_country", "fixed_node_id", "favorite_node_ids", "favorites_fallback", "connection_enabled"):
            if key in body:
                state[key] = body[key]
        save_state(state, DATA_DIR)

    def toggle_node(self, body: dict[str, Any], action: str) -> None:
        node_id = str(body.get("node_id", ""))
        nodes = load_nodes(DATA_DIR)
        state = load_state(DATA_DIR)
        for node in nodes:
            if node.get("id") == node_id:
                if action == "favorite":
                    node["favorite"] = not node.get("favorite", False)
                    favs = set(state.get("favorite_node_ids") or [])
                    if node["favorite"]:
                        favs.add(node_id)
                    else:
                        favs.discard(node_id)
                    state["favorite_node_ids"] = sorted(favs)
                else:
                    node["probe_status"] = "blacklisted"
                    node["probe_message"] = "manual blacklist"
        save_nodes(nodes, DATA_DIR)
        save_state(state, DATA_DIR)
        self.send_json({"ok": True})

    def render_login(self) -> str:
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_NAME}</title><style>{CSS}</style></head><body class="login">
<main class="login-box"><h1>{APP_NAME}</h1><p>{CN_NAME}</p>
<form id="loginForm">
<input id="u" autocomplete="username" placeholder="账号" value="admin">
<input id="p" autocomplete="current-password" placeholder="密码" type="password">
<button id="loginBtn" type="submit">登录</button><div id="err"></div>
</form></main>
<script>
const form=document.getElementById('loginForm');
const userInput=document.getElementById('u');
const passInput=document.getElementById('p');
const errBox=document.getElementById('err');
const loginBtn=document.getElementById('loginBtn');
form.addEventListener('submit', async (event)=>{{
 event.preventDefault();
 errBox.textContent='';
 loginBtn.disabled=true;
 try {{
  const base=location.pathname.replace(/\\/$/,'');
  const r=await fetch(base+'/api/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:userInput.value.trim(),password:passInput.value.trim()}})}});
  const j=await r.json();
  if(j.ok) location.href=base+'/';
  else errBox.textContent=j.error||'登录失败，请检查账号、密码和安全路径';
 }} catch(e) {{
  errBox.textContent='登录请求失败，请检查服务是否正常运行';
 }} finally {{
  loginBtn.disabled=false;
 }}
}});
</script></body></html>"""

    def render_app(self) -> str:
        secret = ensure_ui_auth(DATA_DIR)["secret_path"]
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_NAME}</title><style>{CSS}</style></head><body>
<header><div><b>{APP_NAME}</b><span>{CN_NAME}</span></div><nav>
<button onclick="tab('dash')">Dashboard</button><button onclick="tab('nodes')">节点</button><button onclick="tab('settings')">设置</button><button onclick="tab('logs')">日志</button><button onclick="api('/api/logout',{{}}).then(()=>location='/{secret}')">退出</button>
</nav></header>
<main>
<section id="dash"></section>
<section id="nodes" hidden><div class="toolbar"><select id="countryFilter" onchange="renderNodes()"></select><select id="statusFilter" onchange="renderNodes()"><option value="">全部状态</option><option>available</option><option>unavailable</option><option>not_checked</option><option>blacklisted</option></select><select id="sortBy" onchange="renderNodes()"><option value="latency_ms">延迟</option><option value="score">Score</option><option value="speed">Speed</option><option value="sessions">Sessions</option></select></div><div id="nodeTable"></div></section>
<section id="settings" hidden>{SETTINGS_HTML}</section>
<section id="logs" hidden><div class="toolbar"><select id="logLevel" onchange="loadLogs()"><option value="">全部</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select><button onclick="copyLogs()">复制日志</button><button onclick="api('/api/clear-logs',{{}}).then(loadLogs)">清空日志</button></div><pre id="logBox"></pre></section>
</main>
<script>{JS}</script></body></html>"""


CSS = """
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18202a;background:#f6f7f9}body{margin:0}header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:#111827;color:white}header span{margin-left:12px;color:#b7c0ce;font-size:13px}button,select,input{border:1px solid #cfd5df;background:white;border-radius:6px;padding:8px 10px;font:inherit}button{cursor:pointer;background:#1f6feb;color:white;border-color:#1f6feb}button.secondary{background:white;color:#243043}.login{display:grid;place-items:center;min-height:100vh}.login-box{display:grid;gap:12px;width:min(360px,calc(100vw - 40px));padding:28px;background:white;border:1px solid #dbe1ea;border-radius:8px}.login-box form{display:grid;gap:12px}.login-box #err{min-height:20px;color:#c92a2a;font-size:13px}main{padding:18px;max-width:1280px;margin:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.metric,.panel{background:white;border:1px solid #dbe1ea;border-radius:8px;padding:14px}.metric b{display:block;font-size:22px;margin-top:8px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.table{overflow:auto;background:white;border:1px solid #dbe1ea;border-radius:8px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;border-bottom:1px solid #edf0f4;text-align:left;white-space:nowrap}.ok{color:#087f5b}.bad{color:#c92a2a}pre{white-space:pre-wrap;background:#111827;color:#dbeafe;padding:14px;border-radius:8px;min-height:420px}.form{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.form label{display:grid;gap:6px}.hint{color:#5b6573;font-size:13px}
"""

SETTINGS_HTML = """
<div class="panel"><div class="form">
<label>路由模式<select id="routing_mode"><option>auto</option><option>fixed_region</option><option>fixed_ip</option><option>favorites</option></select></label>
<label>固定国家/地区<input id="force_country" placeholder="JP / KR / US"></label>
<label>固定节点 ID<input id="fixed_node_id"></label>
<label>代理监听地址<input id="local_proxy_host" placeholder="127.0.0.1"></label>
<label>代理端口<input id="local_proxy_port" type="number" value="8888"></label>
<label>代理认证用户名<input id="local_proxy_user" autocomplete="off"></label>
<label>代理认证密码<input id="local_proxy_password" type="password" autocomplete="new-password"></label>
<label>最大扫描节点数<input id="max_scan_rows" type="number"></label>
<label>目标可用节点数<input id="target_valid_nodes" type="number"></label>
<label>拉取间隔秒<input id="fetch_interval_seconds" type="number"></label>
<label>检测间隔秒<input id="check_interval_seconds" type="number"></label>
</div><p class="hint">IP 类型判断来自第三方数据库，仅供参考，不代表真实平台风控结果。公网代理监听必须设置代理认证。</p><button onclick="saveSettings()">保存设置</button></div>
"""

JS = r"""
let state={}, nodes=[], logs=[];
const base=location.pathname.replace(/\/$/,'');
async function api(path, body){const r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); const j=await r.json(); if(!r.ok) alert(j.error||j.message||'操作失败'); return j}
async function get(path){const r=await fetch(base+path); return await r.json()}
function tab(id){for(const s of document.querySelectorAll('main section'))s.hidden=s.id!==id;if(id==='logs')loadLogs();if(id==='nodes')renderNodes()}
async function refresh(){state=await get('/api/state');nodes=await get('/api/nodes');renderDash();renderNodes();fillSettings()}
function renderDash(){const active=nodes.find(n=>n.id===state.active_openvpn_node_id)||{};dash.innerHTML=`<div class="toolbar"><button onclick="api('/api/fetch',{}).then(refresh)">更新节点</button><button onclick="api('/api/check',{}).then(refresh)">立即检测</button><button onclick="api('/api/auto-connect',{}).then(refresh)">自动连接最佳节点</button><button onclick="api('/api/disconnect',{}).then(refresh)">断开连接</button><button onclick="api('/api/check-proxy',{}).then(refresh)">检测代理出口</button></div><div class="grid"><div class="metric">当前节点<b>${active.id||'未连接'}</b></div><div class="metric">出口 IP<b>${state.proxy_ip||'-'}</b></div><div class="metric">代理状态<b class="${state.proxy_ok?'ok':'bad'}">${state.proxy_ok?'正常':'异常'}</b></div><div class="metric">代理延迟<b>${state.proxy_latency_ms||0} ms</b></div><div class="metric">节点总数<b>${nodes.length}</b></div><div class="metric">可用节点<b>${nodes.filter(n=>n.probe_status==='available').length}</b></div><div class="metric">不可用节点<b>${nodes.filter(n=>n.probe_status==='unavailable').length}</b></div><div class="metric">路由模式<b>${state.routing_mode||'auto'}</b></div></div><div class="panel"><b>本地代理</b><p>HTTP/SOCKS5: http://127.0.0.1:8888</p><p class="hint">${state.proxy_error||''}</p></div>`}
function renderNodes(){let list=[...nodes];const c=countryFilter.value,s=statusFilter.value;if(c)list=list.filter(n=>n.country_short===c);if(s)list=list.filter(n=>n.probe_status===s);const sort=sortBy.value;list.sort((a,b)=>(a[sort]||999999)-(b[sort]||999999));countryFilter.innerHTML='<option value="">全部国家</option>'+[...new Set(nodes.map(n=>n.country_short).filter(Boolean))].sort().map(x=>`<option ${x===c?'selected':''}>${x}</option>`).join('');nodeTable.innerHTML=`<div class="table"><table><thead><tr><th>状态</th><th>国家</th><th>IP</th><th>HostName</th><th>协议</th><th>端口</th><th>延迟</th><th>Score</th><th>Speed</th><th>Sessions</th><th>ASN</th><th>IP 类型</th><th>活动</th><th>收藏</th><th>操作</th></tr></thead><tbody>${list.map(n=>`<tr><td>${n.probe_status}</td><td>${n.country_short}</td><td>${n.ip}</td><td>${n.host_name||''}</td><td>${n.proto}</td><td>${n.remote_port}</td><td>${n.latency_ms||n.ping||0}</td><td>${n.score||0}</td><td>${n.speed||0}</td><td>${n.sessions||0}</td><td>${n.asn||''}</td><td>${n.ip_type||''}</td><td>${n.active?'是':''}</td><td>${n.favorite?'是':''}</td><td><button onclick="api('/api/connect',{node_id:'${n.id}'}).then(refresh)">连接</button> <button class="secondary" onclick="api('/api/favorite',{node_id:'${n.id}'}).then(refresh)">收藏</button> <button class="secondary" onclick="api('/api/blacklist',{node_id:'${n.id}'}).then(refresh)">拉黑</button> <a href="${base}/api/download/${n.id}">下载</a></td></tr>`).join('')}</tbody></table></div>`}
function fillSettings(){for(const k of ['routing_mode','force_country','fixed_node_id'])if(document.getElementById(k))document.getElementById(k).value=state[k]||'';local_proxy_host.value='127.0.0.1';local_proxy_port.value='8888'}
async function saveSettings(){const ids=['routing_mode','force_country','fixed_node_id','local_proxy_host','local_proxy_port','local_proxy_user','local_proxy_password','max_scan_rows','target_valid_nodes','fetch_interval_seconds','check_interval_seconds'];const body={};for(const id of ids){const el=document.getElementById(id);if(el&&el.value)body[id]=el.type==='number'?Number(el.value):el.value}await api('/api/settings',body);refresh()}
async function loadLogs(){logs=await get('/api/logs?level='+(logLevel.value||''));logBox.textContent=logs.map(x=>`${x.timestamp} ${x.level} ${x.module} ${x.message}`).join('\n')}
function copyLogs(){navigator.clipboard.writeText(logBox.textContent)}
refresh();setInterval(refresh,15000);
"""


def run() -> None:
    logger.write("INFO", "Main", "Starting StellaVPN Gate")
    RUNTIME.start_proxy()
    RUNTIME.start_maintenance()
    host = os.getenv("UI_HOST", UI_HOST)
    port = int(os.getenv("UI_PORT", str(UI_PORT)))
    server_cls = DualStackServer if ":" in host else ThreadingHTTPServer
    server = server_cls((host, port), Handler)
    auth = ensure_ui_auth(DATA_DIR)
    logger.write("INFO", "UI", "Web UI started", url=f"http://{public_server_ip()}:{port}/{auth['secret_path']}")
    try:
        server.serve_forever()
    finally:
        RUNTIME.stop_event.set()
        if RUNTIME.proxy_server:
            RUNTIME.proxy_server.stop()


if __name__ == "__main__":
    run()
