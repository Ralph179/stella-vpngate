#!/usr/bin/env python3
"""Core utilities for StellaVPN Gate.

This module intentionally uses the Python standard library only. It contains
VPNGate CSV parsing, JSON persistence, logging, OpenVPN process management and
small diagnostics helpers used by both the web service and CLI.
"""

from __future__ import annotations

import base64
import csv
import string
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = int(os.getenv("FETCH_INTERVAL_SECONDS", "1260"))
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "1260"))
TARGET_VALID_NODES = int(os.getenv("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.getenv("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.getenv("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.getenv("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.getenv("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.getenv("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.getenv("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.getenv("LOCAL_PROXY_PORT", "8888"))
UI_HOST = os.getenv("UI_HOST", "::")
UI_PORT = int(os.getenv("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.getenv("INVALID_BACKOFF_SECONDS", "1800"))
DATA_DIR = Path(os.getenv("VPNGATE_DATA_DIR", os.getenv("DATA_DIR", "./data"))).resolve()
ROUTE_TABLE = "100"
ROUTE_MARK = "0x64"


DEFAULT_STATE: dict[str, Any] = {
    "active_openvpn_node_id": "",
    "is_connecting": False,
    "last_fetch_at": 0,
    "last_fetch_status": "",
    "last_fetch_message": "",
    "last_check_message": "",
    "proxy_ok": False,
    "proxy_ip": "",
    "proxy_latency_ms": 0,
    "proxy_error": "",
    "routing_mode": "auto",
    "force_country": "",
    "fixed_node_id": "",
    "favorite_node_ids": [],
    "favorites_fallback": True,
    "connection_enabled": True,
    "local_proxy": "http://127.0.0.1:8888",
}

SENSITIVE_KEYS = ("password", "pass", "authorization", "proxy-authorization", "token")


def now_ts() -> int:
    return int(time.time())


def ensure_dirs(data_dir: Path = DATA_DIR) -> None:
    for path in (data_dir, data_dir / "configs", data_dir / "logs"):
        path.mkdir(parents=True, exist_ok=True)


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default.copy() if isinstance(default, dict) else default


def save_json(path: Path, value: Any, mode: int | None = None) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if any(s in k.lower() for s in SENSITIVE_KEYS):
                out[k] = "***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class JsonLogger:
    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self.lock = threading.Lock()

    def write(self, level: str, module: str, message: str, **fields: Any) -> None:
        ensure_dirs(self.data_dir)
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level.upper(),
            "module": module,
            "message": message,
        }
        if fields:
            record["fields"] = redact(fields)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        path = self.data_dir / "logs" / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        with self.lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        self.cleanup()

    def cleanup(self) -> None:
        cutoff = datetime.now() - timedelta(days=3)
        log_dir = self.data_dir / "logs"
        if not log_dir.exists():
            return
        for path in log_dir.glob("*.jsonl"):
            try:
                day = datetime.strptime(path.stem, "%Y-%m-%d")
                if day < cutoff:
                    path.unlink()
            except (ValueError, OSError):
                continue

    def tail(self, limit: int = 200, level: str = "", module: str = "") -> list[dict[str, Any]]:
        log_dir = self.data_dir / "logs"
        if not log_dir.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(log_dir.glob("*.jsonl"))[-4:]:
            try:
                with path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if level and item.get("level") != level.upper():
                            continue
                        if module and item.get("module") != module:
                            continue
                        rows.append(item)
            except OSError:
                continue
        return rows[-limit:]


logger = JsonLogger(DATA_DIR)


def state_path(data_dir: Path = DATA_DIR) -> Path:
    return data_dir / "state.json"


def nodes_path(data_dir: Path = DATA_DIR) -> Path:
    return data_dir / "nodes.json"


def auth_path(data_dir: Path = DATA_DIR) -> Path:
    return data_dir / "ui_auth.json"


def blacklist_path(data_dir: Path = DATA_DIR) -> Path:
    return data_dir / "blacklist.json"


def vpn_auth_path(data_dir: Path = DATA_DIR) -> Path:
    return data_dir / "vpngate_auth.txt"


def load_state(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    state = DEFAULT_STATE.copy()
    state.update(load_json(state_path(data_dir), {}))
    state["local_proxy"] = f"http://{os.getenv('LOCAL_PROXY_HOST', LOCAL_PROXY_HOST)}:{int(os.getenv('LOCAL_PROXY_PORT', str(LOCAL_PROXY_PORT)))}"
    return state


def save_state(state: dict[str, Any], data_dir: Path = DATA_DIR) -> None:
    save_json(state_path(data_dir), state)


def load_nodes(data_dir: Path = DATA_DIR) -> list[dict[str, Any]]:
    nodes = load_json(nodes_path(data_dir), [])
    return nodes if isinstance(nodes, list) else []


def save_nodes(nodes: list[dict[str, Any]], data_dir: Path = DATA_DIR) -> None:
    save_json(nodes_path(data_dir), nodes)


def ensure_vpngate_auth_file(data_dir: Path = DATA_DIR) -> Path:
    path = vpn_auth_path(data_dir)
    text = f"{os.getenv('OPENVPN_AUTH_USER', OPENVPN_AUTH_USER)}\n{os.getenv('OPENVPN_AUTH_PASS', OPENVPN_AUTH_PASS)}\n"
    atomic_write_text(path, text, 0o600)
    return path


def generate_ui_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_ui_auth(data_dir: Path = DATA_DIR) -> dict[str, str]:
    import hashlib

    ensure_dirs(data_dir)
    current = load_json(auth_path(data_dir), {})
    if current.get("username") and current.get("password_hash") and current.get("secret_path"):
        return current
    password = generate_ui_password()
    salt = secrets.token_hex(16)
    record = {
        "username": "admin",
        "password_hash": hashlib.sha256((salt + password).encode()).hexdigest(),
        "salt": salt,
        "secret_path": secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12],
        "initial_password": password,
        "sessions": {},
    }
    save_json(auth_path(data_dir), record, 0o600)
    return record


def verify_ui_password(username: str, password: str, data_dir: Path = DATA_DIR) -> bool:
    import hashlib

    record = ensure_ui_auth(data_dir)
    username = username.strip()
    password = password.strip()
    if username != record.get("username"):
        return False
    return hashlib.sha256((record.get("salt", "") + password).encode()).hexdigest() == record.get("password_hash")


def reset_ui_password(data_dir: Path = DATA_DIR) -> str:
    import hashlib

    record = ensure_ui_auth(data_dir)
    password = generate_ui_password()
    salt = secrets.token_hex(16)
    record.update({
        "password_hash": hashlib.sha256((salt + password).encode()).hexdigest(),
        "salt": salt,
        "initial_password": password,
        "sessions": {},
    })
    save_json(auth_path(data_dir), record, 0o600)
    return password


def reset_secret_path(data_dir: Path = DATA_DIR) -> str:
    record = ensure_ui_auth(data_dir)
    secret_path = secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
    record["secret_path"] = secret_path
    record["sessions"] = {}
    save_json(auth_path(data_dir), record, 0o600)
    return secret_path


def make_session(data_dir: Path = DATA_DIR) -> str:
    record = ensure_ui_auth(data_dir)
    token = secrets.token_urlsafe(32)
    sessions = record.setdefault("sessions", {})
    sessions[token] = now_ts() + 86400
    save_json(auth_path(data_dir), record, 0o600)
    return token


def valid_session(token: str, data_dir: Path = DATA_DIR) -> bool:
    if not token:
        return False
    record = ensure_ui_auth(data_dir)
    sessions = record.get("sessions", {})
    expiry = sessions.get(token, 0)
    if expiry > now_ts():
        return True
    if token in sessions:
        sessions.pop(token, None)
        save_json(auth_path(data_dir), record, 0o600)
    return False


def drop_session(token: str, data_dir: Path = DATA_DIR) -> None:
    record = ensure_ui_auth(data_dir)
    sessions = record.get("sessions", {})
    sessions.pop(token, None)
    save_json(auth_path(data_dir), record, 0o600)


def parse_remote(config_text: str) -> tuple[str, int, str]:
    proto = "udp"
    remote_host = ""
    remote_port = 1194
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        if parts[0] == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            try:
                remote_port = int(parts[2])
            except ValueError:
                remote_port = 1194
            if len(parts) >= 4:
                proto = parts[3].lower()
            break
    return remote_host, remote_port, proto


def sanitize_node_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")[:180]


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_vpngate_csv(csv_text: str, data_dir: Path = DATA_DIR, max_rows: int = MAX_SCAN_ROWS) -> list[dict[str, Any]]:
    ensure_dirs(data_dir)
    lines = [line for line in csv_text.splitlines() if line and not line.startswith("*") and not line.startswith("#")]
    reader = csv.DictReader(lines)
    seen: set[str] = set()
    nodes: list[dict[str, Any]] = []
    for idx, row in enumerate(reader):
        if idx >= max_rows:
            break
        ip = (row.get("IP") or "").strip()
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not ip or not encoded or ip in seen:
            continue
        seen.add(ip)
        try:
            config_text = base64.b64decode(encoded + "===" ).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.write("WARNING", "API", "OpenVPN config decode failed", ip=ip, error=str(exc))
            continue
        remote_host, remote_port, proto = parse_remote(config_text)
        if not remote_host:
            remote_host = ip
        country_short = (row.get("CountryShort") or "XX").strip().upper() or "XX"
        node_id = sanitize_node_id(f"{country_short}_{ip}_{remote_port}_{proto}")
        config_file = data_dir / "configs" / f"{node_id}.ovpn"
        atomic_write_text(config_file, normalize_openvpn_config(config_text))
        nodes.append({
            "id": node_id,
            "country": row.get("CountryLong", ""),
            "country_short": country_short,
            "host_name": row.get("HostName", ""),
            "ip": ip,
            "score": parse_int(row.get("Score")),
            "ping": parse_int(row.get("Ping")),
            "speed": parse_int(row.get("Speed")),
            "sessions": parse_int(row.get("NumVpnSessions")),
            "owner": row.get("Operator", ""),
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
            "latency_ms": 0,
            "config_file": str(config_file),
            "config_text": config_text,
            "proto": proto,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "fetched_at": now_ts(),
            "probe_status": "not_checked",
            "probe_message": "",
            "probed_at": 0,
            "active": False,
            "favorite": False,
        })
    return nodes


def normalize_openvpn_config(config_text: str) -> str:
    lines = []
    for line in config_text.splitlines():
        if line.strip().startswith(("auth-user-pass", "route ", "redirect-gateway", "dhcp-option DNS")):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip() + "\n"


def fetch_vpngate_nodes(data_dir: Path = DATA_DIR, api_url: str = API_URL) -> list[dict[str, Any]]:
    logger.write("INFO", "API", "Fetching VPNGate official node list", url=api_url)
    req = urllib.request.Request(api_url, headers={"User-Agent": "StellaVPNGate/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(diagnose_fetch_error(exc)) from exc
    nodes = parse_vpngate_csv(body, data_dir=data_dir, max_rows=int(os.getenv("MAX_SCAN_ROWS", str(MAX_SCAN_ROWS))))
    existing = {n["id"]: n for n in load_nodes(data_dir)}
    favorites = {n["id"] for n in existing.values() if n.get("favorite")}
    active_id = load_state(data_dir).get("active_openvpn_node_id", "")
    for node in nodes:
        old = existing.get(node["id"], {})
        node["favorite"] = node["id"] in favorites
        if old.get("probe_status") in ("available", "blacklisted"):
            node.update({
                "probe_status": old.get("probe_status", "not_checked"),
                "probe_message": old.get("probe_message", ""),
                "latency_ms": old.get("latency_ms", 0),
                "probed_at": old.get("probed_at", 0),
                "ip_type": old.get("ip_type", ""),
                "asn": old.get("asn", ""),
                "as_name": old.get("as_name", ""),
            })
        node["active"] = node["id"] == active_id
    save_nodes(nodes, data_dir)
    state = load_state(data_dir)
    state.update({"last_fetch_at": now_ts(), "last_fetch_status": "ok", "last_fetch_message": f"Fetched {len(nodes)} nodes"})
    save_state(state, data_dir)
    logger.write("INFO", "API", "Fetched VPNGate nodes", count=len(nodes))
    return nodes


def diagnose_fetch_error(exc: Exception) -> str:
    text = str(exc)
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLError):
            return f"SSL verification failed or TLS blocked: {reason}"
        if isinstance(reason, socket.gaierror):
            return f"DNS resolution failed for VPNGate API: {reason}"
        return f"VPNGate API connection failed: {reason or text}"
    return f"VPNGate API returned unexpected data: {text}"


def tcp_probe(host: str, port: int, timeout: float = 5.0) -> tuple[bool, int, str]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = int((time.monotonic() - start) * 1000)
            return True, latency_ms, "tcp ok"
    except OSError as exc:
        return False, 0, str(exc)


def ping_probe(host: str, timeout: int = 3) -> int:
    cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    match = re.search(r"time=([0-9.]+)\s*ms", proc.stdout)
    return int(float(match.group(1))) if match else 0


def classify_openvpn_log(text: str) -> tuple[bool, str]:
    if "Initialization Sequence Completed" in text:
        return True, "Initialization Sequence Completed"
    checks = [
        "AUTH_FAILED",
        "TLS Error",
        "connection timeout",
        "cannot open TUN/TAP dev",
        "permission denied",
        "fatal",
        "route",
    ]
    lowered = text.lower()
    for needle in checks:
        if needle.lower() in lowered:
            return False, needle
    return False, "OpenVPN initialization timed out"


def run_openvpn_probe(node: dict[str, Any], dev: str, data_dir: Path = DATA_DIR) -> tuple[bool, str]:
    if shutil.which(os.getenv("OPENVPN_CMD", OPENVPN_CMD)) is None:
        return False, "openvpn is not installed"
    ensure_vpngate_auth_file(data_dir)
    cmd = [
        os.getenv("OPENVPN_CMD", OPENVPN_CMD),
        "--config", node["config_file"],
        "--dev", dev,
        "--dev-type", "tun",
        "--pull-filter", "ignore", "route-ipv6",
        "--pull-filter", "ignore", "ifconfig-ipv6",
        "--route-delay", "2",
        "--connect-retry-max", "1",
        "--connect-timeout", "15",
        "--auth-user-pass", str(vpn_auth_path(data_dir)),
        "--auth-nocache",
        "--verb", "3",
        "--route-nopull",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except PermissionError:
        return False, "permission denied starting openvpn"
    except OSError as exc:
        return False, str(exc)
    deadline = time.time() + int(os.getenv("OPENVPN_TEST_TIMEOUT_SECONDS", str(OPENVPN_TEST_TIMEOUT_SECONDS)))
    output = []
    try:
        while time.time() < deadline:
            if proc.stdout:
                line = proc.stdout.readline()
                if line:
                    output.append(line)
                    ok, msg = classify_openvpn_log("".join(output))
                    if ok or msg != "OpenVPN initialization timed out":
                        return ok, msg
            if proc.poll() is not None:
                break
            time.sleep(0.2)
        return classify_openvpn_log("".join(output))
    finally:
        terminate_process(proc)


def test_node(node: dict[str, Any], data_dir: Path = DATA_DIR, dev: str = "tun10", openvpn: bool = False) -> dict[str, Any]:
    node = node.copy()
    node["probe_status"] = "testing"
    host = node.get("remote_host") or node.get("ip")
    port = int(node.get("remote_port") or 1194)
    proto = str(node.get("proto", "udp")).lower()
    latency = ping_probe(str(node.get("ip") or host))
    if proto == "tcp":
        ok, tcp_latency, message = tcp_probe(host, port)
        latency = latency or tcp_latency
        if not ok:
            node.update({"probe_status": "unavailable", "probe_message": message, "latency_ms": latency, "probed_at": now_ts()})
            return node
    if openvpn:
        ok, message = run_openvpn_probe(node, dev=dev, data_dir=data_dir)
    else:
        ok, message = True, "basic probe ok"
    node.update({
        "probe_status": "available" if ok else "unavailable",
        "probe_message": message,
        "latency_ms": latency,
        "probed_at": now_ts(),
    })
    return node


def check_nodes(data_dir: Path = DATA_DIR, limit: int | None = None, openvpn: bool = False) -> list[dict[str, Any]]:
    nodes = load_nodes(data_dir)
    limit = limit or int(os.getenv("TARGET_VALID_NODES", str(TARGET_VALID_NODES)))
    candidates = [n for n in nodes if n.get("probe_status") != "blacklisted"][: int(os.getenv("MAX_SCAN_ROWS", str(MAX_SCAN_ROWS)))]
    checked: dict[str, dict[str, Any]] = {}
    max_workers = min(8, max(1, limit * 2))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(test_node, node, data_dir, f"tun{10 + i}", openvpn): node for i, node in enumerate(candidates)}
        available = 0
        for future in as_completed(futures):
            result = future.result()
            checked[result["id"]] = result
            if result.get("probe_status") == "available":
                available += 1
            if available >= limit:
                break
    merged = [checked.get(n["id"], n) for n in nodes]
    save_nodes(merged, data_dir)
    state = load_state(data_dir)
    state["last_check_message"] = f"Checked {len(checked)} nodes, available {sum(1 for n in merged if n.get('probe_status') == 'available')}"
    save_state(state, data_dir)
    logger.write("INFO", "VPN", "Node check completed", checked=len(checked))
    return merged


def terminate_process(proc: subprocess.Popen[Any], timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def run_cmd(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def kill_existing_openvpn() -> None:
    try:
        run_cmd(["pkill", "-f", "stella-vpngate.*openvpn"], timeout=5)
    except Exception:
        pass


def configure_policy_routing(dev: str = "tun0") -> None:
    cmds = [
        ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"],
        ["ip", "route", "replace", "default", "dev", dev, "table", ROUTE_TABLE],
        ["ip", "rule", "add", "fwmark", ROUTE_MARK, "table", ROUTE_TABLE],
    ]
    for cmd in cmds:
        proc = run_cmd(cmd, timeout=10)
        if proc.returncode not in (0, 2):
            logger.write("WARNING", "Routing", "Routing command failed", command=" ".join(cmd), stderr=proc.stderr.strip())


def cleanup_policy_routing() -> None:
    cmds = [
        ["ip", "rule", "del", "fwmark", ROUTE_MARK, "table", ROUTE_TABLE],
        ["ip", "route", "flush", "table", ROUTE_TABLE],
    ]
    for cmd in cmds:
        try:
            run_cmd(cmd, timeout=10)
        except Exception:
            pass


def connect_node(node_id: str, data_dir: Path = DATA_DIR) -> tuple[bool, str]:
    nodes = load_nodes(data_dir)
    node = next((n for n in nodes if n.get("id") == node_id), None)
    if not node:
        return False, "node not found"
    if shutil.which(os.getenv("OPENVPN_CMD", OPENVPN_CMD)) is None:
        return False, "openvpn is not installed"
    state = load_state(data_dir)
    state["is_connecting"] = True
    save_state(state, data_dir)
    disconnect_current(data_dir, update_state=False)
    ensure_vpngate_auth_file(data_dir)
    cmd = [
        os.getenv("OPENVPN_CMD", OPENVPN_CMD),
        "--config", node["config_file"],
        "--dev", "tun0",
        "--dev-type", "tun",
        "--pull-filter", "ignore", "route-ipv6",
        "--pull-filter", "ignore", "ifconfig-ipv6",
        "--route-delay", "2",
        "--connect-retry-max", "1",
        "--connect-timeout", "15",
        "--auth-user-pass", str(vpn_auth_path(data_dir)),
        "--auth-nocache",
        "--verb", "3",
        "--route-nopull",
        "--writepid", str(data_dir / "openvpn.pid"),
    ]
    log_file = data_dir / "logs" / "openvpn-current.log"
    fh = log_file.open("a", encoding="utf-8")
    try:
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    except Exception as exc:
        fh.close()
        state["is_connecting"] = False
        save_state(state, data_dir)
        return False, str(exc)
    deadline = time.time() + int(os.getenv("OPENVPN_TEST_TIMEOUT_SECONDS", str(OPENVPN_TEST_TIMEOUT_SECONDS)))
    ok = False
    message = "OpenVPN initialization timed out"
    try:
        while time.time() < deadline:
            text = log_file.read_text(encoding="utf-8", errors="replace")[-20000:]
            ok, message = classify_openvpn_log(text)
            if ok or message != "OpenVPN initialization timed out":
                break
            if proc.poll() is not None:
                break
            time.sleep(1)
    finally:
        fh.close()
    if ok:
        configure_policy_routing("tun0")
        for n in nodes:
            n["active"] = n["id"] == node_id
        save_nodes(nodes, data_dir)
        state.update({"active_openvpn_node_id": node_id, "is_connecting": False})
        save_state(state, data_dir)
        logger.write("INFO", "VPN", "Connected node", node_id=node_id)
        return True, message
    terminate_pid_file(data_dir / "openvpn.pid")
    state["is_connecting"] = False
    save_state(state, data_dir)
    logger.write("ERROR", "VPN", "OpenVPN connection failed", node_id=node_id, error=message)
    return False, message


def terminate_pid_file(path: Path) -> None:
    try:
        pid = int(path.read_text().strip())
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        try:
            pid = int(path.read_text().strip())
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    try:
        path.unlink()
    except OSError:
        pass


def disconnect_current(data_dir: Path = DATA_DIR, update_state: bool = True) -> None:
    terminate_pid_file(data_dir / "openvpn.pid")
    kill_existing_openvpn()
    cleanup_policy_routing()
    nodes = load_nodes(data_dir)
    for node in nodes:
        node["active"] = False
    save_nodes(nodes, data_dir)
    if update_state:
        state = load_state(data_dir)
        state.update({"active_openvpn_node_id": "", "is_connecting": False})
        save_state(state, data_dir)
    logger.write("INFO", "VPN", "Disconnected current node")


def select_best_node(data_dir: Path = DATA_DIR) -> dict[str, Any] | None:
    state = load_state(data_dir)
    nodes = load_nodes(data_dir)
    available = [n for n in nodes if n.get("probe_status") == "available"]
    mode = state.get("routing_mode", "auto")
    if mode == "fixed_ip":
        wanted = state.get("fixed_node_id")
        return next((n for n in nodes if n.get("id") == wanted and n.get("probe_status") == "available"), None)
    if mode == "fixed_region":
        country = str(state.get("force_country", "")).upper()
        available = [n for n in available if n.get("country_short") == country]
    if mode == "favorites":
        favorite_ids = set(state.get("favorite_node_ids") or [])
        fav = [n for n in available if n.get("id") in favorite_ids or n.get("favorite")]
        available = fav or (available if state.get("favorites_fallback", True) else [])
    if not available:
        return None
    return sorted(available, key=lambda n: (n.get("latency_ms") or n.get("ping") or 999999, -(n.get("speed") or 0)))[0]


def check_proxy_health(host: str = "127.0.0.1", port: int = 8888, timeout: int = 15) -> dict[str, Any]:
    start = time.monotonic()
    req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "StellaVPNGate/1.0"})
    proxy = urllib.request.ProxyHandler({"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"})
    opener = urllib.request.build_opener(proxy)
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        data = json.loads(text)
        return {"ok": True, "ip": data.get("ip", ""), "latency_ms": int((time.monotonic() - start) * 1000), "error": ""}
    except Exception as exc:
        return {"ok": False, "ip": "", "latency_ms": 0, "error": str(exc)}


def lookup_ip_info(ip: str, timeout: int = 8) -> dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip_type": "unknown"}
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile,message"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"ip_type": "unknown", "error": str(exc)}
    if data.get("status") != "success":
        return {"ip_type": "unknown", "error": data.get("message", "")}
    if data.get("mobile"):
        ip_type = "mobile"
    elif data.get("hosting") or data.get("proxy"):
        ip_type = "hosting"
    else:
        ip_type = "residential"
    data["ip_type"] = ip_type
    return data


def public_server_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            return resp.read().decode().strip()
    except Exception:
        return "your_server_ip"


@dataclass
class Settings:
    local_proxy_host: str = LOCAL_PROXY_HOST
    local_proxy_port: int = LOCAL_PROXY_PORT
    local_proxy_user: str = os.getenv("LOCAL_PROXY_USER", "")
    local_proxy_password: str = os.getenv("LOCAL_PROXY_PASSWORD", "")
    ui_host: str = UI_HOST
    ui_port: int = UI_PORT


def load_settings(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    values = load_json(data_dir / "settings.json", {})
    return values if isinstance(values, dict) else {}


def save_settings(values: dict[str, Any], data_dir: Path = DATA_DIR) -> None:
    safe = {k: v for k, v in values.items() if k not in {"proxy_password_display"}}
    save_json(data_dir / "settings.json", safe, 0o600)
