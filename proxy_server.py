#!/usr/bin/env python3
"""HTTP and SOCKS5 local proxy for StellaVPN Gate."""

from __future__ import annotations

import base64
import errno
import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable

from vpn_utils import LOCAL_PROXY_HOST, LOCAL_PROXY_PORT, logger


PUBLIC_HOSTS = {"0.0.0.0", "::", ""}


@dataclass
class ProxyConfig:
    host: str = os.getenv("LOCAL_PROXY_HOST", LOCAL_PROXY_HOST)
    port: int = int(os.getenv("LOCAL_PROXY_PORT", str(LOCAL_PROXY_PORT)))
    user: str = os.getenv("LOCAL_PROXY_USER", "")
    password: str = os.getenv("LOCAL_PROXY_PASSWORD", "")
    bind_device: str = os.getenv("OPENVPN_BIND_DEVICE", "tun0")
    timeout: int = int(os.getenv("PROXY_TIMEOUT", "30"))
    max_connections: int = int(os.getenv("PROXY_MAX_CONNECTIONS", "256"))


def validate_proxy_config(config: ProxyConfig) -> None:
    if config.host in PUBLIC_HOSTS and (not config.user or not config.password):
        raise RuntimeError("Refusing to start public proxy listener without LOCAL_PROXY_USER and LOCAL_PROXY_PASSWORD")


class DualProxyServer:
    def __init__(self, config: ProxyConfig | None = None, log: Callable[..., None] | None = None) -> None:
        self.config = config or ProxyConfig()
        self.log = log or logger.write
        self.server: socket.socket | None = None
        self.shutdown = threading.Event()
        self.active_connections = 0
        self.active_lock = threading.Lock()

    def start(self) -> None:
        validate_proxy_config(self.config)
        family = socket.AF_INET6 if ":" in self.config.host else socket.AF_INET
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.config.host, self.config.port))
        srv.listen(128)
        srv.settimeout(1.0)
        self.server = srv
        self.log("INFO", "Proxy", "Proxy server started", host=self.config.host, port=self.config.port)
        while not self.shutdown.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.active_lock:
                if self.active_connections >= self.config.max_connections:
                    client.close()
                    self.log("WARNING", "Proxy", "Maximum connections reached")
                    continue
                self.active_connections += 1
            threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()

    def stop(self) -> None:
        self.shutdown.set()
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass

    def handle_client(self, client: socket.socket, addr: tuple) -> None:
        client.settimeout(self.config.timeout)
        try:
            first = client.recv(1, socket.MSG_PEEK)
            if not first:
                return
            if first == b"\x05":
                self.handle_socks5(client)
            else:
                self.handle_http(client)
        except Exception as exc:
            self.log("WARNING", "Proxy", "Proxy connection failed", peer=str(addr), error=str(exc))
        finally:
            try:
                client.close()
            except OSError:
                pass
            with self.active_lock:
                self.active_connections -= 1

    def authenticate(self, username: str, password: str) -> bool:
        if not self.config.user and not self.config.password:
            return True
        return username == self.config.user and password == self.config.password

    def handle_socks5(self, client: socket.socket) -> None:
        header = self.recv_exact(client, 2)
        if header[0] != 5:
            return
        methods = self.recv_exact(client, header[1])
        require_auth = bool(self.config.user or self.config.password)
        if require_auth and 2 in methods:
            client.sendall(b"\x05\x02")
            if not self.handle_socks5_auth(client):
                return
        elif not require_auth and 0 in methods:
            client.sendall(b"\x05\x00")
        else:
            client.sendall(b"\x05\xff")
            return
        req = self.recv_exact(client, 4)
        if req[0] != 5 or req[1] != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        host = self.read_socks_host(client, req[3])
        port = struct.unpack("!H", self.recv_exact(client, 2))[0]
        upstream = self.connect_target(host, port)
        bind_host, bind_port = upstream.getsockname()[:2]
        reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", int(bind_port))
        client.sendall(reply)
        self.relay(client, upstream)

    def handle_socks5_auth(self, client: socket.socket) -> bool:
        ver = self.recv_exact(client, 1)
        if ver != b"\x01":
            return False
        ulen = self.recv_exact(client, 1)[0]
        username = self.recv_exact(client, ulen).decode("utf-8", errors="replace")
        plen = self.recv_exact(client, 1)[0]
        password = self.recv_exact(client, plen).decode("utf-8", errors="replace")
        if self.authenticate(username, password):
            client.sendall(b"\x01\x00")
            return True
        client.sendall(b"\x01\x01")
        self.log("WARNING", "Proxy", "SOCKS5 authentication failed", user=username)
        return False

    def read_socks_host(self, client: socket.socket, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntoa(self.recv_exact(client, 4))
        if atyp == 3:
            length = self.recv_exact(client, 1)[0]
            return self.recv_exact(client, length).decode("idna")
        if atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, self.recv_exact(client, 16))
        raise RuntimeError("unsupported socks address type")

    def handle_http(self, client: socket.socket) -> None:
        data = self.recv_until(client, b"\r\n\r\n", 65536)
        if not data:
            return
        header_blob, _, buffered_body = data.partition(b"\r\n\r\n")
        header_text = header_blob.decode("iso-8859-1", errors="replace")
        lines = header_text.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = self.parse_headers(lines[1:])
        if not self.check_http_auth(headers):
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"StellaVPN Gate\"\r\nContent-Length: 0\r\n\r\n")
            return
        if method.upper() == "CONNECT":
            host, port = self.parse_host_port(target, 443)
            upstream = self.connect_target(host, port)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.relay(client, upstream)
            return
        host, port, path = self.parse_http_target(target, headers)
        upstream = self.connect_target(host, port)
        clean_headers = [lines[0].replace(target, path, 1)]
        for line in lines[1:]:
            if line.lower().startswith(("proxy-authorization:", "proxy-connection:")):
                continue
            clean_headers.append(line)
        upstream.sendall("\r\n".join(clean_headers).encode("iso-8859-1", errors="replace") + b"\r\n\r\n" + buffered_body)
        self.relay(client, upstream)

    def check_http_auth(self, headers: dict[str, str]) -> bool:
        if not self.config.user and not self.config.password:
            return True
        auth = headers.get("proxy-authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return False
        ok = self.authenticate(username, password)
        if not ok:
            self.log("WARNING", "Proxy", "HTTP proxy authentication failed", user=username)
        return ok

    @staticmethod
    def parse_headers(lines: list[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.lower().strip()] = v.strip()
        return headers

    @staticmethod
    def parse_host_port(value: str, default_port: int) -> tuple[str, int]:
        if value.startswith("[") and "]" in value:
            host, _, rest = value[1:].partition("]")
            port = int(rest[1:]) if rest.startswith(":") else default_port
            return host, port
        if ":" in value:
            host, port = value.rsplit(":", 1)
            return host, int(port)
        return value, default_port

    def parse_http_target(self, target: str, headers: dict[str, str]) -> tuple[str, int, str]:
        if target.startswith("http://"):
            rest = target[7:]
            host_port, _, path = rest.partition("/")
            host, port = self.parse_host_port(host_port, 80)
            return host, port, "/" + path
        host = headers.get("host", "")
        if not host:
            raise RuntimeError("missing Host header")
        h, p = self.parse_host_port(host, 80)
        return h, p, target

    def connect_target(self, host: str, port: int) -> socket.socket:
        last_error: OSError | None = None
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.config.timeout)
            self.try_bind_device(sock)
            try:
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        raise RuntimeError(f"connect target failed: {last_error}")

    def try_bind_device(self, sock: socket.socket) -> None:
        if not self.config.bind_device:
            return
        try:
            sock.setsockopt(socket.SOL_SOCKET, 25, self.config.bind_device.encode() + b"\0")
        except OSError as exc:
            if exc.errno not in (errno.ENODEV, errno.EPERM, errno.EACCES):
                self.log("WARNING", "Proxy", "SO_BINDTODEVICE failed", error=str(exc))

    def relay(self, left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, self.config.timeout)
                if exceptional or not readable:
                    break
                for src in readable:
                    dst = right if src is left else left
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
        finally:
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            data = sock.recv(remaining)
            if not data:
                raise RuntimeError("unexpected eof")
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)

    @staticmethod
    def recv_until(sock: socket.socket, marker: bytes, limit: int) -> bytes:
        data = b""
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > limit:
                raise RuntimeError("request header too large")
        return data


def run_proxy_forever() -> None:
    server = DualProxyServer()
    while True:
        try:
            server.start()
        except RuntimeError as exc:
            logger.write("ERROR", "Proxy", str(exc))
            raise
        except OSError as exc:
            logger.write("ERROR", "Proxy", "Proxy server crashed", error=str(exc))
            time.sleep(3)


if __name__ == "__main__":
    run_proxy_forever()
