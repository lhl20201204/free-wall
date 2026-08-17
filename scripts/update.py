from __future__ import annotations

import gzip
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.yaml"
OUTPUT = ROOT / "output" / "clash.yaml"
STATUS = ROOT / "output" / "source-status.json"
CACHE = ROOT / ".cache"
MIHOMO_VERSION = "v1.19.29"
DELAY_URL = os.getenv("DELAY_URL", "http://www.gstatic.com/generate_204")
SKIP_TYPES = {
    "vless",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
    "ssh",
    "anytls",
    "mieru",
}
SS_CIPHERS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "chacha20",
    "salsa20",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


MAX_NODES = env_int("MAX_NODES", 200, 10, 1000)
FAST_GROUP = env_int("FAST_GROUP", 20, 5, 50)
FETCH_TIMEOUT = env_int("FETCH_TIMEOUT", 20, 5, 60)
FETCH_WORKERS = env_int("FETCH_WORKERS", 8, 1, 16)
TCP_TIMEOUT = env_int("TCP_TIMEOUT", 2, 1, 8)
TCP_WORKERS = env_int("TCP_WORKERS", 80, 8, 200)
DELAY_CANDIDATES = env_int("DELAY_CANDIDATES", 500, 20, 2000)
DELAY_TIMEOUT_MS = env_int("DELAY_TIMEOUT_MS", 3000, 500, 8000)
DELAY_WORKERS = env_int("DELAY_WORKERS", 24, 4, 64)


def fetch(url: str) -> dict:
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("url must be http(s)")
    request = urllib.request.Request(url, headers={"User-Agent": "free-vpn-clash-aggregator/1.0"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
        body = response.read()
    parsed = yaml.safe_load(body) or {}
    if not isinstance(parsed, dict):
        raise ValueError("top-level YAML value is not a mapping")
    return parsed


def fingerprint(proxy: dict) -> tuple:
    fields = ("type", "server", "port", "uuid", "password", "public-key", "private-key", "token")
    return tuple(str(proxy.get(field, "")) for field in fields)


def supported_proxy(proxy: dict) -> bool:
    proxy_type = str(proxy.get("type", "")).strip().lower()
    if proxy_type in SKIP_TYPES:
        return False
    cipher = str(proxy.get("cipher") or "").strip().lower()
    if proxy_type in {"ss", "ssr"}:
        return cipher in SS_CIPHERS
    if proxy_type == "vmess":
        return (cipher or "auto") in VMESS_CIPHERS
    return True


def endpoint(proxy: dict) -> tuple[str, int] | None:
    host = str(proxy.get("server") or "").strip()
    if not host or len(host) > 253 or host.lower() in {"localhost", "127.0.0.1", "::1"}:
        return None
    try:
        port = int(str(proxy.get("port")).strip())
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def unique_name(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base} #{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def collect_from_source(source: dict) -> tuple[list[dict], dict]:
    name, url = source["name"], source["url"]
    try:
        document = fetch(url)
        candidates = document.get("proxies", [])
        if not isinstance(candidates, list):
            raise ValueError("proxies is not a list")
        proxies = []
        for proxy in candidates:
            if not isinstance(proxy, dict) or not proxy.get("name") or not proxy.get("type"):
                continue
            if not supported_proxy(proxy) or endpoint(proxy) is None:
                continue
            item = dict(proxy)
            item["name"] = str(item["name"]).strip()[:80]
            proxies.append(item)
        return proxies, {"name": name, "url": url, "ok": True, "received": len(candidates), "accepted": len(proxies)}
    except Exception as exc:
        return [], {"name": name, "url": url, "ok": False, "error": str(exc)}


def tcp_latency(host: str, port: int) -> float | None:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    target = None
    for family, socktype, proto, _, sockaddr in infos:
        ip_text = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip.is_global and not ip.is_multicast:
            target = (family, socktype, proto, sockaddr)
            break
    if target is None:
        return None
    family, socktype, proto, sockaddr = target
    sock = socket.socket(family, socktype, proto)
    try:
        sock.settimeout(TCP_TIMEOUT)
        started = time.perf_counter()
        sock.connect(sockaddr)
        return (time.perf_counter() - started) * 1000
    except OSError:
        return None
    finally:
        sock.close()


def probe_tcp(proxies: list[dict]) -> list[tuple[dict, float]]:
    def worker(proxy: dict) -> tuple[dict, float | None]:
        parsed = endpoint(proxy)
        if parsed is None:
            return proxy, None
        return proxy, tcp_latency(*parsed)

    alive: list[tuple[dict, float]] = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        futures = [pool.submit(worker, proxy) for proxy in proxies]
        for future in as_completed(futures):
            try:
                proxy, latency = future.result()
            except Exception:
                continue
            if latency is not None:
                alive.append((proxy, latency))
    alive.sort(key=lambda item: item[1])
    return alive


def pick_delay_candidates(alive: list[tuple[dict, float]]) -> list[dict]:
    selected: list[dict] = []
    seen: set[tuple] = set()
    by_server: dict[str, tuple[dict, float]] = {}
    for proxy, latency in alive:
        server = str(proxy.get("server", "")).strip().lower()
        if server not in by_server:
            by_server[server] = (proxy, latency)
    for proxy, _latency in sorted(by_server.values(), key=lambda item: item[1]):
        key = fingerprint(proxy)
        selected.append(proxy)
        seen.add(key)
        if len(selected) >= DELAY_CANDIDATES:
            return selected
    for proxy, _latency in alive:
        key = fingerprint(proxy)
        if key in seen:
            continue
        selected.append(proxy)
        seen.add(key)
        if len(selected) >= DELAY_CANDIDATES:
            break
    return selected


def mihomo_asset() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        os_name = "linux"
    elif system == "darwin":
        os_name = "darwin"
    else:
        raise RuntimeError(f"unsupported os for mihomo: {system}")
    if machine in {"x86_64", "amd64"}:
        arch = "amd64-compatible"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"unsupported arch for mihomo: {machine}")
    return f"mihomo-{os_name}-{arch}-{MIHOMO_VERSION}.gz"


def ensure_mihomo() -> Path | None:
    if os.getenv("DISABLE_DELAY_TEST", "").strip() in {"1", "true", "yes"}:
        return None
    configured = os.getenv("MIHOMO_BIN", "").strip()
    if configured:
        path = Path(configured)
        return path if path.exists() else None
    found = shutil.which("mihomo") or shutil.which("clash-meta")
    if found:
        return Path(found)
    CACHE.mkdir(parents=True, exist_ok=True)
    binary = CACHE / f"mihomo-{MIHOMO_VERSION}"
    if binary.exists() and os.access(binary, os.X_OK):
        return binary
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/{mihomo_asset()}"
    request = urllib.request.Request(url, headers={"User-Agent": "free-vpn-clash-aggregator/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = gzip.decompress(response.read())
    tmp = binary.with_suffix(".tmp")
    tmp.write_bytes(payload)
    tmp.chmod(0o755)
    tmp.replace(binary)
    return binary


def wait_api(api: str, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    last_error = "mihomo api did not start"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(api + "/version", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise RuntimeError(last_error)


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def delay_one(api: str, name: str) -> int | None:
    query = urllib.parse.urlencode({"url": DELAY_URL, "timeout": str(DELAY_TIMEOUT_MS)})
    path = urllib.parse.quote(name, safe="")
    request = urllib.request.Request(f"{api}/proxies/{path}/delay?{query}")
    try:
        with urllib.request.urlopen(request, timeout=DELAY_TIMEOUT_MS / 1000 + 3) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    delay = data.get("delay")
    if isinstance(delay, (int, float)) and 0 < delay < 65535:
        return int(delay)
    return None


def probe_delay(mihomo: Path, proxies: list[dict]) -> list[tuple[dict, int]]:
    mixed_port = unused_port()
    api_port = unused_port()
    api = f"http://127.0.0.1:{api_port}"
    config = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "global",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{api_port}",
        "unified-delay": True,
        "find-process-mode": "off",
        "proxies": proxies,
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [item["name"] for item in proxies]}],
        "rules": ["MATCH,DIRECT"],
    }
    with tempfile.TemporaryDirectory(prefix="clash-probe-") as tmp:
        workdir = Path(tmp)
        config_path = workdir / "config.yaml"
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        process = subprocess.Popen(
            [str(mihomo), "-f", str(config_path), "-d", str(workdir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_api(api)
            measured: list[tuple[dict, int]] = []
            with ThreadPoolExecutor(max_workers=DELAY_WORKERS) as pool:
                futures = {pool.submit(delay_one, api, proxy["name"]): proxy for proxy in proxies}
                for future in as_completed(futures):
                    delay = future.result()
                    if delay is not None:
                        measured.append((futures[future], delay))
            measured.sort(key=lambda item: item[1])
            return measured
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def rank_proxies(proxies: list[dict]) -> tuple[list[tuple[dict, int]], str, dict]:
    alive = probe_tcp(proxies)
    stats = {"collected": len(proxies), "tcp_alive": len(alive)}
    if not alive:
        return [], "tcp-rtt", stats
    method = "tcp-rtt"
    ranked: list[tuple[dict, int]] = [(proxy, int(latency)) for proxy, latency in alive]
    try:
        mihomo = ensure_mihomo()
    except Exception as exc:
        stats["mihomo_error"] = str(exc)
        mihomo = None
    if mihomo is not None:
        candidates = pick_delay_candidates(alive)
        stats["delay_tested"] = len(candidates)
        try:
            measured = probe_delay(mihomo, candidates)
            stats["delay_ok"] = len(measured)
            if measured:
                ranked = measured
                method = "mihomo-delay"
            else:
                stats["delay_fallback"] = "all delay tests failed"
        except Exception as exc:
            stats["delay_error"] = str(exc)
    return ranked, method, stats


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    config = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))
    entries = config.get("sources", [])
    collected: list[dict] = []
    seen: set[tuple] = set()
    used_names: set[str] = set()
    status = []
    with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, max(1, len(entries)))) as pool:
        futures = [pool.submit(collect_from_source, source) for source in entries]
        for future in as_completed(futures):
            proxies, item = future.result()
            added = 0
            for proxy in proxies:
                key = fingerprint(proxy)
                if key in seen:
                    continue
                seen.add(key)
                proxy["name"] = unique_name(proxy["name"], used_names)
                collected.append(proxy)
                added += 1
            if item.get("ok"):
                item["added"] = added
            status.append(item)

    if not collected:
        raise RuntimeError("all upstream sources failed or returned no Clash proxies")

    ranked, method, probe_stats = rank_proxies(collected)
    if not ranked:
        raise RuntimeError("no reachable Clash proxies after latency probing")

    selected = ranked[:MAX_NODES]
    used_output: set[str] = set()
    proxies = []
    for proxy, delay in selected:
        item = dict(proxy)
        item["name"] = unique_name(f"{delay}ms | {proxy['name']}", used_output)
        proxies.append(item)
    names = [proxy["name"] for proxy in proxies]
    fast_names = names[: min(FAST_GROUP, len(names))]
    generated = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "FAST", "type": "url-test", "url": DELAY_URL, "interval": 180, "tolerance": 50, "proxies": fast_names},
            {"name": "AUTO", "type": "url-test", "url": DELAY_URL, "interval": 180, "tolerance": 80, "proxies": names},
            {"name": "PROXY", "type": "select", "proxies": ["FAST", "AUTO", "DIRECT"] + names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("# Generated by scripts/update.py; do not edit.\n" + yaml.safe_dump(generated, allow_unicode=True, sort_keys=False), encoding="utf-8")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proxy_count": len(proxies),
        "method": method,
        **probe_stats,
        "sources": status,
    }
    STATUS.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"proxy_count": len(proxies), "method": method, **probe_stats, "sources": status}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
