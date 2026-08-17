from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.yaml"
OUTPUT = ROOT / "output" / "discovered-sources.yaml"
API = "https://api.github.com"
RAW_HOST = "raw.githubusercontent.com"
UA = "free-vpn-clash-aggregator/1.0"
MIN_PROXIES = 5
MAX_FILE_BYTES = 2_000_000
ALLOWED_HOSTS = {"api.github.com", RAW_HOST, "github.com"}
SKIP_PATH_PARTS = {".github", "node_modules", "vendor", "docs", "charts", "deploy", "k8s", "kubernetes"}
SKIP_FILE_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "action.yml",
    "action.yaml",
    "chart.yaml",
    "kustomization.yaml",
    "kustomization.yml",
    "dependabot.yml",
    ".pre-commit-config.yaml",
}
CODE_QUERIES = [
    'extension:yaml "proxy-groups" proxies',
    'extension:yml "proxy-groups" proxies',
    "filename:clash.yaml proxies",
    "filename:clash.yml proxies",
    "filename:Clash.yaml proxies",
    "filename:proxies.yaml proxies",
    "filename:nodes.yaml proxies",
    "path:subscribe proxies extension:yml",
]
REPO_QUERIES = [
    "clash subscribe in:name,description",
    "free clash yaml in:name,description",
    "free-node clash in:name,description",
    "topic:clash-config",
    "v2ray clash proxies in:name,description",
]
YAML_HINTS = ("clash", "proxies", "subscribe", "node", "nodes", "list", "free", "airport")
MAX_YAML_PER_REPO = 12


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


PER_PAGE = env_int("DISCOVER_PER_PAGE", 30, 10, 100)
MAX_PAGES = env_int("DISCOVER_MAX_PAGES", 1, 1, 5)
FETCH_TIMEOUT = env_int("FETCH_TIMEOUT", 15, 5, 40)
PROBE_WORKERS = env_int("PROBE_WORKERS", 8, 1, 16)
MAX_NEW = env_int("MAX_NEW_SOURCES", 20, 1, 50)


def token() -> str:
    return (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip()


def request_json(url: str, timeout: int = FETCH_TIMEOUT, retries: int = 5) -> dict | list:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"blocked host: {parsed.hostname}")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": UA,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    secret = token()
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    last_error: Exception | None = None
    for attempt in range(retries):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
                if len(payload) > MAX_FILE_BYTES:
                    raise ValueError("response too large")
                return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            last_error = RuntimeError(f"GitHub API {exc.code}: {detail}")
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code not in {403, 408, 429, 502, 503, 504} or attempt == retries - 1:
                raise last_error from exc
            wait = min(int(retry_after), 60) if retry_after and retry_after.isdigit() else min(2 ** attempt, 20)
            time.sleep(wait)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, BrokenPipeError) as exc:
            last_error = exc
            if attempt == retries - 1:
                raise RuntimeError(f"GitHub API network error: {exc}") from exc
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GitHub API failed: {last_error}")


def search(kind: str, query: str, page: int) -> list[dict]:
    params = urllib.parse.urlencode(
        {"q": query, "per_page": str(PER_PAGE), "page": str(page), "sort": "indexed" if kind == "code" else "stars"}
    )
    path = "/search/code" if kind == "code" else "/search/repositories"
    data = request_json(f"{API}{path}?{params}")
    if not isinstance(data, dict):
        return []
    items = data.get("items") or []
    return items if isinstance(items, list) else []


def html_to_raw(html_url: str) -> str | None:
    parsed = urllib.parse.urlparse(html_url)
    if parsed.hostname != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        return None
    owner, repo, _blob, ref, *path_parts = parts
    if not path_parts:
        return None
    path = "/".join(urllib.parse.unquote(part) for part in path_parts)
    return f"https://{RAW_HOST}/{owner}/{repo}/{urllib.parse.quote(ref)}/{path}"


def yaml_path(path: str) -> bool:
    parts = Path(path).parts
    name = Path(path).name
    if any(part in SKIP_PATH_PARTS for part in parts):
        return False
    if name.lower() in SKIP_FILE_NAMES:
        return False
    return name.lower().endswith((".yaml", ".yml"))


def load_existing() -> tuple[list[dict], set[str], set[str]]:
    config = yaml.safe_load(SOURCES.read_text(encoding="utf-8")) or {}
    entries = config.get("sources") or []
    urls: set[str] = set()
    repos: set[str] = set()
    for item in entries:
        url = str(item.get("url", "")).strip()
        name = str(item.get("name", "")).strip().lower()
        urls.add(url.rstrip("/"))
        if "/" in name:
            repos.add(name.lower())
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname == RAW_HOST:
            bits = [part for part in parsed.path.split("/") if part]
            if len(bits) >= 2:
                repos.add(f"{bits[0]}/{bits[1]}".lower())
    return entries, urls, repos


def collect_code_candidates() -> tuple[list[dict], dict]:
    stats = {"ran": False, "queries_ok": 0, "queries_failed": 0, "hits": 0}
    if not token():
        print("skip code search: set GITHUB_TOKEN to search GitHub files", file=sys.stderr)
        return [], stats
    stats["ran"] = True
    found: dict[str, dict] = {}
    for query in CODE_QUERIES:
        got = 0
        for page in range(1, MAX_PAGES + 1):
            try:
                items = search("code", query, page)
                stats["queries_ok"] += 1
            except Exception as exc:
                stats["queries_failed"] += 1
                print(f"code search skipped ({query}): {exc}", file=sys.stderr)
                break
            if not items:
                break
            for item in items:
                html_url = str(item.get("html_url") or "")
                raw = html_to_raw(html_url)
                repo = ((item.get("repository") or {}).get("full_name") or "").strip()
                path = str(item.get("path") or "")
                if not raw or not repo or not yaml_path(path):
                    continue
                found[raw] = {"name": repo, "url": raw, "repo": repo, "via": "code", "path": path}
                got += 1
            if len(items) < PER_PAGE:
                break
        print(f"code search {query!r}: +{got} unique so far {len(found)}", file=sys.stderr)
        time.sleep(6.5)
    stats["hits"] = len(found)
    return list(found.values()), stats


def path_score(path: str) -> int:
    name = path.lower()
    return sum(1 for hint in YAML_HINTS if hint in name)


def list_repo_yaml(repo: str, branch: str) -> list[str]:
    ref = urllib.parse.quote(branch, safe="")
    data = request_json(f"{API}/repos/{repo}/git/trees/{ref}?recursive=1", timeout=30)
    if not isinstance(data, dict):
        return []
    paths = [str(item.get("path") or "") for item in (data.get("tree") or []) if item.get("type") == "blob"]
    yaml_files = [path for path in paths if yaml_path(path)]
    yaml_files.sort(key=lambda path: (-path_score(path), path))
    return yaml_files[:MAX_YAML_PER_REPO]


def collect_repo_candidates() -> tuple[list[dict], dict]:
    stats = {"repos": 0, "yaml_files": 0, "tree_failed": 0}
    repos: dict[str, str] = {}
    for query in REPO_QUERIES:
        for page in range(1, MAX_PAGES + 1):
            try:
                items = search("repositories", query, page)
            except Exception as exc:
                print(f"repo search skipped ({query}): {exc}", file=sys.stderr)
                break
            if not items:
                break
            for item in items:
                if item.get("archived") or item.get("disabled"):
                    continue
                repo = str(item.get("full_name") or "").strip()
                branch = str(item.get("default_branch") or "main").strip() or "main"
                if repo:
                    repos[repo] = branch
            if len(items) < PER_PAGE:
                break
        time.sleep(0.8)
    stats["repos"] = len(repos)
    found: dict[str, dict] = {}
    for repo, branch in repos.items():
        try:
            paths = list_repo_yaml(repo, branch)
        except Exception as exc:
            stats["tree_failed"] += 1
            print(f"tree skipped ({repo}): {exc}", file=sys.stderr)
            continue
        for path in paths:
            raw = f"https://{RAW_HOST}/{repo}/{urllib.parse.quote(branch)}/{path}"
            found[raw] = {"name": repo, "url": raw, "repo": repo, "via": "repo-tree", "path": path}
    stats["yaml_files"] = len(found)
    print(f"repo trees: {stats['repos']} repos, {stats['yaml_files']} yaml files", file=sys.stderr)
    return list(found.values()), stats


def fetch_yaml(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != RAW_HOST:
        raise ValueError("url must be https raw.githubusercontent.com")
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
        body = response.read()
    if len(body) > MAX_FILE_BYTES:
        raise ValueError("file too large")
    parsed_yaml = yaml.safe_load(body) or {}
    if not isinstance(parsed_yaml, dict):
        raise ValueError("top-level YAML value is not a mapping")
    return parsed_yaml


def proxy_count(document: dict) -> int:
    proxies = document.get("proxies")
    if not isinstance(proxies, list):
        return 0
    count = 0
    for item in proxies:
        if not isinstance(item, dict):
            continue
        if item.get("name") and item.get("type") and item.get("server") and item.get("port"):
            count += 1
    return count


def probe(candidate: dict) -> dict | None:
    try:
        document = fetch_yaml(candidate["url"])
        count = proxy_count(document)
    except Exception:
        return None
    if count < MIN_PROXIES:
        return None
    result = dict(candidate)
    result["proxies"] = count
    return result


def merge_unique(existing: list[dict], discovered: list[dict]) -> list[dict]:
    merged = list(existing)
    seen = {str(item.get("url", "")).rstrip("/") for item in existing}
    for item in discovered:
        url = item["url"].rstrip("/")
        if url in seen:
            continue
        seen.add(url)
        merged.append({"name": item["name"], "url": item["url"]})
    return merged


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    apply_changes = "--apply" in sys.argv
    if not token():
        print("GitHub 代码搜索需要 GITHUB_TOKEN 或 GH_TOKEN。仓库搜索仍会尝试，但结果更少。", file=sys.stderr)
    existing, existing_urls, existing_repos = load_existing()
    skip_repos = existing_repos | {"lhl20201204/free-wall", "1000ttank/free-vpn-clash-aggregator"}
    code_candidates, code_stats = collect_code_candidates()
    repo_candidates, repo_stats = collect_repo_candidates()
    raw_candidates = code_candidates + repo_candidates
    filtered = []
    seen_urls = set(existing_urls)
    skipped_known_repo = 0
    for item in raw_candidates:
        url = item["url"].rstrip("/")
        repo = item["repo"].lower()
        if url in seen_urls:
            continue
        if repo in skip_repos:
            skipped_known_repo += 1
            continue
        seen_urls.add(url)
        filtered.append(item)

    probed: list[dict] = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        futures = [pool.submit(probe, item) for item in filtered]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                probed.append(result)
    probed.sort(key=lambda item: (-int(item["proxies"]), item["name"]))
    selected = probed[:MAX_NEW]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        yaml.safe_dump({"sources": [{"name": item["name"], "url": item["url"], "proxies": item["proxies"]} for item in selected]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "existing": len(existing),
                "code_search": code_stats,
                "repo_search": repo_stats,
                "skipped_known_repo": skipped_known_repo,
                "candidates": len(filtered),
                "valid": len(probed),
                "selected": selected,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if apply_changes and selected:
        SOURCES.write_text(yaml.safe_dump({"sources": merge_unique(existing, selected)}, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"updated {SOURCES} with {len(selected)} new sources", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
