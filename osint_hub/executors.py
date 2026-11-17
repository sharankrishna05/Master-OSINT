"""Execution Engine for Automated Enrichment and Safe Browser Dispatch.

Implements:
- Phase A: Safe browser launch (webbrowser)
- Phase B: Curated public OSINT API hits (GitHub, crt.sh, IP-API, Keybase, Blockchain.info)
- Token bucket rate limiter: 1 req / 2s per host + exponential backoff
- SQLite caching with configurable TTL (default 24h)
- Strict adherence to knowledge base rules (no scraping [R], no executing [T])
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from osint_hub.parse import DEFAULT_DB_PATH, init_db

logger = logging.getLogger("osint_hub.executors")


@dataclass
class APIHitResult:
    service: str
    target: str
    url: str
    status: str  # "SUCCESS", "NOT_FOUND", "SKIPPED", "ERROR", "CACHED"
    summary: str
    data: Optional[Dict[str, Any]] = None
    cached: bool = False


class HostRateLimiter:
    """Token bucket per-host rate limiter ensuring max 1 req / 2s per host."""

    def __init__(self, min_interval_seconds: float = 2.0):
        self.min_interval = min_interval_seconds
        self.last_hit: Dict[str, float] = {}

    def wait(self, url: str) -> None:
        host = urlparse(url).netloc.lower()
        now = time.time()
        last = self.last_hit.get(host, 0.0)
        elapsed = now - last
        if elapsed < self.min_interval:
            sleep_needed = self.min_interval - elapsed
            time.sleep(sleep_needed)
        self.last_hit[host] = time.time()


class APICache:
    """Persistent SQLite cache with TTL for API queries."""

    def __init__(self, db_path: Optional[Path] = None, ttl_hours: float = 24.0):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.ttl_seconds = ttl_hours * 3600.0

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        conn = init_db(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT body, ts FROM cache WHERE url = ?", (url,))
        row = cur.fetchone()
        conn.close()

        if row:
            body_str, ts = row[0], row[1]
            if (time.time() - ts) <= self.ttl_seconds:
                try:
                    return json.loads(body_str)
                except Exception:
                    return None
        return None

    def set(self, url: str, params: str, body: Dict[str, Any]) -> None:
        conn = init_db(self.db_path)
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache (url, params, body, ts)
                VALUES (?, ?, ?, ?)
                """,
                (url, params, json.dumps(body), time.time()),
            )
        conn.close()


class OSINTExecutor:
    """Orchestrates Phase A (browser auto-open) and Phase B (public API queries)."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        rate_limit_interval: float = 2.0,
        cache_ttl_hours: float = 24.0,
        no_browser: bool = False,
    ):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.limiter = HostRateLimiter(rate_limit_interval)
        self.cache = APICache(self.db_path, cache_ttl_hours)
        self.no_browser = no_browser
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "osint-hub/1.0.0 (Research Investigation Tool)"})

    # ---------- Phase A: Browser Launch ----------

    def execute_phase_a(self, auto_open_urls: List[str], max_open: int = 15) -> int:
        """Auto-open URLs in default browser if permitted."""
        if self.no_browser:
            logger.info("Phase A skipped (--no-browser flag set).")
            return 0

        opened = 0
        for url in auto_open_urls[:max_open]:
            try:
                webbrowser.open_new_tab(url)
                opened += 1
                time.sleep(0.15)  # brief pause to avoid OS browser hang
            except Exception as e:
                logger.warning("Failed opening URL '%s': %s", url, e)

        return opened

    # ---------- Phase B: Public API Hits ----------

    def _fetch_json_with_retry(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Any]:
        # Check cache first
        cached = self.cache.get(url)
        if cached is not None:
            return cached

        retries = 1
        delay = 1.0
        req_headers = headers or {}

        for attempt in range(retries + 1):
            self.limiter.wait(url)
            try:
                resp = self.session.get(url, headers=req_headers, timeout=4)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        self.cache.set(url, "", data)
                        return data
                    except Exception:
                        return None
                elif resp.status_code == 404:
                    return {"status": "NOT_FOUND"}
                elif resp.status_code in {429, 500, 502, 503, 504}:
                    if attempt < retries:
                        time.sleep(delay)
                        delay *= 2
                        continue
                return None
            except Exception as e:
                logger.debug("Request exception for %s: %s", url, e)
                if attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                else:
                    return None
        return None

    def execute_phase_b(self, target: str, target_type: str, planned_apis: List[str]) -> List[APIHitResult]:
        """Execute automated Phase B API calls directly and structure the findings."""
        results: List[APIHitResult] = []

        for api_name in planned_apis:
            if api_name == "github_user":
                results.append(self._hit_github_user(target))
            elif api_name == "github_events":
                results.append(self._hit_github_events(target))
            elif api_name == "crt_sh":
                results.append(self._hit_crt_sh(target))
            elif api_name == "ip_api":
                results.append(self._hit_ip_api(target))
            elif api_name == "hibp":
                results.append(self._hit_hibp(target))
            elif api_name == "keybase_lookup":
                results.append(self._hit_keybase(target))
            elif api_name == "btc_blockchain":
                results.append(self._hit_btc_blockchain(target))
            elif "eth_etherscan" in api_name:
                results.append(
                    APIHitResult(
                        service="Etherscan API",
                        target=target,
                        url="https://api.etherscan.io/api",
                        status="SKIPPED",
                        summary="Skipped direct API call: Etherscan requires API registration [R]. Verify manually via web portal.",
                    )
                )

        return results

    def _hit_github_user(self, username: str) -> APIHitResult:
        url = f"https://api.github.com/users/{username}"
        data = self._fetch_json_with_retry(url)

        if not data:
            return APIHitResult(
                service="GitHub User API",
                target=username,
                url=url,
                status="ERROR",
                summary="No response from GitHub API.",
            )

        if data.get("status") == "NOT_FOUND" or data.get("message") == "Not Found":
            return APIHitResult(
                service="GitHub User API",
                target=username,
                url=url,
                status="NOT_FOUND",
                summary=f"User '{username}' not found on GitHub.",
            )

        summary = (
            f"User '{data.get('login')}' (ID: {data.get('id')}). "
            f"Name: {data.get('name') or 'N/A'}, Bio: {data.get('bio') or 'N/A'}, "
            f"Public Repos: {data.get('public_repos', 0)}, Followers: {data.get('followers', 0)}, "
            f"Created: {data.get('created_at', 'N/A')}"
        )
        return APIHitResult(
            service="GitHub User API",
            target=username,
            url=url,
            status="SUCCESS",
            summary=summary,
            data=data,
        )

    def _hit_github_events(self, username: str) -> APIHitResult:
        url = f"https://api.github.com/users/{username}/events/public"
        data = self._fetch_json_with_retry(url)

        if not data or not isinstance(data, list):
            return APIHitResult(
                service="GitHub Public Events",
                target=username,
                url=url,
                status="NOT_FOUND",
                summary="No recent public activity events found.",
            )

        event_types = set(e.get("type") for e in data[:10] if isinstance(e, dict))
        repos = set(e.get("repo", {}).get("name") for e in data[:10] if isinstance(e, dict))
        summary = (
            f"Observed {len(data)} public events. Event types: {', '.join(filter(None, event_types)) or 'None'}. "
            f"Repositories: {', '.join(filter(None, list(repos)[:3])) or 'None'}"
        )
        return APIHitResult(
            service="GitHub Public Events",
            target=username,
            url=url,
            status="SUCCESS",
            summary=summary,
            data={"event_count": len(data), "events_preview": data[:5]},
        )

    def _hit_crt_sh(self, domain: str) -> APIHitResult:
        url = f"https://crt.sh/?q={domain}&output=json"
        data = self._fetch_json_with_retry(url)

        if not data or not isinstance(data, list):
            return APIHitResult(
                service="crt.sh Certificate Transparency",
                target=domain,
                url=url,
                status="NOT_FOUND",
                summary=f"No Certificate Transparency logs returned for {domain}.",
            )

        subdomains = set()
        for entry in data[:50]:
            name_val = entry.get("name_value", "")
            for sub in name_val.split("\n"):
                sub_clean = sub.strip().lower()
                if sub_clean and domain in sub_clean:
                    subdomains.add(sub_clean)

        summary = (
            f"Found {len(data)} certificate entries. "
            f"Discovered {len(subdomains)} unique names/subdomains (e.g. {', '.join(list(subdomains)[:4])})."
        )
        return APIHitResult(
            service="crt.sh Certificate Transparency",
            target=domain,
            url=url,
            status="SUCCESS",
            summary=summary,
            data={"total_records": len(data), "subdomains": sorted(list(subdomains))[:25]},
        )

    def _hit_ip_api(self, ip: str) -> APIHitResult:
        url = f"http://ip-api.com/json/{ip}"
        data = self._fetch_json_with_retry(url)

        if not data or data.get("status") != "success":
            return APIHitResult(
                service="IP-API Geolocation",
                target=ip,
                url=url,
                status="NOT_FOUND",
                summary=f"No geolocation record found for IP {ip}.",
            )

        summary = (
            f"Location: {data.get('city')}, {data.get('regionName')}, {data.get('country')}. "
            f"ISP: {data.get('isp')} | Org: {data.get('org')} | AS: {data.get('as')}"
        )
        return APIHitResult(
            service="IP-API Geolocation",
            target=ip,
            url=url,
            status="SUCCESS",
            summary=summary,
            data=data,
        )

    def _hit_hibp(self, email: str) -> APIHitResult:
        api_key = os.environ.get("HIBP_API_KEY", "").strip()
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        if not api_key:
            return APIHitResult(
                service="Have I Been Pwned",
                target=email,
                url=url,
                status="SKIPPED",
                summary="Skipped HIBP direct API call: HIBP_API_KEY is not set in environment. Use web portal https://haveibeenpwned.com/ or configure .env.",
            )

        data = self._fetch_json_with_retry(url, headers={"hibp-api-key": api_key})
        if not data:
            return APIHitResult(
                service="Have I Been Pwned",
                target=email,
                url=url,
                status="NOT_FOUND",
                summary=f"No breach records reported for '{email}'.",
            )

        breach_count = len(data) if isinstance(data, list) else 1
        summary = f"Flagged in {breach_count} known public data breaches."
        return APIHitResult(
            service="Have I Been Pwned",
            target=email,
            url=url,
            status="SUCCESS",
            summary=summary,
            data={"breaches": data},
        )

    def _hit_keybase(self, username: str) -> APIHitResult:
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}"
        data = self._fetch_json_with_retry(url)

        if not data or data.get("status", {}).get("code") != 0:
            return APIHitResult(
                service="Keybase Identity Verification",
                target=username,
                url=url,
                status="NOT_FOUND",
                summary=f"User '{username}' not found on Keybase.",
            )

        them = data.get("them", {})
        profile = them.get("profile", {})
        proofs = [p.get("service_name") for p in them.get("proofs_summary", {}).get("all", [])]
        summary = (
            f"Keybase profile verified: '{profile.get('full_name') or username}'. "
            f"Cryptographic proofs linked across: {', '.join(proofs) or 'None'}"
        )
        return APIHitResult(
            service="Keybase Identity Verification",
            target=username,
            url=url,
            status="SUCCESS",
            summary=summary,
            data={"profile": profile, "proofs": proofs},
        )

    def _hit_btc_blockchain(self, address: str) -> APIHitResult:
        url = f"https://blockchain.info/rawaddr/{address}"
        data = self._fetch_json_with_retry(url)

        if not data or "n_tx" not in data:
            return APIHitResult(
                service="Bitcoin Blockchain Info",
                target=address,
                url=url,
                status="NOT_FOUND",
                summary=f"Address '{address}' has 0 recorded ledger transactions or invalid format.",
            )

        n_tx = data.get("n_tx", 0)
        final_balance = data.get("final_balance", 0) / 1e8
        total_recv = data.get("total_received", 0) / 1e8
        summary = (
            f"Bitcoin Ledger Record: {n_tx} total transactions. "
            f"Total Received: {total_recv:.6f} BTC | Current Balance: {final_balance:.6f} BTC"
        )
        return APIHitResult(
            service="Bitcoin Blockchain Info",
            target=address,
            url=url,
            status="SUCCESS",
            summary=summary,
            data={"n_tx": n_tx, "final_balance_btc": final_balance, "total_received_btc": total_recv},
        )
