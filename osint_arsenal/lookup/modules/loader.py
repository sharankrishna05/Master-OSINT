from __future__ import annotations
import importlib.util
import json
import sys
from pathlib import Path

from .base import SiteModule, registry
from .username import load_builtin as load_username
from .email import load_builtin as load_email
from .phone import load_builtin as load_phone
from .domain import load_builtin as load_domain
from .ip import load_builtin as load_ip
from .crypto import load_builtin as load_crypto
from ...config import settings


class JSONSiteModule(SiteModule):
    def __init__(self, spec: dict):
        self.name = spec["name"]
        self.category = spec.get("category", "medium")
        self.url = spec["url"]
        self.supported = set(spec.get("kinds", ["username"]))
        self.negative_marker = spec.get("negative_marker")

    async def check(self, client, query: str) -> dict:
        url = self.url.format(u=query, e=query, p=query, d=query)
        try:
            r = await client.get(url)
        except Exception as e:
            return {"status": "error", "url": url, "confidence": 0.0,
                    "evidence": {"error": str(e)}}
        if r.status_code == 200:
            if self.negative_marker and self.negative_marker.lower() in r.text.lower():
                return {"status": "not_found", "url": url, "http_status": 200,
                        "confidence": 0.7, "evidence": {}}
            return {"status": "found", "url": url, "http_status": 200,
                    "confidence": 0.8, "evidence": {}}
        if r.status_code == 404:
            return {"status": "not_found", "url": url, "http_status": 404,
                    "confidence": 0.9, "evidence": {}}
        return {"status": "inconclusive", "url": url,
                "http_status": r.status_code, "confidence": 0.3, "evidence": {}}


def load_all() -> dict:
    load_username(); load_email(); load_phone(); load_domain(); load_ip(); load_crypto()
    n_builtin = len(registry.all())

    sites_path = Path(__file__).parent.parent / "data" / "sites.json"
    n_json = 0
    if sites_path.exists():
        for spec in json.loads(sites_path.read_text(encoding="utf-8")):
            registry.register(JSONSiteModule(spec))
            n_json += 1

    n_user = 0
    mod_dir = Path(settings.plugins_dir)
    if mod_dir.exists():
        for py in mod_dir.glob("*lookup*.py"):
            if py.name.startswith("_"):
                continue
            mod_name = f"arsenal_plugin_lookup_{py.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if not spec or not spec.loader:
                continue
            m = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = m
            try:
                spec.loader.exec_module(m)
            except Exception as e:
                print(f"[lookup] failed to load {py}: {e}")
                continue
            if hasattr(m, "register") and callable(m.register):
                try:
                    m.register(registry); n_user += 1
                except Exception as e:
                    print(f"[lookup] register() failed for {py}: {e}")
            elif hasattr(m, "MODULE") and isinstance(m.MODULE, SiteModule):
                registry.register(m.MODULE); n_user += 1

    return {"builtin": n_builtin, "json": n_json,
            "user": n_user, "total": len(registry.all())}
