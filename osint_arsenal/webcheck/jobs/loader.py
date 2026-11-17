from __future__ import annotations
import importlib
import importlib.util
import sys
from pathlib import Path

from .base import Job, registry
from ...config import settings


BUILTIN = [
    "ip_info", "ssl_chain", "dns_records", "headers", "cookies",
    "robots", "sitemap", "tech_stack", "security_headers", "hsts",
    "dnssec", "email_config", "waf", "redirects", "server_info",
    "whois_lookup", "txt_records", "server_status", "open_ports",
    "traceroute", "carbon", "social_tags", "linked_pages", "archive",
    "global_rank", "malware", "tls_ciphers", "tls_security", "screenshot",
]


def load_all() -> dict:
    for name in BUILTIN:
        importlib.import_module(f".{name}", package="osint_arsenal.webcheck.jobs")
    n_builtin = len(registry.all())

    n_user = 0
    mod_dir = Path(settings.plugins_dir)
    if mod_dir.exists():
        for py in mod_dir.glob("*webcheck*.py"):
            if py.name.startswith("_"):
                continue
            mod_name = f"arsenal_plugin_webcheck_{py.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if not spec or not spec.loader:
                continue
            m = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = m
            try:
                spec.loader.exec_module(m)
            except Exception as e:
                print(f"[webcheck] failed to load {py}: {e}")
                continue
            if hasattr(m, "register") and callable(m.register):
                try:
                    m.register(registry); n_user += 1
                except Exception as e:
                    print(f"[webcheck] register() failed for {py}: {e}")
            elif hasattr(m, "JOB") and isinstance(m.JOB, Job):
                registry.register(m.JOB); n_user += 1

    return {"builtin": n_builtin, "user": n_user, "total": len(registry.all())}
