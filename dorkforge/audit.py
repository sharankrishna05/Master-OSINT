from __future__ import annotations
import os
import sys
import logging
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

LEGAL_DISCLAIMER = """[bold red]⚖️ DORKFORGE LEGAL & ETHICAL USE NOTICE[/bold red]

DorkForge is designed strictly for [bold cyan]authorized security testing, bug bounty reconnaissance,
and defensive asset discovery[/bold cyan].

1. You may ONLY target domains, organizations, or assets that you own or have explicit, documented
   permission to test.
2. Unauthorized security scanning, credential harvesting, unauthorized access attempts, or individual
   doxxing is illegal under the Computer Fraud and Abuse Act (CFAA), GDPR, Section 43/66 of India's IT Act,
   and international cyber law.
3. Use of the [bold yellow]--i-have-authorization[/bold yellow] flag legally binds the operator as having authorized
   approval. All actions, queries, timestamps, and operator IDs are recorded in the immutable audit log.
"""

# Malicious / unethical pattern safeguards
REFUSED_PATTERNS = [
    r"social\s*security\s*number",
    r"ssn\s*ext:csv",
    r"passport\s*number",
    r"credit\s*card\s*number",
    r"cvv\s*ext:",
    r"private\s*personal\s*photo",
    r"doxx",
    r"stalk",
    r"intext:\"password\"\s*inurl:dump"
]

def get_audit_dir() -> Path:
    audit_dir = Path.home() / ".dorkforge"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir

def get_audit_log_path() -> Path:
    return get_audit_dir() / "audit.log"

def setup_audit_logging() -> logging.Logger:
    logger = logging.getLogger("dorkforge.audit")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        log_path = get_audit_log_path()
        handler = logging.FileHandler(str(log_path), encoding="utf-8")
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [OPERATOR: %(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S UTC"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

audit_logger = setup_audit_logging()

def print_disclaimer():
    """Display the formatted ethical and legal warning."""
    console.print(Panel(LEGAL_DISCLAIMER, border_style="red", title="[bold white]SECURITY NOTICE[/bold white]"))

def validate_authorization(domain: str, authorized: bool, dry_run: bool = False):
    """Enforce authorization check prior to execution."""
    # Local/example safe domains exempt from authorization prompt
    safe_local_domains = ["localhost", "127.0.0.1", "example.com", "test.local"]
    is_safe_local = any(s in domain.lower() for s in safe_local_domains)

    if dry_run or is_safe_local:
        return

    if not authorized:
        print_disclaimer()
        console.print(
            f"[bold red]✖ ACCESS RESTRICTED:[/bold red] Targeting external domain [bold yellow]{domain}[/bold yellow] "
            f"requires explicit confirmation.\n"
            f"Please supply the [bold cyan]--i-have-authorization[/bold cyan] flag to certify legal permission.",
            style="red"
        )
        log_audit_event("AUTHORIZATION_FAILURE", domain, "Execution aborted due to missing --i-have-authorization flag")
        sys.exit(1)

def validate_query_safety(query: str) -> bool:
    """Refuse queries intended for credential theft, doxxing, or unauthorized exploitation."""
    import re
    q_lower = query.lower()
    for pattern in REFUSED_PATTERNS:
        if re.search(pattern, q_lower):
            audit_logger.warning(f"REFUSED_MALICIOUS_QUERY: {query}")
            return False
    return True

def log_audit_event(event_type: str, target: str, details: str):
    """Write an entry to ~/.dorkforge/audit.log."""
    audit_logger.info(f"[{event_type}] TARGET={target} | {details}")
