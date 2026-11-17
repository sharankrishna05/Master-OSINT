"""Account & Credential Vault for OSINT-HUB and NOSTROMO Platform."""

from __future__ import annotations

import datetime
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from ..config import settings


def _default_vault_path() -> Path:
    env_path = os.getenv("ARSENAL_VAULT_DB", "").strip()
    if env_path:
        return Path(env_path)
    return Path(settings.db_path).resolve().parent / "vault.db"


VAULT_DB_PATH = _default_vault_path()


class CredentialVault:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _default_vault_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    service TEXT PRIMARY KEY,
                    account_email TEXT NOT NULL,
                    secret_key TEXT NOT NULL,
                    notes TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
        conn.close()

    def save_credential(
        self,
        service: str,
        account_email: str,
        secret_key: str,
        notes: str = "",
    ) -> Dict[str, str]:
        srv_clean = service.strip().lower()
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO credentials (service, account_email, secret_key, notes, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (srv_clean, account_email.strip(), secret_key.strip(), notes.strip(), now),
            )
        conn.close()
        return {
            "service": srv_clean,
            "account_email": account_email.strip(),
            "updated_at": now,
            "status": "SAVED",
        }

    def list_credentials(self, mask: bool = True) -> List[Dict[str, str]]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT service, account_email, secret_key, notes, updated_at FROM credentials ORDER BY service")
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            sec = r["secret_key"]
            if mask:
                if len(sec) > 8:
                    masked_sec = sec[:4] + "••••••••" + sec[-4:]
                else:
                    masked_sec = "••••••••"
            else:
                masked_sec = sec

            results.append(
                {
                    "service": r["service"],
                    "account_email": r["account_email"],
                    "secret_key": masked_sec,
                    "notes": r["notes"] or "",
                    "updated_at": r["updated_at"],
                }
            )
        return results

    def get_credential(self, service: str) -> Optional[Dict[str, str]]:
        srv_clean = service.strip().lower()
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT service, account_email, secret_key, notes, updated_at FROM credentials WHERE service = ?", (srv_clean,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "service": row["service"],
            "account_email": row["account_email"],
            "secret_key": row["secret_key"],
            "notes": row["notes"] or "",
            "updated_at": row["updated_at"],
        }

    def delete_credential(self, service: str) -> bool:
        srv_clean = service.strip().lower()
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        with conn:
            cur = conn.execute("DELETE FROM credentials WHERE service = ?", (srv_clean,))
            deleted = cur.rowcount > 0
        conn.close()
        return deleted

    def get_all_secrets(self) -> Dict[str, str]:
        """Return raw unmasked secrets dictionary mapping service -> secret_key."""
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT service, secret_key FROM credentials")
        rows = cur.fetchall()
        conn.close()
        return {r["service"]: r["secret_key"] for r in rows}


# Global singleton instance
credential_vault = CredentialVault()
