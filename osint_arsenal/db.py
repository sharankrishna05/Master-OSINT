from __future__ import annotations
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from .models import (
    Investigation, InvestigationKind, ModuleResult, JobResult,
    Verdict, Status,
)
from .config import settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
  key TEXT PRIMARY KEY,
  label TEXT,
  active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  last_used TEXT
);
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subkind TEXT,
  query TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  verdict TEXT,
  summary TEXT,
  followups TEXT,
  api_key TEXT,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_inv_kind ON investigations(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_query ON investigations(query);
CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  "group" TEXT,
  status TEXT NOT NULL,
  url TEXT,
  http_status INTEGER,
  confidence REAL,
  data TEXT,
  error TEXT,
  duration_ms INTEGER,
  timestamp TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_inv ON results(investigation_id);
CREATE TABLE IF NOT EXISTS usage (
  api_key TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_key ON usage(api_key, ts);
"""


class DB:
    def __init__(self, path: str | None = None):
        self.path = path or settings.db_path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def _init(self):
        with self.conn() as c:
            c.executescript(SCHEMA)
        for k in settings.default_keys:
            self.ensure_key(k, label="default")

    # ---------- API keys ----------
    def ensure_key(self, key: str, label: str = ""):
        with self.conn() as c:
            if not c.execute("SELECT key FROM api_keys WHERE key=?", (key,)).fetchone():
                c.execute(
                    "INSERT INTO api_keys VALUES (?,?,?,?,?)",
                    (key, label, 1, datetime.utcnow().isoformat(), None),
                )

    def is_valid_key(self, key: str) -> bool:
        with self.conn() as c:
            row = c.execute("SELECT active FROM api_keys WHERE key=?", (key,)).fetchone()
            return bool(row and row["active"])

    def touch_key(self, key: str):
        with self.conn() as c:
            c.execute("UPDATE api_keys SET last_used=? WHERE key=?",
                      (datetime.utcnow().isoformat(), key))

    def list_keys(self) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()]

    def revoke_key(self, key: str):
        with self.conn() as c:
            c.execute("UPDATE api_keys SET active=0 WHERE key=?", (key,))

    # ---------- investigations ----------
    def create_investigation(self, inv: Investigation) -> Investigation:
        with self.conn() as c:
            c.execute(
                "INSERT INTO investigations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (inv.id, inv.kind.value, inv.subkind, inv.query, inv.status,
                 inv.created_at.isoformat(), None, json.dumps(inv.summary),
                 json.dumps(inv.followups), inv.api_key, inv.duration_ms),
            )
        return inv

    def update_investigation(self, inv_id: str, *, status: str | None = None,
                             verdict: Verdict | None = None,
                             summary: dict | None = None,
                             followups: list[str] | None = None,
                             duration_ms: int | None = None):
        sets, args = [], []
        if status is not None:
            sets.append("status=?"); args.append(status)
        if verdict is not None:
            sets.append("verdict=?"); args.append(json.dumps(verdict.model_dump(mode="json")))
        if summary is not None:
            sets.append("summary=?"); args.append(json.dumps(summary))
        if followups is not None:
            sets.append("followups=?"); args.append(json.dumps(followups))
        if duration_ms is not None:
            sets.append("duration_ms=?"); args.append(duration_ms)
        if not sets:
            return
        args.append(inv_id)
        with self.conn() as c:
            c.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE id=?", args)

    def add_result(self, inv_id: str, source: str, r):
        """r is either ModuleResult or JobResult."""
        if isinstance(r, ModuleResult):
            payload = json.dumps(r.evidence, default=str)
            error = None
            group = r.category
            url = r.url
            http_status = r.http_status
            confidence = r.confidence
        else:  # JobResult
            payload = json.dumps(r.data, default=str)
            error = r.error
            group = r.group
            url = None
            http_status = None
            confidence = None

        with self.conn() as c:
            c.execute(
                'INSERT INTO results (investigation_id, source, "group", status, '
                "url, http_status, confidence, data, error, duration_ms, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (inv_id, source, group, r.status.value, url, http_status,
                 confidence, payload, error, r.duration_ms,
                 r.timestamp.isoformat()),
            )

    def get_investigation(self, inv_id: str) -> dict | None:
        with self.conn() as c:
            row = c.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
            if not row:
                return None
            inv = dict(row)
            inv["verdict"] = json.loads(inv["verdict"]) if inv["verdict"] else None
            inv["summary"] = json.loads(inv["summary"] or "{}")
            inv["followups"] = json.loads(inv["followups"] or "[]")
            rows = c.execute(
                "SELECT * FROM results WHERE investigation_id=? ORDER BY timestamp",
                (inv_id,),
            ).fetchall()
            inv["results"] = [
                dict(r, data=json.loads(r["data"] or "{}")) for r in rows
            ]
            return inv

    def list_investigations(self, kind: str | None = None,
                            limit: int = 50) -> list[dict]:
        sql = "SELECT id, kind, subkind, query, status, created_at, summary FROM investigations"
        args: list = []
        if kind:
            sql += " WHERE kind=?"
            args.append(kind)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        with self.conn() as c:
            rows = c.execute(sql, args).fetchall()
            return [dict(r, summary=json.loads(r["summary"] or "{}")) for r in rows]

    def delete_investigation(self, inv_id: str):
        with self.conn() as c:
            c.execute("DELETE FROM investigations WHERE id=?", (inv_id,))

    # ---------- usage ----------
    def record_usage(self, key: str):
        with self.conn() as c:
            c.execute("INSERT INTO usage VALUES (?,?)",
                      (key, datetime.utcnow().isoformat()))

    def count_usage(self, key: str, window_seconds: int) -> int:
        since = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()
        with self.conn() as c:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM usage WHERE api_key=? AND ts>=?",
                (key, since),
            ).fetchone()
            return row["n"] if row else 0
