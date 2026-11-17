"""
Enterprise Authentication, User Management, Vault Security, and Activity Monitoring
for OSINT-ARSENAL & NOSTROMO CTI Platform.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import jwt

from .config import settings


def _load_or_create_jwt_secret() -> str:
    env_secret = os.getenv("ARSENAL_JWT_SECRET", "").strip()
    if env_secret:
        return env_secret
    secret_file = Path(settings.db_path).resolve().parent / ".jwt_secret"
    try:
        if secret_file.exists():
            val = secret_file.read_text(encoding="utf-8").strip()
            if val:
                return val
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_urlsafe(48)
        secret_file.write_text(generated, encoding="utf-8")
        return generated
    except Exception:
        return secrets.token_urlsafe(48)


JWT_SECRET_KEY = _load_or_create_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DAYS = 14

AUTH_DB_PATH = Path(settings.db_path).resolve()


class AuthManager:
    """Manages User Accounts, Personal Credential Vaults, and Activity Auditing."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else Path(settings.db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._seed_default_accounts()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    name TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    is_verified INTEGER DEFAULT 0,
                    auth_provider TEXT DEFAULT 'local',
                    avatar_url TEXT,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_vault_credentials (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    service TEXT NOT NULL,
                    account_email TEXT NOT NULL,
                    secret_key TEXT NOT NULL,
                    notes TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, service)
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_vault ON user_vault_credentials(user_id);
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_activity_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    user_email TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_activity_user ON user_activity_logs(user_email);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_activity_ts ON user_activity_logs(timestamp DESC);
                """
            )
        conn.close()

    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        if not hashed_password:
            return False
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    def create_token(self, user: Dict[str, Any]) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "is_verified": bool(user["is_verified"]),
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(days=JWT_EXPIRATION_DAYS)).timestamp()),
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user = self.get_user_by_id(payload["sub"])
            if user and user.get("is_active"):
                return user
            return None
        except Exception:
            return None

    def _seed_default_accounts(self) -> None:
        """Optionally seeds an initial admin account from environment variables."""
        admin_email = os.getenv("ARSENAL_ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("ARSENAL_ADMIN_PASSWORD", "").strip()
        if admin_email and admin_password and not self.get_user_by_email(admin_email):
            self.create_user(
                email=admin_email,
                password=admin_password,
                name=os.getenv("ARSENAL_ADMIN_NAME", "Platform Administrator"),
                role="admin",
                is_verified=True,
                auth_provider="local",
            )

        # Optional local demo mode only when explicitly enabled
        if os.getenv("ARSENAL_SEED_DEMO", "0") == "1":
            demo_email = "admin@nostromo.sec"
            if not self.get_user_by_email(demo_email):
                demo_pw = os.getenv("ARSENAL_DEMO_PASSWORD") or secrets.token_urlsafe(16)
                self.create_user(
                    email=demo_email,
                    password=demo_pw,
                    name="Security Administrator",
                    role="admin",
                    is_verified=True,
                    auth_provider="local",
                )

    # =========================================================================
    # USER MANAGEMENT
    # =========================================================================

    def create_user(
        self,
        email: str,
        password: Optional[str],
        name: str,
        role: str = "user",
        is_verified: bool = False,
        auth_provider: str = "local",
        avatar_url: Optional[str] = None,
    ) -> str:
        user_id = str(uuid.uuid4())
        email_clean = email.strip().lower()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        pwd_hash = self._hash_password(password) if password else None

        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO users (id, email, password_hash, name, role, is_verified, auth_provider, avatar_url, created_at, last_login, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (user_id, email_clean, pwd_hash, name.strip(), role, 1 if is_verified else 0, auth_provider, avatar_url, now, now),
            )
        conn.close()

        self.log_activity(
            user_id=user_id,
            user_email=email_clean,
            action="USER_REGISTERED",
            target=email_clean,
            status="SUCCESS",
            details=f"Account created via {auth_provider}. Verified: {is_verified}",
        )
        return user_id

    def authenticate_local(self, email: str, password: str, ip: str = "", user_agent: str = "") -> Tuple[bool, Optional[Dict[str, Any]], str]:
        email_clean = email.strip().lower()
        user = self.get_user_by_email(email_clean)
        if not user:
            self.log_activity(None, email_clean, "LOGIN_FAILED", email_clean, "FAILED", ip, user_agent, "Account does not exist")
            return False, None, "Invalid email or password"

        if not user.get("is_active"):
            self.log_activity(user["id"], email_clean, "LOGIN_BLOCKED", email_clean, "BLOCKED", ip, user_agent, "Account deactivated")
            return False, None, "Account has been deactivated. Contact an administrator."

        if not user.get("password_hash") or not self._verify_password(password, user["password_hash"]):
            self.log_activity(user["id"], email_clean, "LOGIN_FAILED", email_clean, "FAILED", ip, user_agent, "Incorrect password")
            return False, None, "Invalid email or password"

        # Check verification requirement
        if not user.get("is_verified"):
            self.log_activity(user["id"], email_clean, "LOGIN_UNVERIFIED", email_clean, "WARNING", ip, user_agent, "Account verification pending")
            return False, None, "Account verification is pending. Please have a Security Administrator verify your account."

        # Update last login
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn = self._get_connection()
        with conn:
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"]))
        conn.close()

        user["last_login"] = now
        token = self.create_token(user)
        self.log_activity(user["id"], email_clean, "LOGIN_SUCCESS", email_clean, "SUCCESS", ip, user_agent, "Local password authenticated")
        return True, {"user": user, "token": token}, "Login successful"

    def authenticate_google(
        self,
        email: str,
        name: str,
        google_id: str = "",
        avatar_url: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Authenticates or registers a user via Google OAuth (auto-verified)."""
        email_clean = email.strip().lower()
        if not email_clean or "@" not in email_clean:
            return False, None, "Invalid Google email address"

        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        user = self.get_user_by_email(email_clean)

        if user:
            if not user.get("is_active"):
                self.log_activity(user["id"], email_clean, "GOOGLE_LOGIN_BLOCKED", email_clean, "BLOCKED", ip, user_agent, "Account deactivated")
                return False, None, "Account is deactivated"

            # Auto-verify Google authenticated accounts
            conn = self._get_connection()
            with conn:
                conn.execute(
                    "UPDATE users SET last_login = ?, is_verified = 1, avatar_url = coalesce(?, avatar_url) WHERE id = ?",
                    (now, avatar_url or None, user["id"]),
                )
            conn.close()
            user["last_login"] = now
            user["is_verified"] = 1
            if avatar_url:
                user["avatar_url"] = avatar_url
        else:
            # First-time Google user registration (auto-verified by Google OAuth)
            role = "admin" if email_clean in ["sharan.vaka@gmail.com", "admin@nostromo.sec"] else "user"
            u_id = self.create_user(
                email=email_clean,
                password=None,
                name=name or email_clean.split("@")[0].title(),
                role=role,
                is_verified=True,
                auth_provider="google",
                avatar_url=avatar_url,
            )
            user = self.get_user_by_id(u_id)

        token = self.create_token(user)
        self.log_activity(user["id"], email_clean, "GOOGLE_LOGIN_SUCCESS", email_clean, "SUCCESS", ip, user_agent, "Google OAuth verification passed")
        return True, {"user": user, "token": token}, "Google authentication successful"

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, name, role, is_verified, auth_provider, avatar_url, created_at, last_login, is_active FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, email, password_hash, name, role, is_verified, auth_provider, avatar_url, created_at, last_login, is_active FROM users WHERE email = ?", (email.strip().lower(),))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def list_users(self, search: str = "") -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        if search:
            pat = f"%{search.strip().lower()}%"
            cur.execute(
                """
                SELECT id, email, name, role, is_verified, auth_provider, avatar_url, created_at, last_login, is_active
                FROM users
                WHERE email LIKE ? OR name LIKE ?
                ORDER BY created_at DESC
                """,
                (pat, pat),
            )
        else:
            cur.execute(
                """
                SELECT id, email, name, role, is_verified, auth_provider, avatar_url, created_at, last_login, is_active
                FROM users
                ORDER BY created_at DESC
                """
            )
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def set_user_verified(self, user_id: str, is_verified: bool, admin_email: str = "") -> bool:
        conn = self._get_connection()
        with conn:
            conn.execute("UPDATE users SET is_verified = ? WHERE id = ?", (1 if is_verified else 0, user_id))
        conn.close()
        u = self.get_user_by_id(user_id)
        if u:
            self.log_activity(
                user_id,
                u["email"],
                "ADMIN_VERIFICATION_CHANGE",
                u["email"],
                "SUCCESS",
                details=f"Verification set to {is_verified} by {admin_email or 'Admin'}",
            )
        return True

    def set_user_role(self, user_id: str, role: str, admin_email: str = "") -> bool:
        if role not in ["admin", "user"]:
            return False
        conn = self._get_connection()
        with conn:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.close()
        u = self.get_user_by_id(user_id)
        if u:
            self.log_activity(
                user_id,
                u["email"],
                "ADMIN_ROLE_CHANGE",
                u["email"],
                "SUCCESS",
                details=f"Role changed to {role} by {admin_email or 'Admin'}",
            )
        return True

    def toggle_user_active(self, user_id: str, is_active: bool, admin_email: str = "") -> bool:
        conn = self._get_connection()
        with conn:
            conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
        conn.close()
        u = self.get_user_by_id(user_id)
        if u:
            self.log_activity(
                user_id,
                u["email"],
                "ADMIN_STATUS_CHANGE",
                u["email"],
                "SUCCESS",
                details=f"Account active state changed to {is_active} by {admin_email or 'Admin'}",
            )
        return True

    # =========================================================================
    # USER VAULT CREDENTIALS (PER-USER API KEYS & SECRETS)
    # =========================================================================

    def save_vault_credential(
        self,
        user_id: str,
        service: str,
        secret_key: str,
        account_email: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Stores or updates an API key in the user's isolated vault."""
        srv_clean = service.strip().lower()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        cred_id = str(uuid.uuid4())

        u = self.get_user_by_id(user_id)
        user_email = (u["email"] if u else "") or account_email

        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO user_vault_credentials (id, user_id, service, account_email, secret_key, notes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, service) DO UPDATE SET
                    account_email = excluded.account_email,
                    secret_key = excluded.secret_key,
                    notes = excluded.notes,
                    updated_at = excluded.updated_at
                """,
                (cred_id, user_id, srv_clean, account_email.strip() or user_email, secret_key.strip(), notes.strip(), now),
            )
        conn.close()

        self.log_activity(
            user_id=user_id,
            user_email=user_email,
            action="VAULT_KEY_SAVED",
            target=srv_clean,
            status="SUCCESS",
            details=f"Saved API key for service {srv_clean}",
        )

        return {
            "service": srv_clean,
            "account_email": account_email.strip() or user_email,
            "updated_at": now,
            "status": "SAVED",
        }

    def list_vault_credentials(self, user_id: str, mask: bool = True) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, user_id, service, account_email, secret_key, notes, updated_at
            FROM user_vault_credentials
            WHERE user_id = ?
            ORDER BY service ASC
            """,
            (user_id,),
        )
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            sec = r["secret_key"]
            if mask:
                masked_sec = sec[:4] + "••••••••" + sec[-4:] if len(sec) > 8 else "••••••••"
            else:
                masked_sec = sec

            results.append(
                {
                    "id": r["id"],
                    "service": r["service"],
                    "account_email": r["account_email"],
                    "secret_key": masked_sec,
                    "notes": r["notes"] or "",
                    "updated_at": r["updated_at"],
                }
            )
        return results

    def get_vault_credential(self, user_id: str, service: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, user_id, service, account_email, secret_key, notes, updated_at
            FROM user_vault_credentials
            WHERE user_id = ? AND service = ?
            """,
            (user_id, service.strip().lower()),
        )
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def delete_vault_credential(self, user_id: str, service: str) -> bool:
        srv_clean = service.strip().lower()
        u = self.get_user_by_id(user_id)
        conn = self._get_connection()
        with conn:
            conn.execute(
                "DELETE FROM user_vault_credentials WHERE user_id = ? AND service = ?",
                (user_id, srv_clean),
            )
        conn.close()

        if u:
            self.log_activity(
                user_id=user_id,
                user_email=u["email"],
                action="VAULT_KEY_DELETED",
                target=srv_clean,
                status="SUCCESS",
                details=f"Deleted API key for {srv_clean}",
            )
        return True

    # =========================================================================
    # ACTIVITY MONITORING & AUDITING (ADMIN DASHBOARD)
    # =========================================================================

    def log_activity(
        self,
        user_id: Optional[str],
        user_email: str,
        action: str,
        target: Optional[str] = None,
        status: str = "SUCCESS",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        log_id = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO user_activity_logs (id, user_id, user_email, action, target, status, ip_address, user_agent, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (log_id, user_id, user_email, action, target or "-", status, ip_address or "127.0.0.1", user_agent or "-", details or "-", now),
            )
        conn.close()

    def list_activity_logs(
        self,
        limit: int = 100,
        user_email: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        query = "SELECT id, user_id, user_email, action, target, status, ip_address, user_agent, details, timestamp FROM user_activity_logs WHERE 1=1"
        params: List[Any] = []

        if user_email:
            query += " AND user_email LIKE ?"
            params.append(f"%{user_email.strip().lower()}%")
        if action:
            query += " AND action = ?"
            params.append(action.strip().upper())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def list_all_vault_inventory(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT v.id, v.user_id, u.email as user_email, u.name as user_name,
                   v.service, v.account_email, v.secret_key, v.notes, v.updated_at, v.updated_at as created_at
            FROM user_vault_credentials v
            JOIN users u ON v.user_id = u.id
            ORDER BY u.email ASC, v.service ASC
        """)
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            secret = d.get("secret_key", "")
            if len(secret) > 8:
                d["masked_secret"] = secret[:4] + ("*" * (len(secret) - 8)) + secret[-4:]
            elif secret:
                d["masked_secret"] = "****"
            else:
                d["masked_secret"] = "EMPTY"
            del d["secret_key"]
            res.append(d)
        return res

    def get_security_stats(self) -> Dict[str, Any]:
        conn = self._get_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) AS total FROM users")
        total_users = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS verified FROM users WHERE is_verified = 1")
        verified_users = cur.fetchone()["verified"]

        cur.execute("SELECT COUNT(*) AS total_keys FROM user_vault_credentials")
        total_vault_keys = cur.fetchone()["total_keys"]

        cur.execute("SELECT COUNT(*) AS total_logs FROM user_activity_logs")
        total_actions = cur.fetchone()["total_logs"]

        cur.execute("SELECT COUNT(*) AS searches FROM user_activity_logs WHERE action IN ('INVESTIGATION_START', 'TARGET_SEARCH', 'OSINT_TOOL_OPEN')")
        total_searches = cur.fetchone()["searches"]

        cur.execute(
            """
            SELECT action, COUNT(*) as count
            FROM user_activity_logs
            GROUP BY action
            ORDER BY count DESC
            LIMIT 6
            """
        )
        action_breakdown = [dict(r) for r in cur.fetchall()]

        conn.close()

        return {
            "total_users": total_users,
            "verified_users": verified_users,
            "unverified_users": total_users - verified_users,
            "total_vault_keys": total_vault_keys,
            "total_actions": total_actions,
            "total_searches": total_searches,
            "action_breakdown": action_breakdown,
        }


auth_manager = AuthManager()
