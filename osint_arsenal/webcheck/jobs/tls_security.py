from __future__ import annotations
import ssl
import socket
from datetime import datetime
from .base import Job, registry


class TLSSecurityJob(Job):
    name = "tls_security"
    label = "TLS Security Assessment"
    group = "Security"

    async def run(self, ctx: dict):
        host = ctx["host"]
        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5.0) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter", "")
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                    days_left = (exp_date - datetime.utcnow()).days if exp_date else None
                    return {
                        "valid": True,
                        "days_until_expiration": days_left,
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}


registry.register(TLSSecurityJob())
