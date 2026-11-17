from __future__ import annotations
import asyncio
import ssl
import socket
from .base import Job, registry


class SSLChainJob(Job):
    name = "ssl_chain"
    label = "SSL Certificate Chain"
    group = "Security"

    async def run(self, ctx: dict):
        if ctx["scheme"] != "https":
            return {"skipped": "not HTTPS"}
        try:
            return await asyncio.to_thread(_get_cert, ctx["host"])
        except Exception as e:
            return {"error": str(e)}


def _get_cert(host: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
    return {
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "subjectAltName": cert.get("subjectAltName", []),
        "tls_version": version,
        "cipher": cipher,
    }


registry.register(SSLChainJob())
