from __future__ import annotations
import ssl
import socket
from .base import Job, registry


class TLSCiphersJob(Job):
    name = "tls_ciphers"
    label = "TLS Cipher Suites"
    group = "Security"

    async def run(self, ctx: dict):
        host = ctx["host"]
        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5.0) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "version": version,
                        "cipher_name": cipher[0] if cipher else None,
                        "protocol": cipher[1] if cipher else None,
                        "bits": cipher[2] if cipher else None,
                    }
        except Exception as e:
            return {"error": str(e)}


registry.register(TLSCiphersJob())
