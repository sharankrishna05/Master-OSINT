import re
import ipaddress
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("nostromo.legal_gate")

FORBIDDEN_HOST_PATTERNS = [
    r"\.onion$",
    r"\.i2p$",
    r"tor2web",
    r"leak-market",
]

STRICT_PRIVATE_PII_PATTERNS = [
    r"^\d{3}-\d{2}-\d{4}$",
    r"^\d{16}$",
]

class LegalGateKeeper:
    @staticmethod
    def audit_target(target: str, target_type: str) -> Tuple[bool, str]:
        target = target.strip()
        
        for pattern in FORBIDDEN_HOST_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                logger.critical(f"LEGAL GATE REJECTION: Target '{target}' points to forbidden darknet routes.")
                return False, "E_DARKNET_RESTRICTED: Direct access to .onion/.i2p dark web services is strictly forbidden."

        if target_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(target)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                    return False, f"E_INTERNAL_IP: Access to RFC1918/Local IP ({target}) is blocked by safety policy."
            except ValueError:
                return False, f"E_INVALID_IP: String '{target}' is not a valid IPv4/IPv6 address."

        for pattern in STRICT_PRIVATE_PII_PATTERNS:
            if re.match(pattern, target):
                return False, "E_PII_RESTRICTED: Raw personal identification numbers (SSN/CCN) cannot be queried."

        return True, "TARGET_COMPLIANT_TLP_WHITE"

    @staticmethod
    def redact_credential(credential_data: Dict[str, Any]) -> Dict[str, Any]:
        redacted = credential_data.copy()
        if "password" in redacted:
            pwd = str(redacted["password"])
            redacted["password"] = f"[REDACTED_HASHED:{pwd[:2]}***{pwd[-2:]}]" if len(pwd) > 4 else "[REDACTED]"
        if "hash" in redacted:
            h = str(redacted["hash"])
            redacted["hash"] = f"{h[:8]}...[TRUNCATED]"
        return redacted
