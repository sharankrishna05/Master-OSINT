"""Target Classification Engine.

Detects target typology:
  username, email, phone, domain, ipv4, ipv6, mac, url,
  image_file, hash, person_name, company, crypto_addr, unknown.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

import phonenumbers


COMPANY_SUFFIXES = {
    "inc", "inc.", "llc", "corp", "corp.", "corporation",
    "ltd", "ltd.", "limited", "gmbh", "co.", "co", "plc",
    "s.a.", "sa", "ag", "nv", "bv", "holding", "holdings"
}

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".tiff", ".tif", ".heic", ".svg", ".raw", ".ico"
}


def classify_target(raw_input: str) -> Tuple[str, str, float]:
    """Classify the input string into one of the 14 OSINT typology categories.

    Returns:
        (detected_type, normalised_value, confidence)
    """
    val = raw_input.strip()
    if not val:
        return ("unknown", "", 0.0)

    # 1. URL Check
    if val.startswith(("http://", "https://", "ftp://")):
        try:
            parsed = urlparse(val)
            if parsed.netloc:
                return ("url", val, 1.0)
        except Exception:
            pass

    # 2. IPv4 Check
    try:
        ip_obj = ipaddress.ip_address(val)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return ("ipv4", str(ip_obj), 1.0)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return ("ipv6", str(ip_obj), 1.0)
    except ValueError:
        pass

    # 3. MAC Address Check
    mac_clean = val.replace("-", ":").replace(".", "").lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", val.lower()) or re.fullmatch(r"([0-9a-f]{2}-){5}[0-9a-f]{2}", val.lower()):
        norm_mac = val.upper().replace("-", ":")
        return ("mac", norm_mac, 1.0)
    if re.fullmatch(r"[0-9a-f]{12}", mac_clean):
        norm_mac = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper()
        return ("mac", norm_mac, 0.95)

    # 4. Email Check
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.fullmatch(email_regex, val):
        return ("email", val.lower(), 1.0)

    # 5. Crypto Address Check
    # Bitcoin Legacy (1...), P2SH (3...) Base58
    if re.fullmatch(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", val):
        return ("crypto_addr", val, 0.98)
    # Bitcoin Bech32 (bc1...)
    if re.fullmatch(r"^bc1[a-z0-9]{38,59}$", val.lower()):
        return ("crypto_addr", val.lower(), 0.98)
    # Ethereum (0x... 40 hex)
    if re.fullmatch(r"^0x[a-fA-F0-9]{40}$", val):
        return ("crypto_addr", val, 0.98)
    # Monero (starts with 4 or 8, 95 or 106 chars)
    if re.fullmatch(r"^[48][0-9ABa-zA-Z]{94,105}$", val):
        return ("crypto_addr", val, 0.98)

    # 6. Hash Check (MD5, SHA1, SHA256)
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", val):
        return ("hash", val.lower(), 0.95)
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", val):
        return ("hash", val.lower(), 0.95)
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", val):
        return ("hash", val.lower(), 0.95)

    # 6b. VIN / Vehicle Identification Number (17 chars, no I, O, Q)
    if re.fullmatch(r"^[A-HJ-NPR-Za-hj-npr-z0-9]{17}$", val) and not re.fullmatch(r"^[0-9]+$", val):
        return ("vin", val.upper(), 0.95)

    # 7. Image File Check (Path or filename)
    p = Path(val)
    if p.suffix.lower() in IMAGE_EXTENSIONS or (p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS):
        return ("image_file", str(p), 0.95)

    # 8. Phone Number Check
    digits_raw = re.sub(r"\D", "", val)
    is_phone_candidate = (
        val.startswith("+")
        or (len(digits_raw) == 10 and digits_raw[0] in "6789")
        or (len(digits_raw) == 11 and digits_raw.startswith("0") and digits_raw[1] in "6789")
        or (len(digits_raw) in range(7, 16) and not any(c in val for c in "@./\\") and not val.isalpha())
    )
    if is_phone_candidate:
        # Check India first if matches Indian mobile syntax
        if (len(digits_raw) == 10 and digits_raw[0] in "6789") or (len(digits_raw) == 11 and digits_raw.startswith("0")):
            try:
                parsed_phone = phonenumbers.parse(digits_raw[-10:], "IN")
                if phonenumbers.is_valid_number(parsed_phone) or phonenumbers.is_possible_number(parsed_phone):
                    norm_phone = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)
                    return ("phone", norm_phone, 0.95)
            except Exception:
                pass

        try:
            parsed_phone = phonenumbers.parse(val, None)
            if phonenumbers.is_valid_number(parsed_phone):
                norm_phone = phonenumbers.format_number(
                    parsed_phone, phonenumbers.PhoneNumberFormat.E164
                )
                return ("phone", norm_phone, 0.95)
            elif phonenumbers.is_possible_number(parsed_phone):
                norm_phone = phonenumbers.format_number(
                    parsed_phone, phonenumbers.PhoneNumberFormat.E164
                )
                return ("phone", norm_phone, 0.75)
        except Exception:
            # Multi-region fallback: India, then US, then UK
            for reg in ["IN", "US", "GB"]:
                try:
                    parsed_phone = phonenumbers.parse(val, reg)
                    if phonenumbers.is_valid_number(parsed_phone) or phonenumbers.is_possible_number(parsed_phone):
                        norm_phone = phonenumbers.format_number(
                            parsed_phone, phonenumbers.PhoneNumberFormat.E164
                        )
                        return ("phone", norm_phone, 0.88)
                except Exception:
                    pass

    # 9. Company Name Check
    words = val.lower().split()
    if any(w.strip(",.") in COMPANY_SUFFIXES for w in words):
        return ("company", val, 0.85)

    # 10. Domain Name Check
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.fullmatch(domain_regex, val) and not val.endswith(tuple(IMAGE_EXTENSIONS)):
        return ("domain", val.lower(), 0.90)

    # 11. Person Name Check (2 to 4 capitalized words)
    name_regex = r"^[A-Z][a-zA-Z']+(?:\s+[A-Z][a-zA-Z']+){1,3}$"
    if re.fullmatch(name_regex, val):
        # Confidence 0.65 triggers confirmation rule (< 0.7)
        return ("person_name", val, 0.65)

    # 12. Username Check (alphanumeric + _ . - length 3-32)
    username_regex = r"^[a-zA-Z0-9_.-]{3,32}$"
    if re.fullmatch(username_regex, val):
        return ("username", val, 0.75)

    # Fallback: Unknown
    return ("unknown", val, 0.0)


def requires_confirmation(confidence: float) -> bool:
    """Return True if classification confidence is below the threshold of 0.7."""
    return 0.0 < confidence < 0.7
