from __future__ import annotations
from .base import SiteModule, registry


class PhoneParseModule(SiteModule):
    name = "PhoneParse"
    category = "major"
    supported = {"phone"}

    async def check(self, client, query: str) -> dict:
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier
        except ImportError:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": "phonenumbers not installed"}}
        try:
            p = phonenumbers.parse(query, None)
        except Exception as e:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": str(e)}}
        valid = phonenumbers.is_valid_number(p)
        return {
            "status": "found" if valid else "inconclusive",
            "url": None, "http_status": None, "confidence": 0.95,
            "evidence": {
                "e164": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
                "national": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
                "country": geocoder.description_for_number(p, "en"),
                "carrier": carrier.name_for_number(p, "en"),
                "line_type": str(phonenumbers.number_type(p)),
                "valid": valid,
            },
        }


def load_builtin():
    registry.register(PhoneParseModule())
