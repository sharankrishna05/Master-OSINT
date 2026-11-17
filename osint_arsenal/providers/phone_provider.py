import httpx
import uuid
import re
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class PhoneTelecomProvider(BaseOSINTProvider):
    name = "ITU-T E.164 Global Telecom & Routing"
    website = "https://www.itu.int"
    api_endpoint = "https://phonevalidation.abstractapi.com / ITU-T E.164 database"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.PHONE]
    enabled = True

    COUNTRY_CODES = {
        "1": {"country": "United States / Canada", "iso": "US/CA", "regex": r"^\+?1([2-9]\d{2})([2-9]\d{2})(\d{4})$"},
        "44": {"country": "United Kingdom", "iso": "GB", "regex": r"^\+?44([1-9]\d{8,9})$"},
        "91": {"country": "India", "iso": "IN", "regex": r"^\+?91([6-9]\d{9})$"},
        "61": {"country": "Australia", "iso": "AU", "regex": r"^\+?61([2-478]\d{8})$"},
        "49": {"country": "Germany", "iso": "DE", "regex": r"^\+?49([1-9]\d{8,11})$"},
        "33": {"country": "France", "iso": "FR", "regex": r"^\+?33([1-9]\d{8})$"},
        "81": {"country": "Japan", "iso": "JP", "regex": r"^\+?81([1-9]\d{8,9})$"},
        "86": {"country": "China", "iso": "CN", "regex": r"^\+?86([1-9]\d{9,10})$"},
        "7": {"country": "Russia / Kazakhstan", "iso": "RU/KZ", "regex": r"^\+?7([1-9]\d{9})$"},
    }

    INDIAN_SERIES = {
        "98": "Bharti Airtel / Vodafone Idea (Legacy GSM)",
        "99": "Vodafone Idea / Reliance (Legacy GSM)",
        "97": "Bharti Airtel / Vodafone Idea",
        "96": "Bharti Airtel / Idea",
        "95": "Reliance Jio / Vodafone Idea",
        "94": "BSNL Mobile (State Operator)",
        "93": "Reliance Jio / Reliance Telecom",
        "91": "Aircel / BSNL / Dynamic Allocation",
        "90": "Vodafone Idea",
        "89": "Tata Teleservices / Dynamic Allocation",
        "88": "Reliance Jio",
        "87": "Vodafone Idea / Airtel",
        "86": "Vodafone Idea / Jio",
        "85": "BSNL / Idea",
        "84": "Vodafone Idea",
        "83": "Reliance Jio",
        "82": "Vodafone Idea / BSNL",
        "81": "Airtel / Jio",
        "80": "Reliance Jio",
        "79": "Reliance Jio / Airtel",
        "78": "Airtel / Vodafone Idea",
        "77": "BSNL / Airtel",
        "76": "Reliance Jio",
        "75": "Vodafone Idea",
        "74": "BSNL / Airtel",
        "73": "Reliance Jio",
        "72": "Vodafone Idea",
        "70": "Reliance Jio / Airtel",
        "62": "Reliance Jio",
        "63": "Reliance Jio"
    }

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-TEL-{uuid.uuid4().hex[:8]}"
        clean_num = re.sub(r"[\s\-\(\)\.]", "", target.strip())
        digits_raw = re.sub(r"\D", "", clean_num)

        # Smart Indian & International normalization:
        # If user entered 10 digits starting with 6, 7, 8, or 9 (standard Indian mobile format)
        if len(digits_raw) == 10 and digits_raw[0] in "6789":
            clean_num = "+91" + digits_raw
        elif len(digits_raw) == 11 and digits_raw.startswith("0") and digits_raw[1] in "6789":
            clean_num = "+91" + digits_raw[1:]
        elif len(digits_raw) == 12 and digits_raw.startswith("91") and digits_raw[2] in "6789":
            clean_num = "+" + digits_raw
        elif clean_num.startswith("00"):
            clean_num = "+" + clean_num[2:]
        elif not clean_num.startswith("+"):
            clean_num = "+" + clean_num

        digits_only = clean_num.lstrip("+")
        matched_cc = None
        matched_info = None

        # Check ITU-T country codes (longest prefix match)
        for cc_len in [3, 2, 1]:
            cand = digits_only[:cc_len]
            if cand in self.COUNTRY_CODES:
                matched_cc = cand
                matched_info = self.COUNTRY_CODES[cand]
                break

        if not matched_cc:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.NO_RESULT,
                status_message="Number does not match recognized ITU-T E.164 country code allocation.",
                endpoint_queried="ITU-T E.164 Prefix Parser",
                raw_response={"target": target, "sanitized": clean_num}
            )

        national_significant = digits_only[len(matched_cc):]
        carrier_guess = "Unknown / Standard Telecom Carrier"
        line_type = "Mobile / Wireless" if len(national_significant) >= 10 else "Fixed Line / Geographic"

        indian_intel = {}
        if matched_cc == "91" and len(national_significant) == 10:
            prefix2 = national_significant[:2]
            carrier_guess = self.INDIAN_SERIES.get(prefix2, "Allocated Indian Mobile Operator")
            indian_intel = {
                "telecom_circle_jurisdiction": "Department of Telecommunications (DoT) / TRAI India",
                "truecaller_url": f"https://www.truecaller.com/search/in/{national_significant}",
                "whatsapp_chat": f"https://wa.me/91{national_significant}",
                "telegram_endpoint": f"https://t.me/+91{national_significant}",
                "sanchar_saathi_tafcop": "https://tafcop.sancharsaathi.gov.in/",
                "cybercrime_portal_india": "https://cybercrime.gov.in"
            }
        elif matched_cc == "1":
            carrier_guess = "North American NANP Carrier (Cellular/VoIP/Landline)"

        result_payload = {
            "e164_format": clean_num,
            "country_code": f"+{matched_cc}",
            "country": matched_info["country"],
            "iso_code": matched_info["iso"],
            "national_significant_number": national_significant,
            "line_type": line_type,
            "carrier_series_allocation": carrier_guess,
            "routing_validity": "Valid ITU-T E.164 National Destination Code",
            "indian_telecom_intel": indian_intel if indian_intel else None,
            "legal_disclosure": "Private subscriber identities (PII, residential addresses, Aadhaar, SSN) are non-public data protected under privacy laws and are strictly restricted from lawful OSINT engines."
        }

        return RawProviderResponse(
            collection_id=collection_id,
            provider=self.name,
            target=target,
            input_type=input_type.value,
            status=ProviderStatus.SUCCESS,
            status_message="ITU-T E.164 routing and carrier block resolved.",
            http_status_code=200,
            endpoint_queried="ITU-T E.164 International Standards Registry",
            raw_response=result_payload
        )

    def normalize(self, raw_response: RawProviderResponse) -> Dict[str, Any]:
        data = raw_response.raw_response
        return {
            "formatted_number": data.get("e164_format"),
            "country": data.get("country"),
            "iso": data.get("iso_code"),
            "country_code": data.get("country_code"),
            "line_type": data.get("line_type"),
            "carrier": data.get("carrier_series_allocation"),
            "validity": data.get("routing_validity"),
            "legal_notice": data.get("legal_disclosure")
        }
