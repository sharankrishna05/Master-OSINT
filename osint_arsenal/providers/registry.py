import os
import re
import asyncio
import logging
from typing import List, Dict, Any, Tuple
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse
from .dns_provider import GoogleDoHDNSProvider
from .whois_provider import RdapWhoisProvider
from .crt_provider import CrtShCertificateProvider
from .ipinfo_provider import IPInfoGeoProvider
from .virustotal_provider import VirusTotalProvider
from .greynoise_provider import GreyNoiseCommunityProvider
from .pwned_passwords_provider import HIBPPwnedPasswordsProvider
from .urlscan_provider import URLScanSearchProvider
from .phone_provider import PhoneTelecomProvider
from .github_provider import GitHubPublicUserProvider
from .crypto_provider import CryptoBlockchainProvider
from .abuseipdb_provider import AbuseIPDBProvider
from .opensanctions_provider import OpenSanctionsProvider
from .shodan_provider import ShodanHostProvider

logger = logging.getLogger("nostromo.provider_registry")

class ProviderRegistry:
    def __init__(self):
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")

        # Initializing real modular adapters
        self.providers: List[BaseOSINTProvider] = [
            GoogleDoHDNSProvider(),
            RdapWhoisProvider(),
            CrtShCertificateProvider(),
            IPInfoGeoProvider(),
            VirusTotalProvider(api_key=vt_key),
            GreyNoiseCommunityProvider(),
            HIBPPwnedPasswordsProvider(),
            URLScanSearchProvider(),
            PhoneTelecomProvider(),
            GitHubPublicUserProvider(),
            CryptoBlockchainProvider(),
            AbuseIPDBProvider(api_key=abuse_key),
            OpenSanctionsProvider(),
            ShodanHostProvider(api_key=shodan_key)
        ]

    def detect_input_type(self, target: str) -> Tuple[str, InputType, str]:
        target = target.strip()
        normalized = target
        digits_only = re.sub(r'\D', '', target)

        if "@" in target:
            return target, InputType.EMAIL, normalized.lower()
        if target.startswith("http://") or target.startswith("https://"):
            lower_u = target.lower()
            if any(lower_u.endswith(ext) or (ext + "?") in lower_u for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"]):
                return target, InputType.IMAGE, normalized
            if any(lower_u.endswith(ext) or (ext + "?") in lower_u for ext in [".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".csv", ".txt", ".bin"]):
                return target, InputType.DOCUMENT, normalized
            return target, InputType.URL, normalized
        if any(target.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"]):
            return target, InputType.IMAGE, normalized
        if any(target.lower().endswith(ext) for ext in [".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".csv", ".bin"]):
            return target, InputType.DOCUMENT, normalized
        if target.replace(".", "").isdigit() and len(target.split(".")) == 4:
            return target, InputType.IP, normalized
        if len(target) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in target) and not target.isdigit():
            return target, InputType.HASH, normalized.lower()
        # Indian & International Phone Detection
        if (target.startswith("+") or len(digits_only) in range(7, 16)) and not any(c in target for c in "@./\\"):
            if len(digits_only) == 10 and digits_only[0] in "6789":
                normalized = f"+91{digits_only}"
            elif len(digits_only) == 11 and digits_only.startswith("0") and digits_only[1] in "6789":
                normalized = f"+91{digits_only[1:]}"
            elif len(digits_only) == 12 and digits_only.startswith("91") and digits_only[2] in "6789":
                normalized = f"+{digits_only}"
            elif not normalized.startswith("+"):
                normalized = f"+{digits_only}"
            return target, InputType.PHONE, normalized
        if (target.startswith("0x") and len(target) == 42) or target.startswith("bc1") or (len(target) in range(26, 36) and (target.startswith("1") or target.startswith("3"))):
            return target, InputType.CRYPTO, normalized
        if "." in target and " " not in target:
            return target, InputType.DOMAIN, normalized.lower()
        if " " in target or any(w in target.lower() for w in ["inc", "corp", "corporation", "ltd", "limited", "pvt", "llc", "gmbh", "technologies", "university", "institute", "foundation", "group", "bank"]):
            return target, InputType.ORGANIZATION, normalized
        
        return target, InputType.USERNAME, normalized

    def get_applicable_providers(self, input_type: InputType) -> List[BaseOSINTProvider]:
        return [p for p in self.providers if p.can_process(input_type)]

    async def execute_all(self, target: str, input_type: InputType) -> Dict[str, Any]:
        applicable = self.get_applicable_providers(input_type)
        logger.info(f"Executing {len(applicable)} applicable OSINT providers for input {target} ({input_type.value})")

        tasks = [p.collect(target, input_type) for p in applicable]
        raw_responses: List[RawProviderResponse] = await asyncio.gather(*tasks, return_exceptions=False)

        results_by_category = {}
        provider_statuses = {}
        raw_evidence_store = []

        stats = {
            "total_applicable": len(applicable),
            "successful": 0,
            "no_result": 0,
            "auth_required": 0,
            "failed": 0,
            "rate_limited": 0,
            "timeout": 0
        }

        for provider, raw in zip(applicable, raw_responses):
            if isinstance(raw, Exception):
                provider_statuses[provider.name] = {
                    "status": ProviderStatus.FAILED.value,
                    "message": f"Provider collection error: {str(raw)}",
                    "http_status": 500,
                    "endpoint": "Error"
                }
                stats["failed"] += 1
                continue
            provider_statuses[provider.name] = {
                "status": raw.status.value,
                "message": raw.status_message,
                "http_status": raw.http_status_code,
                "endpoint": raw.endpoint_queried
            }

            raw_evidence_store.append(raw.dict())

            if raw.status == ProviderStatus.SUCCESS:
                stats["successful"] += 1
                normalized_data = provider.normalize(raw)
                results_by_category[provider.name] = {
                    "status": "SUCCESS",
                    "data": normalized_data,
                    "evidence_id": raw.collection_id
                }
            elif raw.status == ProviderStatus.NO_RESULT:
                stats["no_result"] += 1
                results_by_category[provider.name] = {
                    "status": "NO_RESULT",
                    "message": raw.status_message
                }
            elif raw.status == ProviderStatus.AUTH_REQUIRED:
                stats["auth_required"] += 1
                results_by_category[provider.name] = {
                    "status": "AUTH_REQUIRED",
                    "message": raw.status_message
                }
            elif raw.status == ProviderStatus.TIMEOUT:
                stats["timeout"] += 1
            elif raw.status == ProviderStatus.RATE_LIMITED:
                stats["rate_limited"] += 1
            else:
                stats["failed"] += 1

        return {
            "target": target,
            "input_type": input_type.value,
            "stats": stats,
            "provider_statuses": provider_statuses,
            "structured_results": results_by_category,
            "raw_responses": raw_evidence_store
        }
