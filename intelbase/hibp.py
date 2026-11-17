"""Have I Been Pwned (HIBP) API v3 integration client."""
import os
import aiohttp
import logging
from typing import List, Dict, Any, Tuple
from .models import BreachRecord
from .config import get_default_headers, DEFAULT_TOTAL_TIMEOUT, DEFAULT_CONNECT_TIMEOUT

logger = logging.getLogger("intelbase.hibp")

# ==============================================================================
# HIBP API KEY CONFIGURATION
# To query real-time Have I Been Pwned v3 breach records, provide your API key:
# PowerShell: $env:HIBP_API_KEY="your_api_key_here"
# Linux/Bash: export HIBP_API_KEY="your_api_key_here"
# ==============================================================================
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"

class HIBPClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or HIBP_API_KEY

    async def get_breaches(self, session: aiohttp.ClientSession, email: str) -> Tuple[List[BreachRecord], Dict[str, Any]]:
        """Query breachedaccount API for given email.
        
        Returns:
            Tuple[List[BreachRecord], status_meta_dict]
        """
        if not self.api_key:
            # Informative fallback when API key is not configured in environment
            logger.info("HIBP_API_KEY is not set. Operating in offline/unconfigured mode.")
            return [], {
                "status": "UNCONFIGURED",
                "message": "HIBP_API_KEY environment variable is not configured. Real-time HIBP breach lookup skipped.",
                "has_key": False
            }

        url = f"{HIBP_API_BASE}/breachedaccount/{email}?truncateResponse=false"
        headers = get_default_headers({
            "hibp-api-key": self.api_key,
            "User-Agent": "IntelBase-OSINT-Prototype/1.0"
        })

        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    records = []
                    for item in data:
                        data_classes = item.get("DataClasses", [])
                        has_pw = any("password" in dc.lower() for dc in data_classes)
                        records.append(BreachRecord(
                            name=item.get("Name", "Unknown"),
                            title=item.get("Title", "Unknown Breach"),
                            domain=item.get("Domain", ""),
                            breach_date=item.get("BreachDate", "Unknown"),
                            added_date=item.get("AddedDate", "Unknown"),
                            pwn_count=item.get("PwnCount", 0),
                            data_classes=data_classes,
                            is_verified=item.get("IsVerified", True),
                            is_sensitive=item.get("IsSensitive", False),
                            has_passwords=has_pw
                        ))
                    return records, {"status": "SUCCESS", "message": f"Found {len(records)} breach incident(s)", "has_key": True}

                elif resp.status == 404:
                    return [], {"status": "CLEAN", "message": "No breach records found for this email address", "has_key": True}

                elif resp.status == 429:
                    retry_after = resp.headers.get("Retry-After", "2")
                    return [], {"status": "RATE_LIMITED", "message": f"HIBP rate limited (Retry-After: {retry_after}s)", "has_key": True}

                elif resp.status == 401:
                    return [], {"status": "UNAUTHORIZED", "message": "Invalid HIBP API key supplied", "has_key": True}

                else:
                    return [], {"status": "ERROR", "message": f"HIBP returned HTTP {resp.status}", "has_key": True}

        except Exception as e:
            logger.error("HIBP query failed: %s", e)
            return [], {"status": "ERROR", "message": f"HIBP request error: {str(e)}", "has_key": bool(self.api_key)}
