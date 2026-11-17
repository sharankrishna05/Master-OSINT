"""IntelBase configuration module."""
import os
from typing import Dict

# Default realistic User-Agent to prevent basic blockades
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Network timeouts
DEFAULT_TOTAL_TIMEOUT = 10.0  # seconds
DEFAULT_CONNECT_TIMEOUT = 4.0  # seconds

# Have I Been Pwned API Key from environment variable
# Leave placeholder comment as required
# e.g., export HIBP_API_KEY="your_api_key_here"
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")

def get_default_headers(custom_headers: Dict[str, str] = None) -> Dict[str, str]:
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if custom_headers:
        headers.update(custom_headers)
    return headers
