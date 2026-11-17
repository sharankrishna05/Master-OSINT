from __future__ import annotations
import urllib.parse
import re
from typing import List
from ..models import SearchResult

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}

def normalize_url(url: str) -> str:
    """Normalize URL by lowercasing scheme/host, stripping standard ports, fragments, and tracking params."""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()

        # Strip standard default ports (:80 for http, :443 for https)
        if scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        elif scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]

        path = parsed.path
        if not path:
            path = "/"
        elif path.endswith("/") and len(path) > 1:
            path = path[:-1]

        # Strip tracking query parameters
        qs = urllib.parse.parse_qsl(parsed.query)
        cleaned_qs = [(k, v) for k, v in qs if k.lower() not in TRACKING_PARAMS]
        query = urllib.parse.urlencode(cleaned_qs)

        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return url.strip().lower()

def extract_domain(url: str) -> str:
    """Extract registered host / domain from a URL."""
    try:
        parsed = urllib.parse.urlsplit(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

def deduplicate_results(results: List[SearchResult]) -> List[SearchResult]:
    """Deduplicate search results by normalized URL while preserving first-seen order."""
    seen_urls = set()
    deduped = []
    for r in results:
        norm = normalize_url(r.url)
        if norm and norm not in seen_urls:
            seen_urls.add(norm)
            r.normalized_url = norm
            if not r.domain:
                r.domain = extract_domain(r.url)
            deduped.append(r)
    return deduped
