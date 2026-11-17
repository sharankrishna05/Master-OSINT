from __future__ import annotations
import re
from typing import Tuple

CLASSIFICATION_RULES = [
    # 1. Directory Indexing
    (
        "Directory Listing",
        [r"index of /", r"parent directory", r"last modified", r"size\s+description"],
        0.95
    ),
    # 2. Login & Administrative Panels
    (
        "Login Panel",
        [r"login", r"signin", r"admin", r"dashboard", r"cpanel", r"single sign on", r"user authentication", r"sso"],
        0.90
    ),
    # 3. Exposed Files & Backups
    (
        "Exposed File / Backup",
        [r"\.env", r"\.sql", r"\.bak", r"\.backup", r"\.log", r"dump\.sql", r"database dump", r"insert into", r"config\.json"],
        0.92
    ),
    # 4. Cloud Storage Exposures
    (
        "Cloud Storage Exposure",
        [r"s3\.amazonaws\.com", r"blob\.core\.windows\.net", r"storage\.googleapis\.com", r"firebaseio\.com"],
        0.95
    ),
    # 5. Infrastructure / DevOps
    (
        "Infrastructure / DevOps",
        [r"jenkins", r"gitlab", r"grafana", r"kibana", r"phpmyadmin", r"adminer", r"webcam", r"camera view"],
        0.88
    ),
    # 6. Error Messages & Stack Traces
    (
        "Error / Stack Trace",
        [r"fatal error", r"traceback \(most recent call last\)", r"nullpointerexception", r"syntax error", r"sql syntax"],
        0.91
    ),
    # 7. API Documentation
    (
        "API Documentation",
        [r"swagger ui", r"openapi", r"postman", r"graphql", r"graphiql", r"api documentation"],
        0.87
    )
]

def classify_result(title: str, snippet: str, url: str) -> Tuple[str, float]:
    """
    Classify a search result into an operational category based on title, snippet, and URL patterns.
    """
    corpus = f"{title} {snippet} {url}".lower()

    for category, patterns, confidence in CLASSIFICATION_RULES:
        for p in patterns:
            if re.search(p, corpus):
                return category, confidence

    return "Uncategorized", 0.60
