# osint_arsenal/cti/database_catalog.py
"""
Universal OSINT Database Catalog & Connector Registry
Covers all 15 Core OSINT Domains (Categories A through O)
Fully compliant with TLP:WHITE public-domain intelligence collection.
"""

from typing import Dict, List, Any, Optional
import urllib.parse

DATABASE_CATEGORIES = {
    "A": {
        "code": "A",
        "name": "SURFACE WEB (Indexed)",
        "badge": "SURFACE WEB",
        "color": "#00f5ff",
        "description": "Public search engine indexes, caching layers, and petabyte-scale web crawl repositories."
    },
    "B": {
        "code": "B",
        "name": "DEEP WEB (Public Unindexed)",
        "badge": "DEEP WEB",
        "color": "#39ff14",
        "description": "Exposed cloud storage buckets, open database instances, public paste sites, and public channel previews."
    },
    "C": {
        "code": "C",
        "name": "ARCHIVES & HISTORICAL",
        "badge": "HISTORICAL ARCHIVES",
        "color": "#ffd60a",
        "description": "CDX historical URL endpoints, multi-decade web archives, national library repositories, and scholarly records."
    },
    "D": {
        "code": "D",
        "name": "BREACH & LEAK INTELLIGENCE",
        "badge": "BREACH RADAR",
        "color": "#ff003c",
        "description": "Public breach notifications, k-anonymity password dumps, credential leak directories, and incident registries."
    },
    "E": {
        "code": "E",
        "name": "IDENTITY & PEOPLE INTELLIGENCE",
        "badge": "PEOPLE OSINT",
        "color": "#bf5af2",
        "description": "Public records aggregators, professional licenses, public profile verification, academic credentials, and registries."
    },
    "F": {
        "code": "F",
        "name": "INFRASTRUCTURE & NETWORK",
        "badge": "CTI INFRASTRUCTURE",
        "color": "#06b6d4",
        "description": "Internet-wide port scanners, passive DNS, BGP routing, Certificate Transparency logs, and RFC email configs."
    },
    "G": {
        "code": "G",
        "name": "THREAT INTELLIGENCE FEEDS",
        "badge": "THREAT FEEDS",
        "color": "#f97316",
        "description": "MITRE ATT&CK mappings, CISA KEV advisories, malware telemetry, vulnerability registries, and ransomware trackers."
    },
    "H": {
        "code": "H",
        "name": "SOCIAL MEDIA (Public)",
        "badge": "SOCMINT",
        "color": "#ec4899",
        "description": "Public profile discovery, social graph telemetry, public community channels, and content streaming APIs."
    },
    "I": {
        "code": "I",
        "name": "MEDIA & DOCUMENTS",
        "badge": "DOCUMENT INTEL",
        "color": "#14b8a6",
        "description": "EXIF metadata forensic analysis, visual reverse image search, OCR text extraction, and public document indices."
    },
    "J": {
        "code": "J",
        "name": "GEOSPATIAL (GEOINT)",
        "badge": "GEOINT",
        "color": "#10b981",
        "description": "OpenStreetMap Overpass queries, satellite imagery telemetry (Sentinel/Landsat), live AIS/ADS-B, and Wi-Fi mapping."
    },
    "K": {
        "code": "K",
        "name": "CODE & REPOSITORIES",
        "badge": "CODE RECON",
        "color": "#8b5cf6",
        "description": "Public git repository search, secret scanning signatures, package registry metadata (PyPI/npm), and container hubs."
    },
    "L": {
        "code": "L",
        "name": "DARK WEB (Legal Portion Only)",
        "badge": "DARKNET INDEX",
        "color": "#f43f5e",
        "description": "Clearnet .onion search engines, dark web directories, ransomware leak site metadata, and threat research blogs."
    },
    "M": {
        "code": "M",
        "name": "FINANCIAL & CORPORATE",
        "badge": "FINANCIAL INTEL",
        "color": "#eab308",
        "description": "Global corporate registries, SEC EDGAR filings, sanctions watchlists (OFAC/UN/EU), and blockchain public explorers."
    },
    "N": {
        "code": "N",
        "name": "GOVERNMENT & PUBLIC RECORDS",
        "badge": "PUBLIC RECORDS",
        "color": "#6366f1",
        "description": "Open government data portals, federal/state court dockets, patents & trademarks, regulatory recalls, and filings."
    },
    "O": {
        "code": "O",
        "name": "AI-ENRICHMENT SOURCES",
        "badge": "AI ENRICHMENT",
        "color": "#38bdf8",
        "description": "Grounded LLM intelligence pipelines, knowledge graph ontologies (Wikidata/DBpedia), and contextual synthesis."
    }
}

OSINT_DATABASES: List[Dict[str, Any]] = [
    # ==========================================
    # A. SURFACE WEB (indexed)
    # ==========================================
    {
        "id": "db-a-01",
        "category": "A",
        "name": "DuckDuckGo Public Search",
        "access": "OPEN_FREE",
        "description": "Privacy-focused public search index queryable via clearnet HTML/API endpoints without tracking.",
        "typologies": ["domain", "ip", "email", "username", "person"],
        "url_template": "https://duckduckgo.com/?q={query}",
        "api_endpoint": "https://html.duckduckgo.com/html/?q={query}"
    },
    {
        "id": "db-a-02",
        "category": "A",
        "name": "Google Search / Dorking Index",
        "access": "OPEN_FREE",
        "description": "Primary global web index supporting boolean operators, filetype, site, inurl, and cache directives.",
        "typologies": ["domain", "email", "username", "hash", "person"],
        "url_template": "https://www.google.com/search?q={query}",
        "api_endpoint": "https://customsearch.googleapis.com/v1"
    },
    {
        "id": "db-a-03",
        "category": "A",
        "name": "Bing & Microsoft Search",
        "access": "OPEN_FREE",
        "description": "Alternative index with dedicated IP reverse lookup (ip:) and document indexing capabilities.",
        "typologies": ["domain", "ip", "person"],
        "url_template": "https://www.bing.com/search?q={query}",
        "api_endpoint": "https://api.bing.microsoft.com/v7.0/search"
    },
    {
        "id": "db-a-04",
        "category": "A",
        "name": "Startpage",
        "access": "OPEN_FREE",
        "description": "Proxy-rendered high-privacy Google search results bypassing localized tracking algorithms.",
        "typologies": ["person", "username", "domain"],
        "url_template": "https://www.startpage.com/sp/search?query={query}"
    },
    {
        "id": "db-a-05",
        "category": "A",
        "name": "Brave Search Index",
        "access": "OPEN_FREE",
        "description": "Independent search index built from scratch without reliance on Big Tech search clusters.",
        "typologies": ["domain", "person", "username"],
        "url_template": "https://search.brave.com/search?q={query}",
        "api_endpoint": "https://api.search.brave.com/res/v1/web/search"
    },
    {
        "id": "db-a-06",
        "category": "A",
        "name": "Mojeek Search",
        "access": "OPEN_FREE",
        "description": "Independent crawler-based search engine with strict no-tracking index of 8+ billion pages.",
        "typologies": ["domain", "person"],
        "url_template": "https://www.mojeek.com/search?q={query}"
    },
    {
        "id": "db-a-07",
        "category": "A",
        "name": "SearXNG Public Instances",
        "access": "OPEN_FREE",
        "description": "Decentralized metasearch engine combining results from over 70 search services simultaneously.",
        "typologies": ["domain", "ip", "username", "person"],
        "url_template": "https://searx.be/search?q={query}"
    },
    {
        "id": "db-a-08",
        "category": "A",
        "name": "Common Crawl Index",
        "access": "OPEN_FREE",
        "description": "Petabyte-scale public repository of web crawl data with columnar index available on Amazon S3.",
        "typologies": ["domain", "url"],
        "url_template": "https://commoncrawl.org/the-data/",
        "api_endpoint": "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url={query}&output=json"
    },
    {
        "id": "db-a-09",
        "category": "A",
        "name": "Wayback Machine (Archive.org)",
        "access": "OPEN_FREE",
        "description": "Digital archive of 850+ billion web pages capturing historical snapshots and deleted resources.",
        "typologies": ["domain", "url"],
        "url_template": "https://web.archive.org/web/*/{query}",
        "api_endpoint": "https://archive.org/wayback/available?url={query}"
    },
    {
        "id": "db-a-10",
        "category": "A",
        "name": "Archive.today / Archive.ph",
        "access": "OPEN_FREE",
        "description": "On-demand webpage snapshot archive storing unaltered text and screenshot proofs of online content.",
        "typologies": ["domain", "url"],
        "url_template": "https://archive.today/{query}"
    },

    # ==========================================
    # B. DEEP WEB (public but unindexed)
    # ==========================================
    {
        "id": "db-b-01",
        "category": "B",
        "name": "GrayhatWarfare Public S3 Buckets",
        "access": "FREE_TIER",
        "description": "Searchable database indexing over 4 billion publicly accessible files across misconfigured cloud buckets.",
        "typologies": ["domain", "company", "username"],
        "url_template": "https://buckets.grayhatwarfare.com/files?keywords={query}",
        "api_endpoint": "https://buckets.grayhatwarfare.com/api/v1/files/{query}"
    },
    {
        "id": "db-b-02",
        "category": "B",
        "name": "Public Elasticsearch / Redis / MongoDB Shodan Scanner",
        "access": "FREE_TIER",
        "description": "Public banner search for open, unauthenticated enterprise database endpoints on standard ports.",
        "typologies": ["ip", "domain", "asn"],
        "url_template": "https://www.shodan.io/search?query=port:9200,6379,27017+{query}",
        "api_endpoint": "https://api.shodan.io/shodan/host/search?query={query}"
    },
    {
        "id": "db-b-03",
        "category": "B",
        "name": "Public FTP Index (Mammoth / SearchFTPs)",
        "access": "OPEN_FREE",
        "description": "Global index of public, anonymous File Transfer Protocol servers indexing open directories.",
        "typologies": ["domain", "ip"],
        "url_template": "https://www.searchftps.net/?q={query}"
    },
    {
        "id": "db-b-04",
        "category": "B",
        "name": "Public Directory Listings (Apache/Nginx Autoindex)",
        "access": "OPEN_FREE",
        "description": "Google dork scanner locating open directory indexes revealing backups, logs, and sensitive data.",
        "typologies": ["domain"],
        "url_template": "https://www.google.com/search?q=site:{query}+intitle:\"index+of\""
    },
    {
        "id": "db-b-05",
        "category": "B",
        "name": "Pastebin Public Search",
        "access": "OPEN_FREE",
        "description": "Clearnet search for publicly shared plaintext snippets, error logs, and source code pastes.",
        "typologies": ["domain", "email", "username", "hash"],
        "url_template": "https://www.google.com/search?q=site:pastebin.com+\"{query}\""
    },
    {
        "id": "db-b-06",
        "category": "B",
        "name": "Paste.ee & Rentry.co Index",
        "access": "OPEN_FREE",
        "description": "Alternative paste repositories frequently utilized for markdown briefs and developer dumps.",
        "typologies": ["email", "username", "domain"],
        "url_template": "https://www.google.com/search?q=(site:paste.ee+OR+site:rentry.co)+\"{query}\""
    },
    {
        "id": "db-b-07",
        "category": "B",
        "name": "Telegram Public Web Previews (t.me/s/)",
        "access": "OPEN_FREE",
        "description": "Direct clearnet web index of publicly broadcasted Telegram channels without account login requirements.",
        "typologies": ["username", "domain", "person"],
        "url_template": "https://t.me/s/{query}"
    },
    {
        "id": "db-b-08",
        "category": "B",
        "name": "Disboard Public Discord Directory",
        "access": "OPEN_FREE",
        "description": "Public search engine for discovering active Discord communities, invite links, and server metadata.",
        "typologies": ["username", "domain", "company"],
        "url_template": "https://disboard.org/search?keyword={query}"
    },

    # ==========================================
    # C. ARCHIVES & HISTORICAL
    # ==========================================
    {
        "id": "db-c-01",
        "category": "C",
        "name": "Wayback Machine CDX Server API",
        "access": "OPEN_FREE",
        "description": "Programmatic index endpoint returning every URL archived for a domain with timestamps and status codes.",
        "typologies": ["domain", "url"],
        "url_template": "https://web.archive.org/cdx/search/cdx?url=*.{query}/*&output=json&limit=50",
        "api_endpoint": "https://web.archive.org/cdx/search/cdx?url=*.{query}/*&output=json"
    },
    {
        "id": "db-c-02",
        "category": "C",
        "name": "Arquivo.pt Web Archive",
        "access": "OPEN_FREE",
        "description": "Major European public research web archive with full-text search across billions of historical web pages.",
        "typologies": ["domain", "person"],
        "url_template": "https://arquivo.pt/textsearch?q={query}",
        "api_endpoint": "https://arquivo.pt/textsearch?q={query}&format=json"
    },
    {
        "id": "db-c-03",
        "category": "C",
        "name": "UK Web Archive",
        "access": "OPEN_FREE",
        "description": "Official legal deposit web archive preserving UK domain history and historical societal publications.",
        "typologies": ["domain", "company", "person"],
        "url_template": "https://www.webarchive.org.uk/en/ukwa/search?q={query}"
    },
    {
        "id": "db-c-04",
        "category": "C",
        "name": "Bibliotheca Alexandrina Internet Archive",
        "access": "OPEN_FREE",
        "description": "International digital heritage repository maintaining mirrors of historical web crawls and Arabic texts.",
        "typologies": ["domain", "person"],
        "url_template": "http://web.archive.bibalex.org/web/*/{query}"
    },
    {
        "id": "db-c-05",
        "category": "C",
        "name": "Internet Archive Scholar & TV News",
        "access": "OPEN_FREE",
        "description": "Preserved corpus of 25+ million academic research papers and broadcast TV news transcripts with closed captions.",
        "typologies": ["person", "company"],
        "url_template": "https://scholar.archive.org/search?q={query}"
    },
    {
        "id": "db-c-06",
        "category": "C",
        "name": "Library of Congress Web Archives",
        "access": "OPEN_FREE",
        "description": "Archived websites of government agencies, public organizations, election candidates, and cultural institutions.",
        "typologies": ["person", "domain", "company"],
        "url_template": "https://www.loc.gov/websites/?q={query}"
    },
    {
        "id": "db-c-07",
        "category": "C",
        "name": "HathiTrust Digital Library",
        "access": "OPEN_FREE",
        "description": "Repository of millions of digitized titles from academic and research institutions worldwide.",
        "typologies": ["person", "company"],
        "url_template": "https://babel.hathitrust.org/cgi/ls?q1={query}&field1=ocr"
    },

    # ==========================================
    # D. BREACH & LEAK INTELLIGENCE (public/lawful)
    # ==========================================
    {
        "id": "db-d-01",
        "category": "D",
        "name": "Have I Been Pwned (HIBP)",
        "access": "FREE_TIER",
        "description": "Gold standard breach repository aggregating billions of compromised accounts across verified breaches.",
        "typologies": ["email", "domain"],
        "url_template": "https://haveibeenpwned.com/account/{query}",
        "api_endpoint": "https://haveibeenpwned.com/api/v3/breachedaccount/{query}"
    },
    {
        "id": "db-d-02",
        "category": "D",
        "name": "Pwned Passwords (k-Anonymity API)",
        "access": "OPEN_FREE",
        "description": "Cryptographic k-anonymity API for checking if a SHA-1 password prefix exists in breach corpus.",
        "typologies": ["hash"],
        "url_template": "https://haveibeenpwned.com/Passwords",
        "api_endpoint": "https://api.pwnedpasswords.com/range/{query}"
    },
    {
        "id": "db-d-03",
        "category": "D",
        "name": "DeHashed Public Search Preview",
        "access": "FREE_PREVIEW",
        "description": "Asset search engine providing free summary count and metadata for breached assets and domains.",
        "typologies": ["email", "username", "domain", "ip"],
        "url_template": "https://dehashed.com/search?query={query}",
        "api_endpoint": "https://api.dehashed.com/search?query={query}"
    },
    {
        "id": "db-d-04",
        "category": "D",
        "name": "LeakCheck.io Public API",
        "access": "FREE_TIER",
        "description": "Breach search service with public API returning breach names and entry dates for target emails.",
        "typologies": ["email", "username"],
        "url_template": "https://leakcheck.io/search?query={query}",
        "api_endpoint": "https://leakcheck.io/api/public?check={query}"
    },
    {
        "id": "db-d-05",
        "category": "D",
        "name": "Intelligence X Public Archive (intelx.io)",
        "access": "FREE_TIER",
        "description": "Search engine and data archive indexing public leaks, paste sites, historical whois, and darknet mirrors.",
        "typologies": ["domain", "email", "ip", "hash"],
        "url_template": "https://intelx.io/?s={query}",
        "api_endpoint": "https://2.intelx.io/phonebook/search"
    },
    {
        "id": "db-d-06",
        "category": "D",
        "name": "BreachDirectory.org",
        "access": "FREE_TIER",
        "description": "Public database of compromised credentials with free API for detecting domain and email compromises.",
        "typologies": ["email", "domain"],
        "url_template": "https://breachdirectory.org/?q={query}",
        "api_endpoint": "https://breachdirectory.p.rapidapi.com/"
    },
    {
        "id": "db-d-07",
        "category": "D",
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "access": "OPEN_FREE",
        "description": "Authoritative federal catalog of vulnerabilities actively exploited in the wild with required remediation dates.",
        "typologies": ["cve", "domain", "company"],
        "url_template": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "api_endpoint": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    },
    {
        "id": "db-d-08",
        "category": "D",
        "name": "HHS OCR Healthcare Breach Portal",
        "access": "OPEN_FREE",
        "description": "U.S. Department of Health and Human Services database disclosing breaches affecting 500+ individuals.",
        "typologies": ["company", "domain"],
        "url_template": "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
    },
    {
        "id": "db-d-09",
        "category": "D",
        "name": "Privacy Rights Clearinghouse Chronology",
        "access": "OPEN_FREE",
        "description": "Curated chronological dataset of corporate and municipal data breaches reported since 2005.",
        "typologies": ["company", "domain"],
        "url_template": "https://privacyrights.org/data-breaches?field_breach_name={query}"
    },
    {
        "id": "db-d-10",
        "category": "D",
        "name": "GitGuardian Public Incident Reports",
        "access": "OPEN_FREE",
        "description": "Annual state of secrets sprawl reports detailing public exposure of API tokens and database keys.",
        "typologies": ["domain", "company"],
        "url_template": "https://www.gitguardian.com/state-of-secrets-sprawl"
    },

    # ==========================================
    # E. IDENTITY & PEOPLE INTELLIGENCE (public)
    # ==========================================
    {
        "id": "db-e-in-01",
        "category": "E",
        "name": "Truecaller India Identity Directory",
        "access": "OPEN_FREE",
        "description": "Real-time reverse phone number lookup for Indian mobile subscribers, telecom circle detection, and caller reputation.",
        "typologies": ["phone", "person"],
        "url_template": "https://www.truecaller.com/search/in/{query}"
    },
    {
        "id": "db-e-in-02",
        "category": "E",
        "name": "DoT Sanchar Saathi & TAFCOP Mobile Connections",
        "access": "OPEN_FREE",
        "description": "Department of Telecommunications (DoT) citizen portal for verifying SIM connections registered across Indian telecom circles.",
        "typologies": ["phone"],
        "url_template": "https://tafcop.sancharsaathi.gov.in/"
    },
    {
        "id": "db-e-in-03",
        "category": "E",
        "name": "TRAI National Numbering Plan & Circle Registry",
        "access": "OPEN_FREE",
        "description": "Telecom Regulatory Authority of India official allocation tables for Mobile Network Operators (Jio, Airtel, Vi, BSNL) and licensed circles.",
        "typologies": ["phone"],
        "url_template": "https://www.trai.gov.in/"
    },
    {
        "id": "db-e-01",
        "category": "E",
        "name": "TruePeopleSearch Public Aggregator",
        "access": "OPEN_FREE",
        "description": "Free U.S. public records aggregator returning historical addresses (10+ years), phone numbers, and associates.",
        "typologies": ["person", "phone", "email"],
        "url_template": "https://www.truepeoplesearch.com/results?name={query}"
    },
    {
        "id": "db-e-02",
        "category": "E",
        "name": "ThatsThem Reverse Engine",
        "access": "OPEN_FREE",
        "description": "Free-tier people search engine supporting IP-to-identity, VIN lookups, phone numbers, and addresses.",
        "typologies": ["person", "phone", "email", "ip"],
        "url_template": "https://thatsthem.com/name/{query}"
    },
    {
        "id": "db-e-03",
        "category": "E",
        "name": "Spokeo Public Records",
        "access": "FREE_PREVIEW",
        "description": "People aggregator cross-referencing public records, 120+ social media networks, and court documents.",
        "typologies": ["person", "phone", "email", "username"],
        "url_template": "https://www.spokeo.com/{query}"
    },
    {
        "id": "db-e-04",
        "category": "E",
        "name": "Ghost LinkedIn Public Google Dorking",
        "access": "OPEN_FREE",
        "description": "Conduct professional network reconnaissance without account login to prevent viewer notifications.",
        "typologies": ["person", "company"],
        "url_template": "https://www.google.com/search?q=site:linkedin.com/in/+\"{query}\""
    },
    {
        "id": "db-e-05",
        "category": "E",
        "name": "Gravatar Avatar & Profile API",
        "access": "OPEN_FREE",
        "description": "Global avatar provider exposing profile metadata, social links, and photos via MD5 email hash.",
        "typologies": ["email"],
        "url_template": "https://en.gravatar.com/{query}",
        "api_endpoint": "https://en.gravatar.com/{query}.json"
    },
    {
        "id": "db-e-06",
        "category": "E",
        "name": "EmailRep.io Reputation API",
        "access": "FREE_TIER",
        "description": "Email address risk scoring evaluating domain age, deliverability, data breaches, and social accounts.",
        "typologies": ["email"],
        "url_template": "https://emailrep.io/{query}",
        "api_endpoint": "https://emailrep.io/{query}"
    },
    {
        "id": "db-e-07",
        "category": "E",
        "name": "Hunter.io Public Pattern Discovery",
        "access": "FREE_TIER",
        "description": "Finds email address syntax patterns (e.g. {first}.{last}@domain.com) for organizations and domains.",
        "typologies": ["domain", "company"],
        "url_template": "https://hunter.io/try/search/{query}",
        "api_endpoint": "https://api.hunter.io/v2/domain-search?domain={query}"
    },
    {
        "id": "db-e-08",
        "category": "E",
        "name": "ORCID Public Researcher Registry",
        "access": "OPEN_FREE",
        "description": "Unique persistent identifier connecting researchers with their contributions across scholarly works.",
        "typologies": ["person"],
        "url_template": "https://orcid.org/orcid-search/search?searchQuery={query}",
        "api_endpoint": "https://pub.orcid.org/v3.0/search/?q={query}"
    },
    {
        "id": "db-e-09",
        "category": "E",
        "name": "Google Patents & USPTO Search",
        "access": "OPEN_FREE",
        "description": "Search across worldwide patents to identify inventors, corporate assignees, and technology disclosures.",
        "typologies": ["person", "company"],
        "url_template": "https://patents.google.com/?q={query}"
    },
    {
        "id": "db-e-10",
        "category": "E",
        "name": "NHTSA Free Vehicle VIN Decoder API",
        "access": "OPEN_FREE",
        "description": "National Highway Traffic Safety Administration official API for decoding 17-character vehicle VINs.",
        "typologies": ["cve", "person"],
        "url_template": "https://vpic.nhtsa.dot.gov/decoder/Decoder?vin={query}",
        "api_endpoint": "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/{query}?format=json"
    },

    # ==========================================
    # F. INFRASTRUCTURE & NETWORK
    # ==========================================
    {
        "id": "db-f-01",
        "category": "F",
        "name": "Shodan Internet Scanner",
        "access": "FREE_TIER",
        "description": "Search engine for internet-connected devices, industrial control systems, webcams, and open server ports.",
        "typologies": ["ip", "domain", "asn"],
        "url_template": "https://www.shodan.io/host/{query}",
        "api_endpoint": "https://api.shodan.io/shodan/host/{query}"
    },
    {
        "id": "db-f-02",
        "category": "F",
        "name": "Censys Search 2.0",
        "access": "FREE_TIER",
        "description": "Continuous scan index of IPv4/IPv6 address space and global TLS certificates.",
        "typologies": ["ip", "domain"],
        "url_template": "https://search.censys.io/hosts/{query}",
        "api_endpoint": "https://search.censys.io/api/v2/hosts/{query}"
    },
    {
        "id": "db-f-03",
        "category": "F",
        "name": "crt.sh Certificate Transparency",
        "access": "OPEN_FREE",
        "description": "Free searchable database of public Certificate Transparency logs exposing all issued SSL/TLS subdomains.",
        "typologies": ["domain"],
        "url_template": "https://crt.sh/?q={query}",
        "api_endpoint": "https://crt.sh/?q={query}&output=json"
    },
    {
        "id": "db-f-04",
        "category": "F",
        "name": "VirusTotal Public API",
        "access": "FREE_TIER",
        "description": "Aggregator of 70+ antivirus engines and domain blacklists for inspecting files, URLs, domains, and IPs.",
        "typologies": ["domain", "ip", "hash", "url"],
        "url_template": "https://www.virustotal.com/gui/domain/{query}",
        "api_endpoint": "https://www.virustotal.com/api/v3/domains/{query}"
    },
    {
        "id": "db-f-05",
        "category": "F",
        "name": "GreyNoise Community API",
        "access": "FREE_TIER",
        "description": "Filters out background internet noise to tell analysts if an IP is an opportunistic scanner or targeted attacker.",
        "typologies": ["ip"],
        "url_template": "https://viz.greynoise.io/ip/{query}",
        "api_endpoint": "https://api.greynoise.io/v3/community/{query}"
    },
    {
        "id": "db-f-06",
        "category": "F",
        "name": "AlienVault OTX (Open Threat Exchange)",
        "access": "FREE_TIER",
        "description": "Crowdsourced computer-aided threat intelligence platform providing pulses, malware hashes, and C2 indicators.",
        "typologies": ["ip", "domain", "hash"],
        "url_template": "https://otx.alienvault.com/indicator/domain/{query}",
        "api_endpoint": "https://otx.alienvault.com/api/v1/indicators/domain/{query}/general"
    },
    {
        "id": "db-f-07",
        "category": "F",
        "name": "BGPStream & bgp.tools",
        "access": "OPEN_FREE",
        "description": "Real-time BGP routing telemetry tracking AS paths, prefix hijacks, route leaks, and upstream transit peers.",
        "typologies": ["asn", "ip"],
        "url_template": "https://bgp.tools/as/{query}"
    },
    {
        "id": "db-f-08",
        "category": "F",
        "name": "Hurricane Electric BGP Toolkit",
        "access": "OPEN_FREE",
        "description": "Autonomous system number directory displaying routing graphs, prefix counts, and peering exchanges.",
        "typologies": ["asn", "ip", "domain"],
        "url_template": "https://bgp.he.net/AS{query}"
    },
    {
        "id": "db-f-09",
        "category": "F",
        "name": "IPinfo.io Geolocation API",
        "access": "FREE_TIER",
        "description": "Comprehensive IP address data provider returning geolocation coordinates, ASN, company org, and carrier.",
        "typologies": ["ip"],
        "url_template": "https://ipinfo.io/{query}",
        "api_endpoint": "https://ipinfo.io/{query}/json"
    },
    {
        "id": "db-f-10",
        "category": "F",
        "name": "SSL Labs Qualys Public Scanner",
        "access": "OPEN_FREE",
        "description": "Deep analysis of the configuration of any SSL web server on the public Internet.",
        "typologies": ["domain"],
        "url_template": "https://www.ssllabs.com/ssltest/analyze.html?d={query}",
        "api_endpoint": "https://api.ssllabs.com/api/v3/analyze?host={query}"
    },

    # ==========================================
    # G. THREAT INTELLIGENCE FEEDS
    # ==========================================
    {
        "id": "db-g-01",
        "category": "G",
        "name": "MITRE ATT&CK Framework Matrix",
        "access": "OPEN_FREE",
        "description": "Globally accessible knowledge base of adversary tactics, techniques, and procedures (TTPs).",
        "typologies": ["cve", "domain", "hash"],
        "url_template": "https://attack.mitre.org/",
        "api_endpoint": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    },
    {
        "id": "db-g-02",
        "category": "G",
        "name": "National Vulnerability Database (NVD)",
        "access": "OPEN_FREE",
        "description": "U.S. government repository of standards-based vulnerability management data using SCAP standards.",
        "typologies": ["cve"],
        "url_template": "https://nvd.nist.gov/vuln/detail/{query}",
        "api_endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query}"
    },
    {
        "id": "db-g-03",
        "category": "G",
        "name": "Exploit-DB Vulnerability Archive",
        "access": "OPEN_FREE",
        "description": "Non-profit project providing the most complete public collection of weaponized exploits and papers.",
        "typologies": ["cve", "domain"],
        "url_template": "https://www.exploit-db.com/search?cve={query}"
    },
    {
        "id": "db-g-04",
        "category": "G",
        "name": "MalwareBazaar & ThreatFox (abuse.ch)",
        "access": "OPEN_FREE",
        "description": "Crowdsourced repository of malware samples and indicators of compromise (IOCs) sharing threat data.",
        "typologies": ["hash", "ip", "domain"],
        "url_template": "https://bazaar.abuse.ch/sample/{query}/",
        "api_endpoint": "https://mb-api.abuse.ch/api/v1/"
    },
    {
        "id": "db-g-05",
        "category": "G",
        "name": "Ransomware.live Leak Tracker",
        "access": "OPEN_FREE",
        "description": "Public monitor scraping ransomware extortion sites on the dark web to track claimed victim organizations.",
        "typologies": ["company", "domain"],
        "url_template": "https://www.ransomware.live/#/search?q={query}",
        "api_endpoint": "https://api.ransomware.live/v2/victims"
    },
    {
        "id": "db-g-06",
        "category": "G",
        "name": "EPSS (Exploit Prediction Scoring System)",
        "access": "OPEN_FREE",
        "description": "Data-driven model estimating the probability that a software vulnerability will be exploited in the wild.",
        "typologies": ["cve"],
        "url_template": "https://www.first.org/epss/",
        "api_endpoint": "https://api.first.org/data/v1/epss?cve={query}"
    },

    # ==========================================
    # H. SOCIAL MEDIA (public)
    # ==========================================
    {
        "id": "db-h-01",
        "category": "H",
        "name": "Nitter Public Twitter/X Mirrors",
        "access": "OPEN_FREE",
        "description": "Open-source privacy front-end for Twitter allowing full-text search without authentication or tracking.",
        "typologies": ["username", "person"],
        "url_template": "https://nitter.net/{query}"
    },
    {
        "id": "db-h-02",
        "category": "H",
        "name": "Reddit Public JSON API",
        "access": "OPEN_FREE",
        "description": "Access public Reddit user comment histories, submission posts, and subreddit communities via native JSON.",
        "typologies": ["username"],
        "url_template": "https://www.reddit.com/user/{query}",
        "api_endpoint": "https://www.reddit.com/user/{query}/about.json"
    },
    {
        "id": "db-h-03",
        "category": "H",
        "name": "Bluesky AT Protocol Public API",
        "access": "OPEN_FREE",
        "description": "Decentralized federated social network exposing public post timelines and profile records over AT Protocol.",
        "typologies": ["username", "domain"],
        "url_template": "https://bsky.app/profile/{query}",
        "api_endpoint": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={query}"
    },
    {
        "id": "db-h-04",
        "category": "H",
        "name": "Mastodon Public Instances Firehose",
        "access": "OPEN_FREE",
        "description": "ActivityPub federated microblogging network queryable across public instance timelines.",
        "typologies": ["username"],
        "url_template": "https://mastodon.social/@{query}",
        "api_endpoint": "https://mastodon.social/api/v1/accounts/lookup?acct={query}"
    },
    {
        "id": "db-h-05",
        "category": "H",
        "name": "YouTube Public Data API v3",
        "access": "FREE_TIER",
        "description": "Public channel metadata, video transcripts, upload dates, and subscriber telemetry.",
        "typologies": ["username", "company"],
        "url_template": "https://www.youtube.com/results?search_query={query}",
        "api_endpoint": "https://www.googleapis.com/youtube/v3/search"
    },

    # ==========================================
    # I. MEDIA & DOCUMENTS
    # ==========================================
    {
        "id": "db-i-01",
        "category": "I",
        "name": "ExifTool Public Metadata Engine",
        "access": "OPEN_FREE",
        "description": "Performs deep extraction of EXIF GPS coordinates, camera sensor serials, and timestamps from uploaded images.",
        "typologies": ["photo", "file"],
        "url_template": "https://exiftool.org/"
    },
    {
        "id": "db-i-02",
        "category": "I",
        "name": "TinEye Reverse Image Search",
        "access": "FREE_TIER",
        "description": "Image search engine using image identification technology to locate identical or modified copies online.",
        "typologies": ["photo"],
        "url_template": "https://tineye.com/search?url={query}"
    },
    {
        "id": "db-i-03",
        "category": "I",
        "name": "PimEyes Reverse Face Search",
        "access": "FREE_PREVIEW",
        "description": "Face recognition search engine helping investigators find pictures containing a given face across the public web.",
        "typologies": ["photo", "person"],
        "url_template": "https://pimeyes.com/en"
    },
    {
        "id": "db-i-04",
        "category": "I",
        "name": "DocumentCloud Public Documents",
        "access": "OPEN_FREE",
        "description": "Index of millions of primary-source documents uploaded by investigative journalists worldwide.",
        "typologies": ["person", "company"],
        "url_template": "https://www.documentcloud.org/search?q={query}"
    },

    # ==========================================
    # J. GEOSPATIAL (GEOINT)
    # ==========================================
    {
        "id": "db-j-01",
        "category": "J",
        "name": "OpenStreetMap Overpass API",
        "access": "OPEN_FREE",
        "description": "Read-only API that serves up custom selected parts of the complete OpenStreetMap geospatial database.",
        "typologies": ["ip", "domain", "person"],
        "url_template": "https://overpass-turbo.eu/?Q={query}",
        "api_endpoint": "https://overpass-api.de/api/interpreter"
    },
    {
        "id": "db-j-02",
        "category": "J",
        "name": "Sentinel Hub & Copernicus EO Browser",
        "access": "FREE_TIER",
        "description": "High-resolution multispectral satellite imagery from Sentinel-2 and Landsat Earth observation satellites.",
        "typologies": ["domain", "company"],
        "url_template": "https://apps.sentinel-hub.com/eo-browser/?zoom=10&lat=37.7&lng=-122.4"
    },
    {
        "id": "db-j-03",
        "category": "J",
        "name": "ADS-B Exchange Military & Civilian Flight Tracking",
        "access": "OPEN_FREE",
        "description": "Unfiltered co-op tracking network showing real-time positions of aircraft via ADS-B broadcasts.",
        "typologies": ["company", "person"],
        "url_template": "https://globe.adsbexchange.com/?icao={query}"
    },
    {
        "id": "db-j-04",
        "category": "J",
        "name": "MarineTraffic Live AIS Vessel Tracking",
        "access": "FREE_TIER",
        "description": "Global ship tracking intelligence reporting vessel locations, port arrivals, IMO numbers, and ownership.",
        "typologies": ["company"],
        "url_template": "https://www.marinetraffic.com/en/ais/details/ships/imo:{query}"
    },
    {
        "id": "db-j-05",
        "category": "J",
        "name": "WiGLE Wireless Network Mapping",
        "access": "OPEN_FREE",
        "description": "Database of wireless networks and cell towers worldwide, allowing BSSID geolocation triangulation.",
        "typologies": ["mac", "ip"],
        "url_template": "https://wigle.net/search?netid={query}",
        "api_endpoint": "https://api.wigle.net/api/v2/network/search"
    },

    # ==========================================
    # K. CODE & REPOSITORIES
    # ==========================================
    {
        "id": "db-k-01",
        "category": "K",
        "name": "GitHub Code Search API",
        "access": "FREE_TIER",
        "description": "Search across hundreds of millions of public code repositories for leaked secrets, configs, and handles.",
        "typologies": ["domain", "username", "email", "hash"],
        "url_template": "https://github.com/search?type=code&q={query}",
        "api_endpoint": "https://api.github.com/search/code?q={query}"
    },
    {
        "id": "db-k-02",
        "category": "K",
        "name": "grep.app Public Code Search",
        "access": "OPEN_FREE",
        "description": "Lightning-fast search across a half-million public git repositories supporting regular expressions.",
        "typologies": ["domain", "hash", "email"],
        "url_template": "https://grep.app/search?q={query}"
    },
    {
        "id": "db-k-03",
        "category": "K",
        "name": "PyPI & npm Public Package Registries",
        "access": "OPEN_FREE",
        "description": "Official open-source package repositories disclosing author emails, repository links, and dependency trees.",
        "typologies": ["username", "domain"],
        "url_template": "https://pypi.org/search/?q={query}",
        "api_endpoint": "https://pypi.org/pypi/{query}/json"
    },
    {
        "id": "db-k-04",
        "category": "K",
        "name": "Docker Hub Public Container Registry",
        "access": "OPEN_FREE",
        "description": "Public container registry exposing published Docker images, layered builds, and maintainer accounts.",
        "typologies": ["username", "domain"],
        "url_template": "https://hub.docker.com/search?q={query}"
    },

    # ==========================================
    # L. DARK WEB (Legal Portion Only)
    # ==========================================
    {
        "id": "db-l-01",
        "category": "L",
        "name": "Ahmia.fi Clearnet Tor Index",
        "access": "OPEN_FREE",
        "description": "Clearnet-accessible search engine indexing public Tor v3 hidden services (.onion) with abusive content filtered out.",
        "typologies": ["domain", "onion", "hash"],
        "url_template": "https://ahmia.fi/search/?q={query}"
    },
    {
        "id": "db-l-02",
        "category": "L",
        "name": "DarkSearch.io Public Index",
        "access": "OPEN_FREE",
        "description": "Public search engine for dark web content indexing text without requiring Tor browser installation.",
        "typologies": ["domain", "onion", "email"],
        "url_template": "https://darksearch.io/search?q={query}"
    },
    {
        "id": "db-l-03",
        "category": "L",
        "name": "Dark.fail Clearnet PGP Directory",
        "access": "OPEN_FREE",
        "description": "Automated status verification tracker monitoring uptime and PGP key signatures of major hidden services.",
        "typologies": ["onion"],
        "url_template": "https://dark.fail/"
    },

    # ==========================================
    # M. FINANCIAL & CORPORATE
    # ==========================================
    {
        "id": "db-m-in-01",
        "category": "M",
        "name": "MCA India (Ministry of Corporate Affairs) Master Data",
        "access": "OPEN_FREE",
        "description": "Official Government of India statutory company master data, Corporate Identification Number (CIN), and director network.",
        "typologies": ["company", "domain", "person"],
        "url_template": "https://www.mca.gov.in/content/mca/global/en/home.html"
    },
    {
        "id": "db-m-in-02",
        "category": "M",
        "name": "Zauba Corp Indian Business Directory",
        "access": "OPEN_FREE",
        "description": "India commercial registry aggregator providing company financials, authorized capital, ROC filings, and director networks.",
        "typologies": ["company", "domain", "person"],
        "url_template": "https://www.zaubacorp.com/companysearchresults/{query}"
    },
    {
        "id": "db-m-in-03",
        "category": "M",
        "name": "GSTIN Taxpayer Search & Verification Portal",
        "access": "OPEN_FREE",
        "description": "Central Board of Indirect Taxes and Customs (CBIC) Goods and Services Tax Network verification for active Indian businesses.",
        "typologies": ["company", "domain"],
        "url_template": "https://services.gst.gov.in/services/searchtp"
    },
    {
        "id": "db-m-01",
        "category": "M",
        "name": "OpenCorporates Global Registry",
        "access": "OPEN_FREE",
        "description": "The largest open database of companies in the world, indexing 220+ million corporate entities and directorships.",
        "typologies": ["company", "domain", "person"],
        "url_template": "https://opencorporates.com/companies?q={query}",
        "api_endpoint": "https://api.opencorporates.com/v0.4/companies/search?q={query}"
    },
    {
        "id": "db-m-02",
        "category": "M",
        "name": "SEC EDGAR Filings & Full-Text (EFTS)",
        "access": "OPEN_FREE",
        "description": "Electronic Data Gathering, Analysis, and Retrieval system maintaining public company financial and officer filings.",
        "typologies": ["company", "domain", "person"],
        "url_template": "https://www.sec.gov/edgar/searchedgar/companysearch?company={query}",
        "api_endpoint": "https://efts.sec.gov/LATEST/search-index?q={query}"
    },
    {
        "id": "db-m-03",
        "category": "M",
        "name": "Companies House UK API",
        "access": "FREE_TIER",
        "description": "Official registrar of companies in the United Kingdom disclosing officers, PSC beneficial owners, and accounts.",
        "typologies": ["company", "person"],
        "url_template": "https://find-and-update.company-information.service.gov.uk/search?q={query}",
        "api_endpoint": "https://api.company-information.service.gov.uk/search/companies?q={query}"
    },
    {
        "id": "db-m-04",
        "category": "M",
        "name": "OpenSanctions Global Watchlists",
        "access": "OPEN_FREE",
        "description": "Aggregated sanctions database combining OFAC SDN, EU, UN, UK, and Interpol Red Notices with PEP profiles.",
        "typologies": ["person", "company", "crypto"],
        "url_template": "https://www.opensanctions.org/search/?q={query}",
        "api_endpoint": "https://api.opensanctions.org/search/default?q={query}&limit=5"
    },
    {
        "id": "db-m-05",
        "category": "M",
        "name": "OFAC Specially Designated Nationals (SDN)",
        "access": "OPEN_FREE",
        "description": "U.S. Treasury Office of Foreign Assets Control official sanctions list of individuals, companies, and crypto addresses.",
        "typologies": ["person", "company", "crypto"],
        "url_template": "https://sanctionssearch.ofac.treas.gov/Details.aspx?id={query}"
    },
    {
        "id": "db-m-06",
        "category": "M",
        "name": "Blockchain.com & Etherscan Explorers",
        "access": "OPEN_FREE",
        "description": "Public ledger explorers for Bitcoin, Ethereum, and multi-chain transaction flows, balances, and smart contracts.",
        "typologies": ["crypto"],
        "url_template": "https://www.blockchain.com/explorer/search?search={query}",
        "api_endpoint": "https://api.etherscan.io/api?module=account&action=balance&address={query}"
    },

    # ==========================================
    # N. GOVERNMENT & PUBLIC RECORDS
    # ==========================================
    {
        "id": "db-n-in-01",
        "category": "N",
        "name": "eCourts Services India (National Judicial Data Grid)",
        "access": "OPEN_FREE",
        "description": "Indian judiciary public portal indexing millions of civil, commercial, and criminal case statuses across High Courts and District Courts.",
        "typologies": ["person", "company"],
        "url_template": "https://services.ecourts.gov.in/"
    },
    {
        "id": "db-n-in-02",
        "category": "N",
        "name": "National Cyber Crime Reporting Portal (I4C India)",
        "access": "OPEN_FREE",
        "description": "Ministry of Home Affairs Indian Cyber Crime Coordination Centre portal and national cyber fraud reporting database (Helpline: 1930).",
        "typologies": ["phone", "email", "domain", "ip", "crypto"],
        "url_template": "https://cybercrime.gov.in/"
    },
    {
        "id": "db-n-01",
        "category": "N",
        "name": "Data.gov Open Federal Catalog",
        "access": "OPEN_FREE",
        "description": "U.S. government open data portal offering 300,000+ public datasets across demographics, agriculture, and commerce.",
        "typologies": ["company", "domain"],
        "url_template": "https://catalog.data.gov/dataset?q={query}"
    },
    {
        "id": "db-n-02",
        "category": "N",
        "name": "CourtListener / RECAP Federal Court Dockets",
        "access": "OPEN_FREE",
        "description": "Free Law Project archive providing millions of federal district, appellate, and bankruptcy court opinions and dockets.",
        "typologies": ["person", "company", "domain"],
        "url_template": "https://www.courtlistener.com/?q={query}",
        "api_endpoint": "https://www.courtlistener.com/api/rest/v3/dockets/?q={query}"
    },
    {
        "id": "db-n-03",
        "category": "N",
        "name": "USPTO & WIPO Intellectual Property",
        "access": "OPEN_FREE",
        "description": "United States Patent and Trademark Office and World Intellectual Property Organization registration databases.",
        "typologies": ["company", "person"],
        "url_template": "https://tmsearch.uspto.gov/search/search-information"
    },
    {
        "id": "db-n-04",
        "category": "N",
        "name": "Federal Election Commission (FEC) Donors",
        "access": "OPEN_FREE",
        "description": "Federal campaign finance records documenting individual political contributors, employers, and amounts.",
        "typologies": ["person", "company"],
        "url_template": "https://www.fec.gov/data/receipts/individual-contributions/?contributor_name={query}",
        "api_endpoint": "https://api.open.fec.gov/v1/schedules/schedule_a/?contributor_name={query}"
    },
    {
        "id": "db-n-05",
        "category": "N",
        "name": "FDA & NHTSA Recall Registries",
        "access": "OPEN_FREE",
        "description": "Official federal recall directories tracking food, pharmaceutical, and motor vehicle safety enforcement actions.",
        "typologies": ["company"],
        "url_template": "https://www.nhtsa.gov/recalls?search={query}",
        "api_endpoint": "https://api.fda.gov/drug/enforcement.json?search={query}"
    },

    # ==========================================
    # O. AI-ENRICHMENT SOURCES
    # ==========================================
    {
        "id": "db-o-01",
        "category": "O",
        "name": "Google Gemini Search Grounding",
        "access": "API_KEY_OPTIONAL",
        "description": "Google Gemini 1.5/2.0 multimodal model with live web grounding via Google Search for real-time verification.",
        "typologies": ["domain", "person", "ip", "hash"],
        "url_template": "https://ai.google.dev/"
    },
    {
        "id": "db-o-02",
        "category": "O",
        "name": "Wikidata SPARQL Knowledge Graph",
        "access": "OPEN_FREE",
        "description": "Collaborative, multilingual, secondary knowledge base collecting structured data for Wikipedia and external entities.",
        "typologies": ["person", "company", "domain"],
        "url_template": "https://www.wikidata.org/wiki/Special:Search?search={query}",
        "api_endpoint": "https://query.wikidata.org/sparql?query={query}&format=json"
    },
    {
        "id": "db-o-03",
        "category": "O",
        "name": "DBpedia Structured Knowledge Base",
        "access": "OPEN_FREE",
        "description": "Structured content extracted from Wikipedia information boxes modeling relationships between entities.",
        "typologies": ["person", "company"],
        "url_template": "https://lookup.dbpedia.org/api/search?query={query}",
        "api_endpoint": "https://lookup.dbpedia.org/api/search?query={query}&format=json"
    },
    {
        "id": "db-o-04",
        "category": "O",
        "name": "ConceptNet Semantic Graph",
        "access": "OPEN_FREE",
        "description": "Freely-available knowledge graph that connects words and phrases of natural language with labeled relationships.",
        "typologies": ["person", "username"],
        "url_template": "https://conceptnet.io/c/en/{query}",
        "api_endpoint": "https://api.conceptnet.io/c/en/{query}"
    }
]


def get_all_categories() -> Dict[str, Any]:
    """Returns metadata for all 15 database categories."""
    cats = []
    for code, meta in DATABASE_CATEGORIES.items():
        dbs_in_cat = [d for d in OSINT_DATABASES if d["category"] == code]
        cats.append({
            "code": code,
            "name": meta["name"],
            "badge": meta["badge"],
            "color": meta["color"],
            "description": meta["description"],
            "database_count": len(dbs_in_cat)
        })
    return {
        "total_categories": len(cats),
        "total_databases": len(OSINT_DATABASES),
        "categories": cats
    }


def get_databases_by_category(category_code: str) -> List[Dict[str, Any]]:
    """Returns all databases in a specific category (A through O)."""
    return [d for d in OSINT_DATABASES if d["category"].upper() == category_code.upper()]


def search_databases(keyword: str) -> List[Dict[str, Any]]:
    """Searches databases across all 15 categories by name, description, or typology."""
    kw = keyword.strip().lower()
    if not kw:
        return OSINT_DATABASES
    results = []
    for d in OSINT_DATABASES:
        name_match = kw in d["name"].lower()
        desc_match = kw in d["description"].lower()
        cat_match = kw == d["category"].lower()
        type_match = any(kw in t.lower() for t in d.get("typologies", []))
        if name_match or desc_match or cat_match or type_match:
            results.append(d)
    return results


def build_database_query_url(database_id: str, target: str) -> Optional[str]:
    """Builds the active target query URL for a given database ID."""
    db = next((d for d in OSINT_DATABASES if d["id"] == database_id), None)
    if not db or not db.get("url_template"):
        return None
    encoded = urllib.parse.quote(target.strip())
    return db["url_template"].replace("{query}", encoded)
