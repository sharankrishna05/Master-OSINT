"""OSINT Tool Routing and Filtering Engine.

Maps classified input types to corresponding knowledge base sections,
applies flag-driven filtering (T, R, D, M), executes URL parameter
substitution, and categorizes tools into:
  - auto_open: Safe web tools (no R, no T)
  - api_hit: Public API endpoints for automated JSON enrichment
  - manual_followups: Local tools [T] with exact CLI syntax
  - skipped: Tools requiring registration [R] or dorks [D]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote_plus

from osint_hub.parse import ToolEntry, query_tools_by_sections, search_tools_by_keyword


# Type -> Section mapping strictly adhering to EMBEDDED KNOWLEDGE BASE (2,466 Tools Catalogue)
TYPE_TO_SECTIONS: Dict[str, List[str]] = {
    "username": [
        "USERNAME",
        "SOCIAL NETWORKS",
        "INSTANT MESSAGING",
        "ONLINE COMMUNITIES",
        "TOOLS",
        "PEOPLE SEARCH ENGINES",
    ],
    "email": [
        "EMAIL ADDRESS",
        "USERNAME",
        "TOOLS",
        "PUBLIC RECORDS",
        "OP SEC",
    ],
    "phone": [
        "TELEPHONE NUMBERS",
        "INSTANT MESSAGING",
        "PEOPLE SEARCH ENGINES",
        "TOOLS",
    ],
    "domain": [
        "DOMAIN NAME",
        "SEARCH ENGINES",
        "CYBER THREAT INTELLIGENCE",
        "ARCHIVES",
    ],
    "ipv4": [
        "IP & MAC ADDRESS",
        "CYBER THREAT INTELLIGENCE",
        "DOMAIN NAME",
    ],
    "ipv6": [
        "IP & MAC ADDRESS",
        "CYBER THREAT INTELLIGENCE",
        "DOMAIN NAME",
    ],
    "mac": [
        "IP & MAC ADDRESS",
        "TOOLS",
    ],
    "url": [
        "DOMAIN NAME",
        "ARCHIVES",
        "DISINFORMATION & MEDIA VERIFICATION",
        "CYBER THREAT INTELLIGENCE",
        "MALICIOUS FILE ANALYSIS",
    ],
    "image_file": [
        "IMAGES / VIDEOS / DOCS",
        "DISINFORMATION & MEDIA VERIFICATION",
        "GEOLOCATION TOOLS / MAPS",
    ],
    "hash": [
        "MALICIOUS FILE ANALYSIS",
        "ENCODING / DECODING",
        "CYBER THREAT INTELLIGENCE",
    ],
    "person_name": [
        "PEOPLE SEARCH ENGINES",
        "PUBLIC RECORDS",
        "SOCIAL NETWORKS",
        "BUSINESS RECORDS",
        "TOOLS",
    ],
    "company": [
        "BUSINESS RECORDS",
        "COMPLIANCE & RISK INTELLIGENCE",
        "PUBLIC RECORDS",
        "SEARCH ENGINES",
    ],
    "crypto_addr": [
        "BLOCKCHAIN & CRYPTOCURRENCY",
        "DARK WEB",
    ],
    "vin": [
        "TRANSPORTATION",
        "PUBLIC RECORDS",
        "TOOLS",
    ],
    "license_plate": [
        "TRANSPORTATION",
        "PUBLIC RECORDS",
    ],
    "flight": [
        "TRANSPORTATION",
    ],
    "unknown": [
        "SEARCH ENGINES",
        "TOOLS",
        "PUBLIC RECORDS",
        "CYBER THREAT INTELLIGENCE",
    ],
}

# Known CLI command syntax templates for [T] tools
CLI_TEMPLATES: Dict[str, str] = {
    "sherlock": "sherlock {target}",
    "whatsmyname": "python whatsmyname.py -u {target}",
    "sylva identity discovery": "sylva {target}",
    "gitfive": "gitfive -u {target}",
    "ghunt": "ghunt email {target}",
    "theharvester": "theHarvester -d {target} -b all",
    "infoga": "python infoga.py --target {target}",
    "holehe": "holehe {target}",
    "reacher github": "check-if-email-exists {target}",
    "disposable email domains": "grep -i '{target}' disposable_email_blocklist.conf",
    "burner email providers": "grep -i '{target}' emails.txt",
    "aquatone": "echo '{target}' | aquatone",
    "recon-ng": "recon-ng -w {target}",
    "xray": "xray -target {target}",
    "dns recon": "dnsrecon -d {target}",
    "gobuster": "gobuster dns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "fierce domain scanner": "fierce --domain {target}",
    "bluto": "bluto -d {target}",
    "owasp maryam": "maryam -e osint/dns_search -d {target}",
    "sublist3r": "sublist3r -d {target}",
    "altdns": "altdns -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt",
    "kraken": "kraken -d {target}",
    "sitediff": "sitediff https://{target}",
    "certgraph": "certgraph -ct-subdomains {target}",
    "dns twist": "dnstwist --registered {target}",
    "urlcrazy": "urlcrazy {target}",
    "catphish": "catphish -d {target}",
    "whatweb": "whatweb {target}",
    "urlwatch": "urlwatch {target}",
    "changedetect": "changedetection.io check {target}",
    "sn1per": "sniper -t {target}",
    "web data exposure scanner": "python scanner.py -u {target}",
    "robotsdisallowed": "curl -s https://{target}/robots.txt",
    "belati": "belati -t {target}",
    "burp suite": "burpsuite --project-file={target}.burp",
    "eyewitness": "eyewitness --single {target}",
    "nmap": "nmap -sV -sC -Pn {target}",
    "scanless": "scanless -t {target} -s shodan",
    "masscan": "masscan {target} -p0-65535 --rate 1000",
    "wireshark": "wireshark -k -i any -f 'host {target}'",
    "networkminer": "NetworkMiner {target}",
    "checkip": "checkip {target}",
    "cloudfail": "python cloudfail.py --target {target}",
    "exiftool": "exiftool '{target}'",
    "foca": "foca -d {target}",
    "geosetter": "geosetter '{target}'",
    "jpegsnoop": "jpegsnoop '{target}'",
    "xeuledoc": "xeuledoc {target}",
    "exiv2": "exiv2 '{target}'",
    "mediainfo": "mediainfo '{target}'",
    "apache tika": "tika -m '{target}'",
    "oletools": "olevba '{target}'",
    "hachoir": "hachoir-metadata '{target}'",
    "ghiro": "ghiro '{target}'",
    "creepy": "creepy",
    "numspy": "numspy {target}",
    "orbit": "python orbit.py -s {target}",
    "x0rz tweets_analyzer": "python tweets_analyzer.py -u {target}",
    "birdwatcher": "birdwatcher -u {target}",
    "tinfoleak.py": "python tinfoleak.py -u {target}",
    "dmi-tcat": "dmi-tcat {target}",
    "twint": "twint -u {target}",
    "linkedint - linkedin recon tool": "python LinkedInt.py -c '{target}'",
    "scrapedin": "scrapedin -u {target}",
    "inspy": "inspy --domain {target}",
    "raven": "raven -d {target}",
    "tiktok-osint": "python tiktok-osint.py -u {target}",
    "unfurl": "unfurl {target}",
    "yt-dlp": "yt-dlp '{target}'",
    "treeverse": "treeverse {target}",
    "threads-scraper": "threads-scraper -u {target}",
    "threadsrecon": "threadsrecon -u {target}",
    "steamosint": "python steamosint.py -u {target}",
    "phoneinfoga": "phoneinfoga scan -n {target}",
    "photon": "python photon.py -u {target}",
    "recondog": "python dog.py",
    "osrframework": "usufy.py -n {target}",
    "apkleaks": "apkleaks -f {target}",
    "apktool": "apktool d {target}",
    "jadx": "jadx-gui {target}",
    "mobsf": "mobsf",
    "autopsy": "autopsy",
    "frida": "frida -U -f {target}",
    "charles proxy": "charles",
    "onionscan": "onionscan {target}",
    "torbot": "torbot -u {target}",
    "onioff": "python onioff.py -f {target}",
    "deepfake-detect": "python detect.py --input '{target}'",
    "cyberchef": "cyberchef '{target}'",
    "ioc parser": "ioc-parser -f '{target}'",
    "iocextract": "iocextract -f '{target}'",
    "ghidra": "ghidraRun",
}


@dataclass
class RoutedTool:
    tool: ToolEntry
    populated_url: str
    action_type: str  # "auto_open", "manual_cli", "skipped"
    cli_command: Optional[str] = None
    skip_reason: Optional[str] = None


@dataclass
class RoutingPlan:
    target: str
    target_type: str
    confidence: float
    sections_queried: List[str]
    auto_open: List[RoutedTool]
    manual_followups: List[RoutedTool]
    skipped: List[RoutedTool]
    api_hits_planned: List[str]
    empty_categories_notice: List[str]


def substitute_url_placeholders(url: str, target: str, target_type: str) -> str:
    """Substitute placeholders in url with normalized target."""
    encoded_target = quote_plus(target)

    # Dictionary of placeholders to replace
    replacements = [
        ("%3Cusername%3E", encoded_target),
        ("<username>", target),
        ("{username}", target),
        ("%3Csearchterm%3E", encoded_target),
        ("<searchterm>", target),
        ("{searchterm}", target),
        ("{query}", encoded_target),
        ("{target}", target),
        ("<target>", target),
        ("[target]", target),
        ("%3Cdomain.com%3E", target),
        ("<domain.com>", target),
        ("{domain.com}", target),
        ("%3Cdomain%3E", target),
        ("<domain>", target),
        ("{domain}", target),
        ("%3Cemail_address%3E", encoded_target),
        ("<email_address>", target),
        ("{email}", target),
        ("%3Cuser_id%3E", encoded_target),
        ("<user_id>", target),
        ("{user_id}", target),
        ("{phone}", target),
        ("{hash}", target),
        ("{ip}", target),
        ("{vin}", target),
        ("ENTER-USERNAME-HERE", encoded_target),
        ("ENTER-TARGET-HERE", encoded_target),
        ("ENTER-IP-HERE", target),
        ("ENTER-DOMAIN-HERE", target),
    ]

    populated = url
    for placeholder, val in replacements:
        if placeholder in populated:
            populated = populated.replace(placeholder, val)

    # Special case: Bing IP Search (ip%3A8.8.8.8)
    if "bing.com/search?q=ip%3A8.8.8.8" in populated and target_type in {"ipv4", "ipv6"}:
        populated = populated.replace("8.8.8.8", target)

    # Special case: FamilyTreeNow (555)555-5555
    if "familytreenow.com" in populated and "(555)555-5555" in populated and target_type == "phone":
        clean_num = re.sub(r"\D", "", target)
        populated = populated.replace("(555)555-5555", clean_num)

    return populated


def get_cli_command(tool_name: str, target: str) -> str:
    """Generate exact copy-paste command for a local [T] tool."""
    key = tool_name.lower().strip()
    # Match exact or substring
    for t_key, tmpl in CLI_TEMPLATES.items():
        if t_key == key or t_key in key or key in t_key:
            return tmpl.format(target=target)

    # Fallback slug command
    slug = re.sub(r"[^a-zA-Z0-9_-]", "-", tool_name.lower()).strip("-")
    return f"{slug} '{target}'"


def route_target(
    target: str,
    target_type: str,
    confidence: float,
    include_dorks: bool = False,
    limit: Optional[int] = None,
    db_path: Optional[Path] = None,
) -> RoutingPlan:
    """Route target to relevant tools according to OSINT selection and filtering rules."""
    sections = TYPE_TO_SECTIONS.get(target_type, [])
    tools = query_tools_by_sections(sections, db_path=db_path)

    # Keyword search enrichment and direct indicator matching across all 2,466 tools
    keyword_tools = search_tools_by_keyword(target, limit=60, db_path=db_path)
    existing_tool_ids = {t.id for t in tools if t.id is not None}
    for kt in keyword_tools:
        if kt.id not in existing_tool_ids:
            tools.insert(0, kt)
            existing_tool_ids.add(kt.id)

    auto_open: List[RoutedTool] = []
    manual_followups: List[RoutedTool] = []
    skipped: List[RoutedTool] = []

    # Map candidate Phase B APIs for this target type
    api_hits_planned: List[str] = []
    if target_type == "username":
        api_hits_planned = ["github_user", "github_events", "keybase_lookup"]
    elif target_type == "email":
        api_hits_planned = ["hibp"]
    elif target_type == "domain":
        api_hits_planned = ["crt_sh"]
    elif target_type in {"ipv4", "ipv6"}:
        api_hits_planned = ["ip_api"]
    elif target_type == "crypto_addr":
        if target.startswith(("1", "3", "bc1")):
            api_hits_planned = ["btc_blockchain"]
        elif target.startswith("0x"):
            # Ethereum needs API key; marked as skipped in plan
            api_hits_planned = ["eth_etherscan (key-required)"]

    # Category tracking to identify categories with no free tools
    category_tool_counts: Dict[str, Dict[str, int]] = {}

    for tool in tools:
        cat_key = f"{tool.section} > {tool.category}"
        if cat_key not in category_tool_counts:
            category_tool_counts[cat_key] = {"free": 0, "total": 0}
        category_tool_counts[cat_key]["total"] += 1

        pop_url = substitute_url_placeholders(tool.url, target, target_type)

        # Rule 1: Local tool [T] -> manual follow-ups
        if "T" in tool.flags:
            cmd = get_cli_command(tool.tool_name, target)
            manual_followups.append(
                RoutedTool(
                    tool=tool,
                    populated_url=pop_url,
                    action_type="manual_cli",
                    cli_command=cmd,
                )
            )
            continue

        # Rule 2: Registration required [R] -> skipped
        if "R" in tool.flags:
            skipped.append(
                RoutedTool(
                    tool=tool,
                    populated_url=pop_url,
                    action_type="skipped",
                    skip_reason="Requires account registration [R]",
                )
            )
            continue

        # Rule 3: Google dork [D] -> skipped unless include_dorks
        if "D" in tool.flags and not include_dorks:
            skipped.append(
                RoutedTool(
                    tool=tool,
                    populated_url=pop_url,
                    action_type="skipped",
                    skip_reason="Google dork query [D] (use --include-dorks to enable)",
                )
            )
            continue

        # Rule 4: Clean free tool (no R, no T) -> safe auto-open
        category_tool_counts[cat_key]["free"] += 1
        auto_open.append(
            RoutedTool(
                tool=tool,
                populated_url=pop_url,
                action_type="auto_open",
            )
        )

    # Detect categories that have zero free tools
    empty_categories_notice: List[str] = []
    for cat_name, stats in category_tool_counts.items():
        if stats["free"] == 0 and stats["total"] > 0:
            empty_categories_notice.append(
                f"Section/Category '{cat_name}' has {stats['total']} tools listed, but none are free non-registration/non-local tools."
            )

    # Apply optional limit to auto_open
    if limit and limit > 0:
        auto_open = auto_open[:limit]

    return RoutingPlan(
        target=target,
        target_type=target_type,
        confidence=confidence,
        sections_queried=sections,
        auto_open=auto_open,
        manual_followups=manual_followups,
        skipped=skipped,
        api_hits_planned=api_hits_planned,
        empty_categories_notice=empty_categories_notice,
    )
