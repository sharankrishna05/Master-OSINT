"""OSINT Catalogue Parser and SQLite Persistence Engine."""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("osint_hub.parse")

# Standard paths (self-contained inside osint_arsenal)
HUB_PKG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HUB_PKG_DIR.parent
DEFAULT_DATA_DIR = Path(os.getenv("ARSENAL_DATA_DIR", str(PROJECT_ROOT / "data")))
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "osint.db"
DEFAULT_CATALOG_PATH = HUB_PKG_DIR / "data" / "raw_catalog.txt"


@dataclass
class ToolEntry:
    id: Optional[int]
    section: str
    category: str
    subcategory: str
    tool_name: str
    flags: List[str]
    url: str
    is_unverified: bool
    description: str = ""

    def flags_str(self) -> str:
        return ",".join(self.flags)

    @property
    def display_name(self) -> str:
        marker = " ⚠" if self.is_unverified else ""
        flags_tag = f" [{'/'.join(self.flags)}]" if self.flags else ""
        return f"{self.tool_name}{flags_tag}{marker}"


def parse_flags(text: str) -> Tuple[str, List[str]]:
    """Extract [T/R/D/M] flags from tool text and return clean name + flag list."""
    flags: List[str] = []
    flag_match = re.search(r"\[([TRDM/]+)\]", text)
    if flag_match:
        raw_flags = flag_match.group(1).split("/")
        flags = [f.strip().upper() for f in raw_flags if f.strip().upper() in {"T", "R", "D", "M"}]
        # Strip out the flag bracket from the tool name
        text = re.sub(r"\[[TRDM/]+\]", "", text).strip()
    return text, flags


def parse_line(line: str, current_section: str) -> Optional[ToolEntry]:
    """Parse a single catalogue line into a ToolEntry.
    
    Handles:
      "<Category> — <Subcategory> — <Tool> [flags] — <URL>"
      "<Category> — <Tool> [flags] — <URL>"
      Dash variants (—, –, -)
      (unverified) tags
    """
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    is_unverified = "(unverified)" in clean_line
    clean_line = clean_line.replace("(unverified)", "").strip()

    # Normalise dashes surrounded by whitespace
    parts = [p.strip() for p in re.split(r"\s+[—–-]\s+", clean_line) if p.strip()]

    if len(parts) < 2:
        logger.warning("Malformed line (not enough dash-separated components): %s", line)
        return None

    url = parts[-1]
    # Basic URL sanity check
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
        # If the last item doesn't look like a URL, this line is malformed
        logger.warning("Malformed line (missing valid URL in last component): %s", line)
        return None

    if len(parts) == 2:
        # Category/Subcategory combined, and URL
        cat_str = parts[0]
        tool_raw = cat_str
        category = current_section
        subcategory = ""
    elif len(parts) == 3:
        cat_str = parts[0]
        tool_raw = parts[1]
    elif len(parts) >= 4:
        # E.g. Category — Subcategory — Tool Name — URL
        cat_str = parts[0]
        # Intermediate parts form subcategory and tool name
        subcategory_candidate = parts[1]
        tool_raw = " - ".join(parts[2:-1])
        cat_str = f"{cat_str} > {subcategory_candidate}"
    else:
        logger.warning("Unexpected component split on line: %s", line)
        return None

    # Handle Category > Subcategory if present in cat_str
    if ">" in cat_str:
        cat_parts = [c.strip() for c in cat_str.split(">")]
        category = cat_parts[0]
        subcategory = " > ".join(cat_parts[1:])
    else:
        category = cat_str
        subcategory = ""

    # Parse flags from tool_raw
    clean_tool_name, flags = parse_flags(tool_raw)
    clean_tool_name = clean_tool_name.strip()
    if not clean_tool_name:
        clean_tool_name = category

    return ToolEntry(
        id=None,
        section=current_section,
        category=category,
        subcategory=subcategory,
        tool_name=clean_tool_name,
        flags=flags,
        url=url,
        is_unverified=is_unverified,
    )


def parse_catalog_text(text: str) -> List[ToolEntry]:
    """Parse full catalogue text and return list of valid ToolEntry records."""
    entries: List[ToolEntry] = []
    current_section = "GENERAL"

    for line_idx, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("#"):
            # Update current section header (strip '#', leading/trailing whitespace)
            section_name = line.lstrip("#").strip()
            if section_name:
                current_section = section_name
            continue

        try:
            entry = parse_line(line, current_section)
            if entry:
                entries.append(entry)
        except Exception as e:
            logger.warning("Error parsing line %d: %s (Error: %s)", line_idx, raw_line, e)

    return entries


def init_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create the SQLite database and tables if not existing."""
    path = db_path or DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass

    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                section TEXT NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT,
                tool_name TEXT NOT NULL,
                flags TEXT NOT NULL,
                url TEXT NOT NULL,
                is_unverified INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Ensure description column exists on legacy DBs
        cols = {row[1] for row in conn.execute("PRAGMA table_info(tools)").fetchall()}
        if "description" not in cols:
            conn.execute("ALTER TABLE tools ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tools_section ON tools(section)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tools_flags ON tools(flags)")

        # Create cache table for API rate-limiting and persistence
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                url TEXT PRIMARY KEY,
                params TEXT,
                body TEXT,
                ts REAL NOT NULL
            )
            """
        )

    # Auto-seed from bundled catalog if fresh DB is empty
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM tools")
    if cur.fetchone()[0] == 0 and DEFAULT_CATALOG_PATH.exists():
        text = DEFAULT_CATALOG_PATH.read_text(encoding="utf-8")
        entries = parse_catalog_text(text)
        with conn:
            for e in entries:
                conn.execute(
                    """
                    INSERT INTO tools (section, category, subcategory, tool_name, flags, url, is_unverified, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        e.section,
                        e.category,
                        e.subcategory,
                        e.tool_name,
                        e.flags_str(),
                        e.url,
                        1 if e.is_unverified else 0,
                        e.description or "",
                    ),
                )
        logger.info("Auto-seeded osint_hub database with %d tools.", len(entries))
    return conn


def seed_db(
    db_path: Optional[Path] = None, catalog_path: Optional[Path] = None, force: bool = False
) -> int:
    """Read catalog file, parse all entries, and populate SQLite tools table."""
    conn = init_db(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM tools")
    count = cur.fetchone()[0]

    if count > 0 and not force:
        logger.debug("Database already seeded with %d tools.", count)
        conn.close()
        return count

    cat_file = catalog_path or DEFAULT_CATALOG_PATH
    if not cat_file.exists():
        raise FileNotFoundError(f"Catalogue file not found at {cat_file}")

    with open(cat_file, "r", encoding="utf-8") as f:
        text = f.read()

    entries = parse_catalog_text(text)

    with conn:
        if force:
            conn.execute("DELETE FROM tools")
        for e in entries:
            conn.execute(
                """
                INSERT INTO tools (section, category, subcategory, tool_name, flags, url, is_unverified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e.section,
                    e.category,
                    e.subcategory,
                    e.tool_name,
                    e.flags_str(),
                    e.url,
                    1 if e.is_unverified else 0,
                ),
            )

    cur.execute("SELECT COUNT(*) FROM tools")
    total = cur.fetchone()[0]
    conn.close()
    logger.info("Successfully seeded database with %d tools.", total)
    return total


def get_db_stats(db_path: Optional[Path] = None) -> Dict[str, object]:
    """Return summary statistics of tools database."""
    conn = init_db(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM tools")
    total_tools = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT section) FROM tools")
    total_sections = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM tools WHERE is_unverified = 1")
    unverified_count = cur.fetchone()[0]

    cur.execute("SELECT section, COUNT(*) as cnt FROM tools GROUP BY section ORDER BY cnt DESC")
    section_breakdown = {row["section"]: row["cnt"] for row in cur.fetchall()}

    # Flags breakdown
    cur.execute("SELECT flags FROM tools")
    flag_counts = {"T": 0, "R": 0, "D": 0, "M": 0, "FREE": 0}
    for row in cur.fetchall():
        flags_str = row["flags"]
        if not flags_str:
            flag_counts["FREE"] += 1
        else:
            for f in flags_str.split(","):
                if f in flag_counts:
                    flag_counts[f] += 1

    conn.close()
    return {
        "total_tools": total_tools,
        "total_sections": total_sections,
        "unverified_count": unverified_count,
        "flags_breakdown": flag_counts,
        "sections": section_breakdown,
    }


def query_tools_by_sections(
    sections: List[str], db_path: Optional[Path] = None
) -> List[ToolEntry]:
    """Retrieve all tools belonging to given section names."""
    if not sections:
        return []

    conn = init_db(db_path)
    cur = conn.cursor()
    placeholders = ",".join("?" for _ in sections)
    query = f"""
        SELECT id, section, category, subcategory, tool_name, flags, url, is_unverified, COALESCE(description, '') as description
        FROM tools
        WHERE UPPER(section) IN ({placeholders})
        ORDER BY section, category, tool_name
    """
    cur.execute(query, [s.upper() for s in sections])

    results: List[ToolEntry] = []
    for row in cur.fetchall():
        flags = [f.strip() for f in row["flags"].split(",") if f.strip()]
        desc = row["description"] if "description" in row.keys() else ""
        results.append(
            ToolEntry(
                id=row["id"],
                section=row["section"],
                category=row["category"],
                subcategory=row["subcategory"] or "",
                tool_name=row["tool_name"],
                flags=flags,
                url=row["url"],
                is_unverified=bool(row["is_unverified"]),
                description=desc or "",
            )
        )

    conn.close()
    return results


def search_tools_by_keyword(
    keyword: str, limit: int = 100, db_path: Optional[Path] = None
) -> List[ToolEntry]:
    """Search tools by keyword matching tool_name, category, subcategory, or description with tokenization."""
    clean = keyword.strip()
    if not clean:
        return []

    conn = init_db(db_path)
    cur = conn.cursor()

    # Split into meaningful search tokens
    stop_words = {"the", "and", "for", "with", "from", "tools", "tool", "find", "search", "show", "what", "which", "are"}
    raw_tokens = [w.lower() for w in re.findall(r"[a-zA-Z0-9_\-\.]+", clean) if w.lower() not in stop_words and len(w) >= 3]
    
    expanded_tokens = set(raw_tokens)
    for w in raw_tokens:
        if w.endswith("ies"):
            expanded_tokens.add(w[:-3] + "y")
        elif w.endswith("es"):
            expanded_tokens.add(w[:-2])
        elif w.endswith("s") and not w.endswith("ss"):
            expanded_tokens.add(w[:-1])

    phrase_pattern = f"%{clean}%"
    where_clauses = ["(tool_name LIKE ? OR category LIKE ? OR subcategory LIKE ? OR section LIKE ? OR description LIKE ?)"]
    params: List[Any] = [phrase_pattern, phrase_pattern, phrase_pattern, phrase_pattern, phrase_pattern]

    for t in expanded_tokens:
        t_pat = f"%{t}%"
        where_clauses.append("(tool_name LIKE ? OR category LIKE ? OR subcategory LIKE ? OR section LIKE ? OR description LIKE ?)")
        params.extend([t_pat, t_pat, t_pat, t_pat, t_pat])

    full_where = " OR ".join(where_clauses)
    query = f"""
        SELECT id, section, category, subcategory, tool_name, flags, url, is_unverified, COALESCE(description, '') as description
        FROM tools
        WHERE {full_where}
        ORDER BY
            CASE
                WHEN tool_name LIKE ? THEN 1
                WHEN category LIKE ? THEN 2
                WHEN description LIKE ? THEN 3
                ELSE 4
            END,
            tool_name ASC
        LIMIT ?
    """
    params.extend([phrase_pattern, phrase_pattern, phrase_pattern, limit])
    cur.execute(query, params)

    results: List[ToolEntry] = []
    for row in cur.fetchall():
        flags = [f.strip() for f in row["flags"].split(",") if f.strip()]
        desc = row["description"] if "description" in row.keys() else ""
        results.append(
            ToolEntry(
                id=row["id"],
                section=row["section"],
                category=row["category"],
                subcategory=row["subcategory"] or "",
                tool_name=row["tool_name"],
                flags=flags,
                url=row["url"],
                is_unverified=bool(row["is_unverified"]),
                description=desc or "",
            )
        )

    conn.close()
    return results
