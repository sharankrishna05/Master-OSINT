from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

from ..models import Tool, Category, Platform
from ..config import settings


HERE = Path(__file__).parent / "data"


@dataclass
class DirectoryData:
    tools: list[Tool]
    categories: list[Category]
    platforms: list[Platform]


def load_directory() -> DirectoryData:
    tools = [Tool(**t) for t in json.loads((HERE / "tools.json").read_text(encoding="utf-8"))]
    cats = [Category(**c) for c in json.loads((HERE / "categories.json").read_text(encoding="utf-8"))]
    plats = [Platform(**p) for p in json.loads((HERE / "platforms.json").read_text(encoding="utf-8"))]
    return DirectoryData(tools=tools, categories=cats, platforms=plats)


def filter_tools(
    tools: list[Tool], *,
    q: str | None = None,
    category: str | None = None,
    platform: str | None = None,
    free: bool | None = None,
    open_source: bool | None = None,
) -> list[Tool]:
    q = (q or "").lower().strip()
    out = []
    for t in tools:
        if q:
            hay = (t.name + " " + t.description + " " + " ".join(t.tags) + " " + t.category).lower()
            if q not in hay:
                continue
        if category and t.category != category:
            continue
        if platform and platform not in t.platforms:
            continue
        if free is not None and t.free != free:
            continue
        if open_source is not None and t.open_source != open_source:
            continue
        out.append(t)
    return out
