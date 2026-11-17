"""
DorkForge — Automated Multi-Engine Google Dorking & OSINT Reconnaissance Framework.
"""
__version__ = "1.0.0"

from .generator.engine import DorkGenerator
from .generator.templates import template_registry
from .engines import EngineDispatcher
from .models import DorkQuery, SearchResult, RunSummary, DorkTemplate
from .reporters import export_all, export_json, export_csv, export_markdown, export_html, export_sqlite
