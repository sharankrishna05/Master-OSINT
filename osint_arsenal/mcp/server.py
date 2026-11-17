"""MCP stdio server exposing Arsenal tools to AI assistants."""
from __future__ import annotations
import asyncio
import json

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    MCP_AVAILABLE = True
except Exception:
    MCP_AVAILABLE = False

from ..models import LookupKind
from ..lookup.engine import run_lookup
from ..webcheck.engine import run_webcheck
from ..directory.loader import load_directory, filter_tools
from ..db import DB


def _paginate(items, page, size):
    page = max(1, page); size = max(1, min(200, size))
    start = (page - 1) * size
    return {"page": page, "page_size": size, "total": len(items),
            "items": items[start:start + size]}


def build_server():
    if not MCP_AVAILABLE:
        raise RuntimeError("MCP not installed. `pip install 'osint-arsenal[mcp]'`")

    server = Server("osint-arsenal")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name="lookup", description="Look up a username, email, phone, domain, or IP.",
                 inputSchema={"type": "object", "properties": {
                     "kind": {"type": "string", "enum": [k.value for k in LookupKind]},
                     "query": {"type": "string"},
                     "followups": {"type": "boolean", "default": True},
                     "page": {"type": "integer", "default": 1},
                     "page_size": {"type": "integer", "default": 50}},
                     "required": ["kind", "query"]}),
            Tool(name="webcheck", description="Run website reconnaissance.",
                 inputSchema={"type": "object", "properties": {
                     "url": {"type": "string"},
                     "jobs": {"type": "array", "items": {"type": "string"}},
                     "page": {"type": "integer", "default": 1},
                     "page_size": {"type": "integer", "default": 50}},
                     "required": ["url"]}),
            Tool(name="directory_search", description="Search the curated OSINT directory.",
                 inputSchema={"type": "object", "properties": {
                     "q": {"type": "string"},
                     "category": {"type": "string"},
                     "platform": {"type": "string"},
                     "free": {"type": "boolean"},
                     "open_source": {"type": "boolean"},
                     "page": {"type": "integer", "default": 1},
                     "page_size": {"type": "integer", "default": 50}}}),
            Tool(name="get_investigation", description="Fetch a saved investigation by ID.",
                 inputSchema={"type": "object", "properties": {
                     "investigation_id": {"type": "string"},
                     "page": {"type": "integer", "default": 1},
                     "page_size": {"type": "integer", "default": 50}},
                     "required": ["investigation_id"]}),
            Tool(name="list_investigations", description="List recent investigations.",
                 inputSchema={"type": "object", "properties": {
                     "kind": {"type": "string"}, "limit": {"type": "integer", "default": 20}}}),
            Tool(name="cti_investigate", description="Run enterprise Cyber Threat Intelligence briefing on any target.",
                 inputSchema={"type": "object", "properties": {
                     "target": {"type": "string", "description": "Domain, IP, Hash, Email, Username, or Crypto wallet"}},
                     "required": ["target"]}),
            Tool(name="typosquat_check", description="Detect phishing lookalikes and homoglyph attacks for a domain.",
                 inputSchema={"type": "object", "properties": {
                     "domain": {"type": "string"}},
                     "required": ["domain"]}),
            Tool(name="breach_radar", description="Audit known data breach exposure for an email or domain.",
                 inputSchema={"type": "object", "properties": {
                     "target": {"type": "string"}},
                     "required": ["target"]}),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            if name == "lookup":
                inv = await run_lookup(
                    LookupKind(arguments["kind"]),
                    arguments["query"],
                    api_key="mcp",
                    followups=arguments.get("followups", True),
                )
                data = {
                    "id": inv.id, "query": inv.query, "kind": inv.subkind,
                    "verdict": inv.verdict.model_dump(mode="json") if inv.verdict else None,
                    "results": _paginate(
                        [r.model_dump(mode="json") for r in inv.results],
                        arguments.get("page", 1), arguments.get("page_size", 50)),
                }
            elif name == "webcheck":
                inv = await run_webcheck(arguments["url"], api_key="mcp",
                                         jobs=arguments.get("jobs"))
                data = {
                    "id": inv.id, "url": inv.query, "summary": inv.summary,
                    "results": _paginate(
                        [r.model_dump(mode="json") for r in inv.results],
                        arguments.get("page", 1), arguments.get("page_size", 50)),
                }
            elif name == "directory_search":
                ds = load_directory()
                tools = filter_tools(
                    ds.tools,
                    q=arguments.get("q"),
                    category=arguments.get("category"),
                    platform=arguments.get("platform"),
                    free=arguments.get("free"),
                    open_source=arguments.get("open_source"),
                )
                data = _paginate([t.model_dump(mode="json") for t in tools],
                                 arguments.get("page", 1),
                                 arguments.get("page_size", 50))
            elif name == "get_investigation":
                data = DB().get_investigation(arguments["investigation_id"]) \
                       or {"error": "not found"}
            elif name == "list_investigations":
                data = DB().list_investigations(
                    kind=arguments.get("kind"),
                    limit=arguments.get("limit", 20),
                )
            elif name == "cti_investigate":
                from ..providers.registry import ProviderRegistry
                from ..cti.ai_pipeline import AIPipeline
                reg = ProviderRegistry()
                pipe = AIPipeline()
                target = arguments["target"]
                raw_t, detected_type, norm_t = reg.detect_input_type(target)
                col_res = await reg.execute_all(norm_t, detected_type)
                data = await pipe.correlate_and_synthesize(
                    norm_t,
                    [{"threat_indicators": [f"{k}: {v['status']}"]} for k, v in col_res["provider_statuses"].items()],
                    structured_results=col_res["structured_results"],
                    provider_statuses=col_res["provider_statuses"]
                )
            elif name == "typosquat_check":
                from ..api.routes import analyze_typosquatting
                data = await analyze_typosquatting(arguments["domain"])
            elif name == "breach_radar":
                from ..api.routes import audit_breaches
                data = await audit_breaches(arguments["target"])
            else:
                data = {"error": f"unknown tool {name}"}
        except Exception as e:
            data = {"error": str(e)}
        return [TextContent(type="text",
                            text=json.dumps(data, indent=2, default=str))]

    return server


async def serve_stdio():
    server = build_server()
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())
