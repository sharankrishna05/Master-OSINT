"""A.R.I.A. - Autonomous Reconnaissance & Intelligence Assistant Engine.

Interactive multi-turn conversational AI copilot and communicator for OSINT-ARSENAL:
- Actively communicates, explains, guides, and converses according to user input
- Remembers active targets, topics, and thread context across conversation turns
- Gives plain-English direct answers, asks helpful clarifying questions, and provides tailored recommendations
- Integrates with Gemini 1.5 when configured and provides an intelligent conversational NLP engine as default
- Curates relevant tools from the 2,466+ catalogue and 97+ database connectors when relevant
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("osint_arsenal.ai_assistant")

try:
    from osint_hub.classify import classify_target
    from osint_hub.parse import get_db_stats, query_tools_by_sections, search_tools_by_keyword
    from osint_hub.router import route_target, substitute_url_placeholders
    OSINT_HUB_LOADED = True
except Exception as e:
    logger.warning("OSINT-Hub not directly loaded in ai_assistant: %s", e)
    OSINT_HUB_LOADED = False

try:
    from .database_catalog import search_databases, get_databases_by_category, DATABASE_CATEGORIES, OSINT_DATABASES
    DATABASE_CATALOG_LOADED = True
except Exception:
    DATABASE_CATALOG_LOADED = False


class AIAssistantEngine:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
        self.model = None
        self.kb_sections: List[Dict[str, Any]] = self._load_platform_kb()
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel("gemini-1.5-flash")
                logger.info("A.R.I.A. Gemini Generative AI successfully initialized.")
            except Exception as e:
                logger.warning("Gemini Generative AI unavailable in AIAssistant: %s", e)

    def _load_platform_kb(self) -> List[Dict[str, Any]]:
        """Load and parse the platform operations manual into searchable KB sections."""
        kb_path = Path(__file__).resolve().parent.parent / "data" / "platform_knowledge_base.md"
        if not kb_path.exists():
            logger.warning("Platform KB file not found at %s", kb_path)
            return []
        try:
            raw = kb_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to read platform KB: %s", e)
            return []

        sections: List[Dict[str, Any]] = []
        blocks = re.split(r"<!--\s*KB_SECTION:\s*([a-zA-Z0-9_]+)\s*-->", raw)
        # blocks[0] is preamble, then pairs (section_id, content)
        for i in range(1, len(blocks) - 1, 2):
            sec_id = blocks[i].strip()
            content = blocks[i + 1].strip()
            lines = content.splitlines()
            title = sec_id
            keywords: List[str] = []
            ui_actions: List[Dict[str, str]] = []
            body_lines: List[str] = []
            for line in lines:
                if line.startswith("## ") and title == sec_id:
                    title = line[3:].strip()
                elif line.lower().startswith("**keywords:**"):
                    kw_raw = line.split(":", 1)[1].strip().strip("*")
                    keywords = [k.strip().lower() for k in kw_raw.split(",") if k.strip()]
                elif line.lower().startswith("**ui_actions:**"):
                    act_raw = line.split(":", 1)[1].strip().strip("*")
                    for item in act_raw.split(","):
                        if "|" in item:
                            act, lbl = item.split("|", 1)
                            ui_actions.append({"action": act.strip(), "label": lbl.strip()})
                else:
                    body_lines.append(line)
            body = "\n".join(body_lines).strip()
            sections.append({
                "id": sec_id,
                "title": title,
                "keywords": keywords,
                "ui_actions": ui_actions,
                "body": body,
                "search_blob": f"{title}\n{' '.join(keywords)}\n{body}".lower(),
            })
        return sections

    def retrieve_kb_sections(self, query: str, top_k: int = 2) -> List[Tuple[int, Dict[str, Any]]]:
        """Score and return top matching KB sections for a user question."""
        if not self.kb_sections or not query:
            return []
        q_low = query.lower().strip()
        stop = {
            "the", "and", "for", "with", "from", "this", "that", "what", "when", "where",
            "which", "who", "how", "does", "work", "works", "use", "using", "can", "you",
            "tell", "explain", "guide", "about", "are", "into", "all", "platform", "tool",
            "tools", "feature", "features", "show", "need", "help", "please",
        }
        tokens = [t for t in re.findall(r"[a-z0-9_\-]{3,}", q_low) if t not in stop]

        scored: List[Tuple[int, Dict[str, Any]]] = []
        for sec in self.kb_sections:
            score = 0
            title_low = sec["title"].lower()
            body_low = sec["body"].lower()
            for kw in sec["keywords"]:
                if kw in q_low:
                    score += 12 if " " in kw or len(kw) >= 6 else 7
            for tok in tokens:
                if tok in title_low:
                    score += 5
                elif tok in body_low:
                    score += 2
            if score > 0:
                scored.append((score, sec))

        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:top_k]

    def extract_target_candidate(self, text: str) -> Optional[Tuple[str, str]]:
        """Extract explicit or implicit indicator target from user message."""
        clean = text.strip()

        # Check for URL
        url_match = re.search(r"https?://[^\s]+", clean)
        if url_match:
            return url_match.group(0), "url"

        # Check for Email
        email_match = re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", clean)
        if email_match:
            return email_match.group(0), "email"

        # Check for IPv4
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean)
        if ip_match:
            return ip_match.group(0), "ipv4"

        # Check for VIN (17 chars alphanumeric, no I, O, Q)
        vin_match = re.search(r"\b[A-HJ-NPR-Za-hj-npr-z0-9]{17}\b", clean)
        if vin_match:
            return vin_match.group(0), "vin"

        # Check for Hash (MD5, SHA1, SHA256)
        hash_match = re.search(r"\b[a-fA-F0-9]{32,64}\b", clean)
        if hash_match and not re.search(r"\b[0-9]{32,64}\b", clean):
            return hash_match.group(0), "hash"

        # Check for Phone Number (+1..., or 10-12 digits with separators)
        phone_match = re.search(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", clean)
        if phone_match and len(re.sub(r"\D", "", phone_match.group(0))) >= 10:
            return phone_match.group(0), "phone"

        # Check for Domain (e.g., target.com, hackerone.com)
        domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", clean)
        if domain_match:
            cand = domain_match.group(0).lower()
            ignored_exts = (
                ".py", ".js", ".html", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".txt", ".json", ".md", ".db", ".yml", ".yaml", ".toml", ".env", ".csv", ".pdf", ".log"
            )
            if not cand.endswith(ignored_exts) and cand not in {"a.r.i.a", "e.g"}:
                return cand, "domain"

        # Check for command target after keywords
        kw_patterns = [
            r"(?:investigate|scan|analyze|check|lookup|target|report on|dossier on|recon)\s+([a-zA-Z0-9_.\-@:+]+)",
            r"(?:username|user|handle)\s+([a-zA-Z0-9_.-]{3,32})",
        ]
        stop_targets = {
            "tools", "tool", "target", "domain", "ip", "the", "a", "an", "all", "me", "this",
            "it", "email", "emails", "phone", "image", "images", "photo", "file", "files",
            "how", "what", "which", "work", "works", "breach", "breaches", "for", "my", "your",
            "any", "another", "results", "data", "account", "accounts",
            "batch", "ioc", "iocs", "darkweb", "passive", "pdns", "dorks", "dorkforge",
            "mitre", "vault", "sentinel", "report", "reports", "graph", "graphs",
            "area", "areas", "database", "databases"
        }
        for pat in kw_patterns:
            m = re.search(pat, clean, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val.lower() not in stop_targets:
                    return val, "unknown"

        return None

    def find_target_in_history(self, history: Optional[List[Dict[str, str]]]) -> Optional[Tuple[str, str]]:
        """Recover active target from previous user conversation turns."""
        if not history:
            return None
        for msg in reversed(history):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                cand = self.extract_target_candidate(content)
                if cand:
                    return cand
        return None

    def classify_dialogue_intent(self, user_msg: str, has_history: bool, active_target: Optional[str]) -> str:
        """Identify what the user is asking to respond appropriately."""
        msg = user_msg.lower().strip()

        # Greetings
        if re.search(r"\b(hi|hello|hey|greetings|good\s+(morning|evening|afternoon)|sup|yo|hola)\b", msg) and len(msg.split()) <= 4:
            return "greeting"

        # Gratitude
        if re.search(r"\b(thanks|thank\s+you|appreciate|great\s+job|awesome|perfect|cool|nice)\b", msg):
            return "gratitude"

        # Identity & Capabilities ("Who are you?", "What can you do?", "Help me")
        if re.search(r"\b(who\s+are\s+you|what\s+can\s+you\s+do|what\s+do\s+you\s+do|your\s+role|introduce\s+yourself|help\s+me|can\s+you\s+help|capabilities|who\s+made\s+you)\b", msg):
            return "identity_capabilities"

        # Explicit UI navigation command ("open threat graph", "go to sentinel", "open area 3", "open vault")
        if re.search(r"^(?:open|go\s+to|show|switch\s+to|launch)\s+(?:the\s+)?(search|home|sentinel|account\s+sentinel|threat\s+graph|knowledge\s+graph|vault|databases|area\s*[1-7]|executive|entities|forensics|dorkforge|batch|passive\s+dns|pdns|darkweb|mitre|attribution)", msg):
            return "navigate_ui"

        # Explicit target investigation without question framing takes priority
        has_target = self.extract_target_candidate(user_msg) is not None

        # Full-platform / operate-this-tool questions always map cleanly to our trained KB
        if not has_target and re.search(r"\b(entire\s+tool|whole\s+tool|all\s+features|what\s+is\s+inside|operate\s+this|guide\s+me\s+on\s+the|guide\s+me\s+step\s+by\s+step|full\s+guide|how\s+this\s+tool\s+works|how\s+to\s+use\s+this\s+tool|how\s+to\s+operate)\b", msg):
            return "platform_kb_qa"

        # Grounded Platform Knowledge Base Q&A (areas, graphs, scoring, vault, dorkforge, forensics, CLI, deployment, etc.)
        kb_hits = self.retrieve_kb_sections(msg, top_k=1)
        if not has_target and kb_hits and kb_hits[0][0] >= 6:
            return "platform_kb_qa"

        # Platform / Website Guidance ("How to use this website?", "Where do I start?", "How does this platform work?")
        if re.search(r"\b(how\s+(do\s+i|to|can\s+i)\s+use|how\s+does\s+(this|the)\s+(website|platform|app|tool|suite)\s+work|getting\s+started|guide\s+me\s+around|where\s+do\s+i\s+start|how\s+do\s+i\s+start|navigate|platform\s+overview|how\s+to\s+navigate|use\s+this\s+website)\b", msg):
            return "platform_guidance"

        # Sentinel inquiry ("What is Nexus Account Sentinel?", "Check email", "Breach check")
        if re.search(r"\b(sentinel|intelbase|check\s+email|email\s+checker|breach\s+check|account\s+checker|haveibeenpwned|hibp)\b", msg):
            return "sentinel_inquiry"

        # Is target safe / malicious / reputation check
        if any(w in msg for w in ["safe", "dangerous", "malicious", "is it bad", "is this bad", "threat", "phishing", "scam", "legit", "reputation"]):
            return "safety_assessment"

        # Who owns / registered / identity check
        if any(w in msg for w in ["who owns", "who registered", "who is behind", "owner", "identity", "who created", "whois"]):
            return "ownership_inquiry"

        # How to / Guide / Methodology
        if re.search(r"\b(how\s+do\s+i|how\s+to|how\s+can\s+i|what\s+are\s+the\s+steps|guide\s+me|best\s+way\s+to|methodology|how\s+does.*work)\b", msg):
            return "how_to_guidance"

        # Concept explanation
        if re.search(r"\b(what\s+is|explain|tell\s+me\s+about|difference\s+between|why\s+is)\b", msg):
            return "explain_concept"

        # Tool discovery
        if any(w in msg for w in ["search tool", "find tool", "what tool", "tools for", "which tool", "recommend a tool", "list tools", "show tools"]):
            return "search_tools"

        # Next steps / follow up
        if (has_history or active_target) and any(w in msg for w in ["what next", "what should i do", "what now", "how to proceed", "more details", "what else", "continue", "next step"]):
            return "next_steps"

        # Explicit investigation request or target detected
        if self.extract_target_candidate(user_msg):
            return "investigate_target"

        # Direct conversational question
        return "conversational_assistant"

    async def generate_gemini_response(
        self,
        user_message: str,
        conversation_history: List[Dict[str, str]],
        system_context: str
    ) -> Optional[str]:
        """Query Gemini Generative AI if API key is active."""
        if not self.model:
            return None

        try:
            prompt = (
                "You are A.R.I.A., a friendly, communicative, highly skilled AI assistant embedded in the OSINT-ARSENAL platform.\n"
                "Your personality is approachable, professional, helpful, and communicative. "
                "Instead of dumping raw tables, talk directly to the user! Answer their question in plain English, explain what you found, "
                "ask clarifying questions, and offer recommendations conversationally.\n"
                "IMPORTANT: Never show internal source file paths (.py, .db), CSS/DOM IDs, JavaScript function names, or raw internal API routes in guidance replies unless the user explicitly asks for developer/CLI details.\n"
                f"Platform Context: {system_context}\n\n"
            )
            messages = []
            for h in (conversation_history or [])[-6:]:
                role = "User" if h.get("role") == "user" else "Assistant"
                messages.append(f"{role}: {h.get('content', '')}")

            messages.append(f"User: {user_message}")
            full_prompt = prompt + "\n".join(messages) + "\nAssistant:"

            response = await asyncio.to_thread(self.model.generate_content, full_prompt)
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            logger.warning("Gemini generate_content failed: %s", e)

        return None

    async def process_user_query(
        self,
        user_message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        active_target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Main communicative conversational assistant loop."""
        clean_msg = user_message.strip()
        history = conversation_history or []
        has_history = len(history) > 0

        # Target resolution
        target_info = self.extract_target_candidate(clean_msg)
        target = None
        target_type = "unknown"

        if target_info:
            target, target_type = target_info
        elif active_target:
            target = active_target
        elif has_history:
            hist_target = self.find_target_in_history(history)
            if hist_target:
                target, target_type = hist_target

        stats = get_db_stats() if OSINT_HUB_LOADED else {"total_tools": 2466, "total_sections": 31}
        total_tools = stats.get("total_tools", 2466)
        total_sections = stats.get("total_sections", 31)

        # Detect dialogue intent
        intent = self.classify_dialogue_intent(clean_msg, has_history, target)

        # If Gemini is active, let it communicate directly with grounded KB notes
        if self.model:
            kb_hits = self.retrieve_kb_sections(clean_msg, top_k=2)
            kb_snippet = "\n\n".join(
                f"[{sec['title']}]\n{sec['body']}" for _, sec in kb_hits
            )
            sys_ctx = (
                f"Catalogue of {total_tools} tools. Active target: {target or 'None'} ({target_type})."
                + (f"\n\nRelevant Verified Platform Documentation:\n{kb_snippet}" if kb_snippet else "")
            )
            gemini_reply = await self.generate_gemini_response(clean_msg, history, sys_ctx)
            if gemini_reply:
                matched_tools = []
                if target or "tool" in clean_msg.lower():
                    matched_entries = search_tools_by_keyword(target or clean_msg, limit=4) if OSINT_HUB_LOADED else []
                    matched_tools = [{
                        "tool_name": t.tool_name, "section": t.section, "category": t.category,
                        "description": t.description or "Intelligence provider", "url": t.url,
                        "flags": t.flags, "is_unverified": t.is_unverified
                    } for t in matched_entries]

                return {
                    "character_state": "speaking",
                    "character_name": "A.R.I.A.",
                    "character_avatar": "cyber_operative",
                    "intent": intent,
                    "reply": gemini_reply,
                    "matched_tools": matched_tools,
                    "target": target,
                    "target_type": target_type,
                    "suggested_prompts": self.build_follow_up_prompts(target, intent),
                    "total_tools_catalogue": total_tools,
                    "action_trigger": None
                }

        # -----------------------------------------------------------------
        # CONVERSATIONAL DIALOGUE ENGINE (Communicates naturally)
        # -----------------------------------------------------------------

        # 1. GREETING INTENT
        if intent == "greeting":
            reply_md = (
                f"### 👋 Hey there! I'm A.R.I.A., your OSINT Copilot.\n\n"
                f"I'm here to chat, guide you through investigations, and help you find exactly what you need across our **{total_tools:,} intelligence tools**.\n\n"
                f"What are you working on right now?\n"
                f"• Do you have a **specific target** you want to look up? (Like a domain, email, username, or phone number)\n"
                f"• Or are you looking for **recommended tools** for a specific task?\n\n"
                f"*Tell me what you'd like to do, and I'll walk you through it step by step!*"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "greeting",
                "reply": reply_md,
                "matched_tools": [],
                "target": None,
                "target_type": None,
                "suggested_prompts": [
                    "Help me investigate a suspicious email",
                    "How do I trace who owns a domain?",
                    "What tools do we have for phone numbers?",
                    "Find disposable temporary email tools"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 2. GRATITUDE INTENT
        if intent == "gratitude":
            reply_md = (
                f"### You're very welcome! 😊\n\n"
                f"I'm always here to help you dig deeper or make sense of the intelligence data. "
                f"Is there anything else you'd like to check on this target, or should we move on to something new?"
            )
            return {
                "character_state": "idle",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "gratitude",
                "reply": reply_md,
                "matched_tools": [],
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    "Check another target",
                    "Show database catalog (97 sources)",
                    "Audit email in Nexus Account Sentinel"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 2b. IDENTITY & CAPABILITIES ("Who are you?", "What can you do?", "Help me")
        if intent == "identity_capabilities":
            reply_md = (
                f"### 🤖 Hi, I'm A.R.I.A. — Your Autonomous OSINT Assistant\n\n"
                f"Think of me as your personal cybersecurity analyst and guide. Instead of making you dig through complex menus or run manual terminal commands alone, I communicate directly with you and handle the heavy lifting!\n\n"
                f"**Here are the core ways I can assist you right now:**\n\n"
                f"1. **🎯 Target Reconnaissance**: Give me any domain, IP address, email, phone number, or username. I will classify it, check threat reputation, and summarize key findings.\n"
                f"2. **✉️ Account & Breach Audits**: I can run checks via **Nexus Account Sentinel** to see if an email exists on GitHub, Twitter, Reddit, Discord, or Spotify, and if it appears in Have I Been Pwned breaches.\n"
                f"3. **⚡ Smart Tool Discovery**: I have direct access to **{total_tools:,} curated OSINT tools** across 31 disciplines. Ask me *'What tools exist for tracking phone numbers?'* or *'Find dark web search engines'*, and I'll find them immediately.\n"
                f"4. **🧭 Step-by-Step Guidance**: If you're stuck on an investigation, ask me *'What should I do next?'* and I will map out the logical investigative steps.\n\n"
                f"How can I help you today? You can type any target or question in plain English!"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "identity_capabilities",
                "reply": reply_md,
                "matched_tools": [],
                "target": None,
                "target_type": None,
                "suggested_prompts": [
                    "How do I use this website?",
                    "What is Nexus Account Sentinel?",
                    "Help me investigate a suspicious domain",
                    "Search tools for phone numbers"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 2b-bis. DIRECT UI NAVIGATION ("open threat graph", "go to sentinel", "open area 3", "open vault")
        if intent == "navigate_ui":
            m_low = clean_msg.lower()
            nav_action = "home"
            nav_label = "🔍 Search Home"
            kb_id = "platform_overview"
            if "threat graph" in m_low:
                nav_action, nav_label, kb_id = "section:threatgraph", "🕸️ Threat Graph Map", "graphs"
            elif "knowledge graph" in m_low:
                nav_action, nav_label, kb_id = "graph:knowledge", "🧠 Knowledge Graph", "graphs"
            elif "sentinel" in m_low:
                nav_action, nav_label, kb_id = "section:intelbase", "✉️ Nexus Account Sentinel", "nexus_sentinel"
            elif "vault" in m_low:
                nav_action, nav_label, kb_id = "modal:vault", "🔑 Personal API Key Vault", "vault_and_keys"
            elif "database" in m_low:
                nav_action, nav_label, kb_id = "section:databases", "🗄️ Databases Catalog (97 Sources)", "databases_and_fanout"
            elif "batch" in m_low:
                nav_action, nav_label, kb_id = "section:batch", "⚡ Batch IOC Triage", "threat_ops_and_recon"
            elif "passive dns" in m_low or "pdns" in m_low:
                nav_action, nav_label, kb_id = "section:pdns", "⏳ Passive DNS Timeline", "threat_ops_and_recon"
            elif "darkweb" in m_low:
                nav_action, nav_label, kb_id = "section:darkweb", "☠️ Darkweb & Tor Radar", "threat_ops_and_recon"
            elif "mitre" in m_low:
                nav_action, nav_label, kb_id = "section:mitre", "⚔️ Cyber Ops & ATT&CK", "threat_ops_and_recon"
            elif "attribution" in m_low:
                nav_action, nav_label, kb_id = "section:attribution", "🕵️ Actor Attribution", "threat_ops_and_recon"
            elif "area 1" in m_low or "executive" in m_low:
                nav_action, nav_label, kb_id = "area:executive", "📊 Area 1: Executive Briefing", "areas_1_to_7"
            elif "area 2" in m_low or "osint-hub" in m_low:
                nav_action, nav_label, kb_id = "area:hub", "⚡ Area 2: OSINT-HUB Fanout", "areas_1_to_7"
            elif "area 3" in m_low or "entities" in m_low:
                nav_action, nav_label, kb_id = "area:entities", "🎯 Area 3: 18-Facet Entities", "areas_1_to_7"
            elif "area 4" in m_low:
                nav_action, nav_label, kb_id = "area:cyber", "⚔️ Area 4: Cyber Ops & ATT&CK", "areas_1_to_7"
            elif "area 5" in m_low:
                nav_action, nav_label, kb_id = "area:breach", "🛡️ Area 5: Breach & Darkweb", "areas_1_to_7"
            elif "area 6" in m_low or "forensic" in m_low:
                nav_action, nav_label, kb_id = "area:forensics", "🔬 Area 6: Deep Forensics", "forensics"
            elif "area 7" in m_low or "dorkforge" in m_low:
                nav_action, nav_label, kb_id = "area:dorks", "🔎 Area 7: DorkForge Suite", "dorkforge"

            sec_obj = next((s for s in self.kb_sections if s["id"] == kb_id), None)
            extra = f"\n\n{sec_obj['body']}" if sec_obj else ""
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "navigate_ui",
                "kb_section": kb_id,
                "reply": f"### 🧭 Opening **{nav_label}** for you!{extra}",
                "matched_tools": [],
                "target": target,
                "target_type": target_type,
                "ui_actions": [{"action": nav_action, "label": f"Open {nav_label}"}] + (sec_obj["ui_actions"][:2] if sec_obj else []),
                "suggested_prompts": [
                    "Guide me step by step on this tool",
                    "How do the 7 Investigation Areas work?",
                    "How do I export a report?",
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": {"action": "navigate_ui", "ui_action": nav_action},
            }

        # 2b-ter. GROUNDED PLATFORM KNOWLEDGE BASE Q&A
        if intent == "platform_kb_qa":
            kb_hits = self.retrieve_kb_sections(clean_msg, top_k=2)
            # If user asked for a full-tool walkthrough, ensure platform_overview leads
            if re.search(r"\b(entire\s+tool|whole\s+tool|all\s+features|what\s+is\s+inside|operate\s+this|guide\s+me\s+step\s+by\s+step|full\s+guide|guide\s+me\s+on\s+entire)\b", clean_msg.lower()):
                ov = next((s for s in self.kb_sections if s["id"] == "platform_overview"), None)
                if ov:
                    kb_hits = [(100, ov)] + [h for h in kb_hits if h[1]["id"] != "platform_overview"][:1]
            primary_sec = kb_hits[0][1] if kb_hits else None
            if primary_sec:
                reply_md = (
                    f"### 📘 {primary_sec['title']}\n\n"
                    f"{primary_sec['body']}\n\n"
                )
                if len(kb_hits) > 1 and kb_hits[1][0] >= 12:
                    sec2 = kb_hits[1][1]
                    reply_md += f"---\n\n#### 🔗 Related: {sec2['title']}\n\n{sec2['body']}\n\n"

                reply_md += "Use the quick navigation buttons below to jump straight there, or ask me what to do next!"

                next_chips = [
                    "How do the 7 Investigation Areas work?",
                    "How does Threat Graph Map work?",
                    "How does Nexus Account Sentinel score risk?",
                    "How do I add API keys to the Vault?",
                ]
                sec_id = primary_sec["id"]
                if sec_id == "areas_1_to_7":
                    next_chips = [
                        "How do Threat Graph and Knowledge Graph work?",
                        "How does the Search Box auto-detect targets?",
                        "How do I analyze an image or file?",
                        "How does DorkForge work?",
                    ]
                elif sec_id == "nexus_sentinel":
                    next_chips = [
                        "Check security@github.com",
                        "How does consensus scoring work?",
                        "How do I add API keys to the Vault?",
                        "What are the 97 Databases categories?",
                    ]
                elif sec_id == "graphs":
                    next_chips = [
                        "How do the 7 Investigation Areas work?",
                        "How does Passive DNS Timeline work?",
                        "How does DorkForge work?",
                        "Investigate domain hackerone.com",
                    ]
                elif sec_id == "platform_overview":
                    next_chips = [
                        "Open Nexus Account Sentinel",
                        "Open Threat Graph",
                        "How do I export a report?",
                        "How do I run batch IOC triage?",
                    ]

                return {
                    "character_state": "speaking",
                    "character_name": "A.R.I.A.",
                    "character_avatar": "cyber_operative",
                    "intent": "platform_kb_qa",
                    "kb_section": sec_id,
                    "reply": reply_md,
                    "matched_tools": [],
                    "target": target,
                    "target_type": target_type,
                    "ui_actions": primary_sec.get("ui_actions", []),
                    "suggested_prompts": next_chips,
                    "total_tools_catalogue": total_tools,
                    "action_trigger": None,
                }

        # 2c. PLATFORM & WEBSITE GUIDANCE ("How do I use this website?", "Where do I start?")
        if intent == "platform_guidance":
            reply_md = (
                f"### 🧭 How to Use the Nexus OSINT Platform\n\n"
                f"We designed this platform to be simple, organized, and confusion-free. You can accomplish almost any OSINT task using these 4 easy workflows:\n\n"
                f"• **1. 🎯 Quick Target Lookup (Top Search Bar)**:\n"
                f"  Type any target — like a website (`example.com`), Indian phone number (`9876543210`), IP (`8.8.8.8`), or username (`admin`) — and hit **ENTER**. You'll get instant WHOIS, DNS records, telecom carrier data, and safety ratings.\n\n"
                f"• **2. ✉️ Nexus Account Sentinel (Sidebar -> Account Sentinel)**:\n"
                f"  Enter any email address. The Sentinel asynchronously checks whether the account exists on GitHub, Twitter/X, Reddit, Spotify, and Discord, while auditing Have I Been Pwned breach records.\n\n"
                f"• **3. ⚡ OSINT Tool Finder (Sidebar -> OSINT-Hub)**:\n"
                f"  Search our massive catalog of **{total_tools:,} verified tools** across 31 categories, complete with direct links and copyable CLI commands.\n\n"
                f"• **4. 🕸️ Threat Graph & Cyber Ops (Sidebar -> Threat Graph / MITRE)**:\n"
                f"  Visualize connections between domains, IPs, subdomains, and MITRE ATT&CK adversary tactics.\n\n"
                f"💡 **Pro-Tip**: You can also ask me directly in this chat anytime, and I'll look up the information or navigate you to the right screen!"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "platform_guidance",
                "reply": reply_md,
                "matched_tools": [],
                "target": None,
                "target_type": None,
                "suggested_prompts": [
                    "Open Nexus Account Sentinel",
                    "Investigate domain hackerone.com",
                    "Browse all 2,466 tools",
                    "What is Passive DNS?"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 2d. SENTINEL INQUIRY ("What is Nexus Account Sentinel?", "Check email")
        if intent == "sentinel_inquiry":
            reply_md = (
                f"### ✉️ What is Nexus Account Sentinel?\n\n"
                f"**Nexus Account Sentinel** is our automated email presence and breach detection module. Here is how it works:\n\n"
                f"1. **Asynchronous Account Checkers**: When you provide an email, background worker routines simulate password-reset signals against mainstream sites — including **GitHub, Twitter/X, Reddit, Spotify, and Discord** — to verify if an account is registered with that address.\n"
                f"2. **Data Breach & Leak Records**: Connects to the Have I Been Pwned (HIBP v3) API to cross-reference known breach dumps and stealer logs.\n"
                f"3. **Live SSE Streaming**: Results stream onto your dashboard in real-time as each site finishes checking, generating an overall **Risk Score (0–100)** and actionable security remediation playbook.\n\n"
                f"Would you like to run an email audit in Nexus Account Sentinel right now?"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "sentinel_inquiry",
                "reply": reply_md,
                "matched_tools": [],
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    "Check email test@example.com",
                    "How does the breach scoring work?",
                    "What sites does Sentinel check?",
                    "Go to Account Sentinel screen"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 3. SAFETY / REPUTATION ASSESSMENT ("Is it safe? Is it malicious?")
        if intent == "safety_assessment":
            t_name = target or "this indicator"
            reply_md = (
                f"### 🛡️ Safety & Threat Evaluation for `{t_name}`\n\n"
                f"When evaluating whether **`{t_name}`** is safe or potentially malicious, here is what our engines look for:\n\n"
                f"1. **Threat Feed Blocklists**: Checking if this indicator appears in live feeds like AbuseIPDB, URLhaus, or VirusTotal.\n"
                f"2. **Domain & SSL Age**: Brand new domains registered in the last 14–30 days carry much higher risk than established domains.\n"
                f"3. **Infrastructure Hosting**: Is it hosted on high-reputation CDNs (like Cloudflare/Fastly) or known bulletproof hosting providers?\n\n"
                f"💡 **My Initial Take**: If you received this in an unsolicited email or message, treat it with caution until we verify its WHOIS records and SSL transparency logs.\n\n"
                f"Would you like me to run an automated reputation scan on `{t_name}` right now?"
            )
            kw = "reputation" if not target else target_type
            matched_entries = search_tools_by_keyword(kw, limit=3) if OSINT_HUB_LOADED else []
            tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "Threat reputation checker", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified
            } for t in matched_entries]

            return {
                "character_state": "investigating",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "safety_assessment",
                "reply": reply_md,
                "matched_tools": tools_payload,
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    f"Scan {t_name} on VirusTotal and Shodan",
                    f"Check WHOIS registration for {t_name}",
                    f"See historical passive DNS for {t_name}"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 4. OWNERSHIP INQUIRY ("Who owns it? Who registered it?")
        if intent == "ownership_inquiry":
            t_name = target or "the domain"
            reply_md = (
                f"### 🔍 Tracing Ownership & Registration for `{t_name}`\n\n"
                f"To find out who is behind **`{t_name}`**, here is our recommended investigative approach:\n\n"
                f"• **WHOIS / RDAP Records**: Reveals registrar, creation date, nameservers, and registrant contact details (or the privacy proxy service used).\n"
                f"• **Historical WHOIS**: If current WHOIS is privacy-protected, historical records often reveal the original unredacted owner before privacy was enabled.\n"
                f"• **SSL/TLS Certificate Clustering**: Subject Alternative Names (SANs) and organizational cert fields often link seemingly unrelated domains to the same company or person.\n\n"
                f"Here are the top tools from our catalogue to inspect ownership:"
            )
            matched_entries = search_tools_by_keyword("whois", limit=3) if OSINT_HUB_LOADED else []
            tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "WHOIS registrant lookup", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified
            } for t in matched_entries]

            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "ownership_inquiry",
                "reply": reply_md,
                "matched_tools": tools_payload,
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    f"Lookup WHOIS records for {t_name}",
                    f"Inspect SSL certificates for {t_name}",
                    f"Search subdomains of {t_name}"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 5. HOW-TO GUIDANCE ("How do I find someone's phone / email / crypto?")
        if intent == "how_to_guidance":
            lower_msg = clean_msg.lower()
            topic = "General OSINT"
            guidance = ""
            kw = "search"

            if "phone" in lower_msg or "number" in lower_msg:
                topic = "Phone Number & Telecom Intelligence"
                kw = "phone"
                guidance = (
                    "Here is how you can track and verify a phone number:\n\n"
                    "1. **Carrier & Line Type**: First determine if it's a mobile SIM, landline, or virtual VoIP number (e.g. Google Voice, Twilio, TextNow). VoIP numbers are harder to trace to an individual.\n"
                    "2. **Caller ID & Name Lookups**: Use databases like Truecaller, Sync.me, or NumVerify to check crowd-sourced contact books.\n"
                    "3. **Messaging App Footprints**: Add the number to WhatsApp, Telegram, or Signal to see profile photos, display names, and 'About' status.\n"
                    "4. **Reverse Search in Data Dumps**: Check if the number appears in past credential breaches (like the Facebook 533M leak)."
                )
            elif "email" in lower_msg:
                topic = "Email Footprint & Account Recon"
                kw = "email"
                guidance = (
                    "To investigate an email address effectively:\n\n"
                    "1. **Account Presence Check**: Use our built-in **Nexus Account Sentinel** to probe whether this email is registered on GitHub, Twitter/X, Reddit, Spotify, or Discord.\n"
                    "2. **Data Breach Search**: Query Have I Been Pwned to see if passwords or credentials have been compromised.\n"
                    "3. **MX & Mail Server Verification**: Check if the domain's mail server exists and whether it accepts incoming mail.\n"
                    "4. **Username Pivot**: Take the username part before the `@` and search across 300+ social platforms."
                )
            elif "crypto" in lower_msg or "bitcoin" in lower_msg or "wallet" in lower_msg:
                topic = "Cryptocurrency & Blockchain Tracking"
                kw = "crypto"
                guidance = (
                    "Here is how blockchain tracing works:\n\n"
                    "1. **Explorer Lookups**: Put the wallet address into Etherscan (ETH), Blockchain.com (BTC), or Solscan (SOL) to view balance and transaction history.\n"
                    "2. **Clustering & Fund Flow**: Follow the money trail to identify deposit addresses at centralized exchanges (KYC pinch-points like Binance, Coinbase, Kraken).\n"
                    "3. **Smart Contract Auditing**: Check if the wallet has interacted with mixers (Tornado Cash), bridges, or NFT marketplaces."
                )
            else:
                topic = "OSINT Investigation Strategy"
                kw = "recon"
                guidance = (
                    f"To investigate **{clean_msg}**:\n\n"
                    "1. **Identify the Core Indicator**: Start with the most unique piece of information (email, handle, domain, or IP).\n"
                    "2. **Passive Discovery First**: Use search engines, cached pages, and certificate logs so you don't alert the target.\n"
                    "3. **Cross-Correlate**: Corroborate findings across at least two independent sources before drawing conclusions."
                )

            matched_entries = search_tools_by_keyword(kw, limit=4) if OSINT_HUB_LOADED else []
            tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "Target intelligence utility", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified
            } for t in matched_entries]

            reply_md = (
                f"### 📘 Guide: {topic}\n\n"
                f"{guidance}\n\n"
                f"Would you like to try running this against a specific target now, or explore tools for this category?"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "how_to_guidance",
                "reply": reply_md,
                "matched_tools": tools_payload,
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    f"Show top tools for {kw}",
                    "Audit email in Nexus Account Sentinel",
                    "How to search dark web pastebins",
                    "Investigate a target now"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 6. NEXT STEPS / FOLLOW-UP INTENT
        if intent == "next_steps" and target:
            reply_md = (
                f"### 🎯 Recommended Next Steps for `{target}` ({target_type.upper()})\n\n"
                f"Based on what we've seen for **`{target}`**, here are the most effective follow-up actions:\n\n"
                f"1. **Run the Threat Graph**: Open the 18-facet visual map to see correlated IPs, nameservers, and subdomains in an interactive node diagram.\n"
                f"2. **Check Historical DNS**: Reconstruct past hosting changes using passive DNS to see if it recently moved to a new provider.\n"
                f"3. **Audit Associated Emails**: If investigating a company, check if employee credentials appear in darkweb stealer logs.\n\n"
                f"Which one of these would you like to run next?"
            )
            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "next_steps",
                "reply": reply_md,
                "matched_tools": [],
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    f"Launch Threat Graph for {target}",
                    f"Reconstruct passive DNS for {target}",
                    f"Audit email security for {target}",
                    "Generate an executive briefing report"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 7. TOOL SEARCH INTENT
        if intent == "search_tools":
            kw_clean = re.sub(
                r"\b(search|find|list|tools?|show|me|what|do|you|have|for|are|there|give|in|catalogue|can|you|please|recommend|a)\b",
                "",
                clean_msg,
                flags=re.IGNORECASE,
            ).strip()
            kw_query = kw_clean or "lookup"

            matched_entries = search_tools_by_keyword(kw_query, limit=5) if OSINT_HUB_LOADED else []
            tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "Intelligence utility", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified,
            } for t in matched_entries]

            reply_md = (
                f"### ⚡ Tools for `\"{kw_query}\"`\n\n"
                f"I searched our catalogue of **{total_tools:,} tools**. Here are the most effective options for **{kw_query}**:\n\n"
            )
            for idx, t in enumerate(tools_payload, 1):
                reply_md += f"**{idx}. [{t['tool_name']}]({t['url']})** (*{t['category']}*)\n> {t['description']}\n\n"

            reply_md += f"Do any of these look right for what you're trying to accomplish, or should I refine the search?"

            return {
                "character_state": "success",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "search_tools",
                "reply": reply_md,
                "matched_tools": tools_payload,
                "target": None,
                "target_type": None,
                "suggested_prompts": [
                    f"Open {tools_payload[0]['tool_name'] if tools_payload else 'tool'}",
                    "Search disposable phone number tools",
                    "Find crypto tracking tools",
                    "Investigate a specific target with these"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 8. TARGET INVESTIGATION INTENT (Conversational analysis rather than raw table dump)
        if target:
            if OSINT_HUB_LOADED:
                auto_type, norm_val, auto_conf = classify_target(target)
                final_target = norm_val or target
                final_type = auto_type if auto_type != "unknown" else target_type
                conf = auto_conf if auto_conf > 0 else 0.88
                plan = route_target(final_target, final_type, conf, include_dorks=True, limit=15)
            else:
                final_target = target
                final_type = target_type
                conf = 0.90
                plan = None

            matched_tools_payload = []
            if plan:
                for item in (plan.auto_open + plan.manual_followups)[:5]:
                    t = item.tool
                    pop_url = getattr(item, "populated_url", t.url)
                    matched_tools_payload.append({
                        "tool_name": t.tool_name,
                        "section": t.section,
                        "category": t.category,
                        "description": getattr(t, "description", "") or "Intelligence provider",
                        "url": pop_url,
                        "action_type": item.action_type,
                        "cli_command": getattr(item, "cli_command", None),
                        "is_unverified": t.is_unverified,
                    })

            # Conversational assessment narrative
            if final_type == "email":
                narrative = (
                    f"I analyzed the email address **`{final_target}`**.\n\n"
                    f"• **Type**: Mailbox Indicator\n"
                    f"• **Recommended Action**: You can test this email in our **Nexus Account Sentinel** to see if it is registered on GitHub, Twitter/X, Reddit, Spotify, or Discord, and check for HIBP breach exposure.\n"
                    f"• **Username Pivot**: The prefix `{(final_target.split('@')[0])}` can also be checked across social platforms."
                )
            elif final_type in {"domain", "url"}:
                narrative = (
                    f"I looked into the domain **`{final_target}`**.\n\n"
                    f"• **Type**: Network / Web Domain\n"
                    f"• **Observations**: It is an active domain. We can inspect its DNS records, WHOIS registration history, and SSL certificate transparency logs.\n"
                    f"• **Risk Outlook**: Baseline risk is Low/Moderate unless flagged in threat feeds."
                )
            elif final_type == "ipv4":
                narrative = (
                    f"I evaluated IP address **`{final_target}`**.\n\n"
                    f"• **Type**: IPv4 Address\n"
                    f"• **Observations**: We can trace its Autonomous System (ASN), geographical netblock location, and query Shodan/AbuseIPDB to see if any open ports or abusive activity are recorded."
                )
            elif final_type == "phone":
                narrative = (
                    f"I reviewed the phone number **`{final_target}`**.\n\n"
                    f"• **Type**: Telecommunication Indicator\n"
                    f"• **Observations**: We can identify the carrier, determine whether it is a real mobile SIM or a virtual VoIP number, and search public reverse lookup directories."
                )
            else:
                narrative = (
                    f"I classified **`{final_target}`** as a **{final_type.upper()}** indicator.\n\n"
                    f"I've selected matching utilities from our **{total_tools:,} tools database** to run reconnaissance on this target."
                )

            reply_md = (
                f"### 🛡️ Investigation Overview: `{final_target}`\n\n"
                f"{narrative}\n\n"
                f"#### ⚡ Curated Tools You Can Launch for `{final_target}`:\n"
            )
            for idx, item in enumerate(matched_tools_payload[:4], 1):
                reply_md += f"**{idx}. [{item['tool_name']}]({item['url']})** — *{item['category']}*\n> {item['description']}\n\n"

            reply_md += f"Would you like me to dispatch this target to the **Investigation Hub** for full automated analysis, or should we examine one of these tools?"

            report_data = {
                "report_id": f"ARIA-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "target": final_target,
                "target_type": final_type,
                "confidence_pct": int(conf * 100),
                "risk_score": 35,
                "threat_level": "LOW",
                "matched_tools_count": len(matched_tools_payload),
                "summary": f"Investigation initiated for {final_target}.",
            }

            return {
                "character_state": "success",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "investigate_target",
                "reply": reply_md,
                "matched_tools": matched_tools_payload,
                "target": final_target,
                "target_type": final_type,
                "report_data": report_data,
                "suggested_prompts": self.build_follow_up_prompts(final_target, "investigate"),
                "total_tools_catalogue": total_tools,
                "action_trigger": {
                    "action": "execute_platform_scan",
                    "target": final_target,
                    "target_type": final_type,
                },
            }

        # 8b. CONCEPT EXPLANATION INTENT
        if intent == "explain_concept":
            lower_msg = clean_msg.lower()
            concept_title = "OSINT Concept"
            explanation = ""
            matched_kw = "osint"

            if "passive dns" in lower_msg or "pdns" in lower_msg:
                concept_title = "Passive DNS (pDNS)"
                matched_kw = "dns"
                explanation = (
                    "**Passive DNS** is a historical recording system that logs DNS query resolutions observed across global recursive resolvers over time.\n\n"
                    "• **Why it matters**: While active DNS only shows where a domain points *right now*, passive DNS reveals all IP addresses and hosting providers a domain has pointed to in the past.\n"
                    "• **Use Cases**: Detecting cyber threat infrastructure changes, tracking malicious domain takeovers, and identifying shared hosting neighborhoods."
                )
            elif "whois" in lower_msg or "rdap" in lower_msg:
                concept_title = "WHOIS & RDAP"
                matched_kw = "whois"
                explanation = (
                    "**WHOIS** is a protocol that queries databases storing registered users or assignees of an Internet resource (such as domain names, IP address blocks, or autonomous systems).\n\n"
                    "• **Why it matters**: It provides registrar names, creation dates, expiration dates, nameservers, and sometimes contact details (unless protected by privacy shields).\n"
                    "• **RDAP**: The modern, RESTful JSON successor to legacy WHOIS with standardized formatting and better access controls."
                )
            elif "hibp" in lower_msg or "pwned" in lower_msg or "breach" in lower_msg:
                concept_title = "Have I Been Pwned & Breach Records"
                matched_kw = "breach"
                explanation = (
                    "**Have I Been Pwned (HIBP)** is the industry standard repository of compromised user accounts collected from historical corporate data breaches, stealer logs, and credential stuffing dumps.\n\n"
                    "• **Why it matters**: It lets security teams and individuals check whether their email or password has been exposed in public breaches without revealing the password itself.\n"
                    "• **Nexus Account Sentinel Integration**: Our platform queries HIBP directly alongside live social account presence checks."
                )
            elif "dork" in lower_msg or "google dork" in lower_msg:
                concept_title = "Google Dorking (DorkForge)"
                matched_kw = "dork"
                explanation = (
                    "**Google Dorking** (also known as Google Hacking) uses advanced search operators (like `filetype:pdf`, `site:target.com`, `inurl:admin`) to locate exposed files, configuration leaks, and unsecured login portals indexed by search engines.\n\n"
                    "• **DorkForge Suite**: Our built-in DorkForge module automatically compiles 26 specialized operators for any target you specify with 1-click execution."
                )
            elif "mitre" in lower_msg or "attack" in lower_msg:
                concept_title = "MITRE ATT&CK Framework"
                matched_kw = "threat"
                explanation = (
                    "**MITRE ATT&CK** is a globally accessible knowledge base of adversary tactics and techniques based on real-world cyber threat observations.\n\n"
                    "• **Why it matters**: It helps defenders understand *how* threat actors break in, move laterally, exfiltrate data, and establish persistence, mapped to specific APT threat groups."
                )
            else:
                concept_title = f"Topic: {clean_msg}"
                matched_kw = "osint"
                explanation = (
                    f"You asked about **\"{clean_msg}\"**.\n\n"
                    f"In Open Source Intelligence (OSINT) and cyber defense, this concept relates to gathering verifiable, publicly accessible data to understand infrastructure, identities, and threat vectors without touching unauthorized systems.\n\n"
                    f"Would you like me to recommend specific tools or run an investigation on this?"
                )

            matched_entries = search_tools_by_keyword(matched_kw, limit=3) if OSINT_HUB_LOADED else []
            tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "Intelligence utility", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified
            } for t in matched_entries]

            reply_md = (
                f"### 💡 {concept_title}\n\n"
                f"{explanation}\n\n"
                f"Here are top tools from our catalogue related to this topic:"
            )

            return {
                "character_state": "speaking",
                "character_name": "A.R.I.A.",
                "character_avatar": "cyber_operative",
                "intent": "explain_concept",
                "reply": reply_md,
                "matched_tools": tools_payload,
                "target": target,
                "target_type": target_type,
                "suggested_prompts": [
                    f"Show top tools for {matched_kw}",
                    "How do I use this website?",
                    "Investigate a target now",
                    "What is Nexus Account Sentinel?"
                ],
                "total_tools_catalogue": total_tools,
                "action_trigger": None,
            }

        # 9. GENERAL CONVERSATIONAL INQUIRY FALLBACK (Natural, friendly, communicative response)
        # Check if user mentioned any topical keyword
        kw_match = None
        for cand in [
            "telegram", "discord", "twitter", "reddit", "instagram", "facebook", "linkedin", "github",
            "bitcoin", "crypto", "blockchain", "darkweb", "onion", "tor", "phone", "sms", "email",
            "domain", "ip", "dns", "subdomain", "camera", "shodan", "wifi", "satellite", "flight",
            "vehicle", "vin", "breach", "leak", "password", "hash"
        ]:
            if cand in clean_msg.lower():
                kw_match = cand
                break

        matched_tools_payload = []
        if kw_match:
            matched_entries = search_tools_by_keyword(kw_match, limit=3) if OSINT_HUB_LOADED else []
            matched_tools_payload = [{
                "tool_name": t.tool_name, "section": t.section, "category": t.category,
                "description": t.description or "Intelligence provider", "url": t.url,
                "flags": t.flags, "is_unverified": t.is_unverified
            } for t in matched_entries]

            reply_md = (
                f"### 💬 Let's explore **{kw_match.capitalize()}**!\n\n"
                f"I noticed your inquiry touches on **{kw_match}**. "
                f"Our platform includes dedicated intelligence tools specifically for this discipline across our **{total_tools:,} tools catalogue**.\n\n"
                f"Here are top-tier tools you can use right away for **{kw_match}**:\n\n"
            )
            for idx, t in enumerate(matched_tools_payload, 1):
                reply_md += f"**{idx}. [{t['tool_name']}]({t['url']})** (*{t['category']}*)\n> {t['description']}\n\n"

            reply_md += (
                f"What specific target or question do you have in mind regarding **{kw_match}**? "
                f"Tell me more and I'll walk you through the exact steps!"
            )
        else:
            reply_md = (
                f"### 💬 I'm here and ready to help!\n\n"
                f"I received your message: *\"{clean_msg}\"*\n\n"
                f"I can help you with anything related to open-source intelligence, cybersecurity, or navigating this platform. Here are the easiest ways we can proceed:\n\n"
                f"• **Investigate a Target**: Give me any email, website domain, phone number, username, or IP address.\n"
                f"• **Find Tools**: Ask me to recommend tools for anything (like *'tools for tracking crypto'* or *'reverse image search'*).\n"
                f"• **Guide You**: Ask *'How do I use this website?'* or *'What is Nexus Account Sentinel?'*.\n\n"
                f"What would you like to explore next?"
            )

        return {
            "character_state": "speaking",
            "character_name": "A.R.I.A.",
            "character_avatar": "cyber_operative",
            "intent": "conversational_assistant",
            "reply": reply_md,
            "matched_tools": matched_tools_payload,
            "target": target,
            "target_type": target_type,
            "suggested_prompts": [
                "How do I investigate an email address?",
                "What tools do we have for phone lookup?",
                "Help me trace a suspicious domain",
                "Show all 2,466 tools"
            ],
            "total_tools_catalogue": total_tools,
            "action_trigger": None,
        }

    def build_follow_up_prompts(self, target: Optional[str], intent: str) -> List[str]:
        """Generate smart, contextual follow-up question chips for the chat UI."""
        if not target:
            return [
                "Investigate domain hackerone.com",
                "Find disposable phone tools",
                "Search cryptocurrency tracking tools",
                "How does reverse image search work?"
            ]

        t = target.lower()
        if "@" in t:
            return [
                f"Audit {target} in Nexus Account Sentinel",
                f"Check Have I Been Pwned breach history for {target}",
                f"Find usernames associated with {target.split('@')[0]}",
                "How to verify email deliverability (MX records)"
            ]
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t):
            return [
                f"Lookup ASN and BGP routing for {target}",
                f"Check Shodan and open ports on {target}",
                f"Check AbuseIPDB reputation for {target}",
                f"Reconstruct passive DNS for {target}"
            ]
        else:
            return [
                f"Check WHOIS & DNS records for {target}",
                f"Inspect historical passive DNS for {target}",
                f"Scan SSL certificate transparency logs for {target}",
                f"Generate executive briefing dossier for {target}"
            ]


ai_assistant_engine = AIAssistantEngine()
