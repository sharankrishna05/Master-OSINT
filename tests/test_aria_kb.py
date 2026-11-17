import pytest
from osint_arsenal.cti.ai_assistant import AIAssistantEngine


@pytest.mark.asyncio
async def test_aria_kb_loaded():
    engine = AIAssistantEngine()
    assert len(engine.kb_sections) >= 14
    ids = {s["id"] for s in engine.kb_sections}
    assert {"areas_1_to_7", "graphs", "nexus_sentinel", "search_box", "vault_and_keys", "cli_mcp_deploy"}.issubset(ids)


@pytest.mark.asyncio
@pytest.mark.parametrize("question,expected_section,expected_snippet", [
    ("How do the 7 investigation areas work?", "areas_1_to_7", "Area 1"),
    ("How does Threat Graph Map and Knowledge Graph work?", "graphs", "Star-Mesh"),
    ("How does Nexus Account Sentinel calculate the risk score?", "nexus_sentinel", "55"),
    ("How do I analyze an image or EXIF metadata?", "forensics", "EXIF"),
    ("How do I add API keys to the Vault to unlock tools?", "vault_and_keys", "VAULT"),
    ("How does consensus scoring calculate confidence?", "consensus_and_lookup", "Bayesian-shrunk"),
    ("What are the 15 database categories A through O?", "databases_and_fanout", "97"),
    ("How does DorkForge work?", "dorkforge", "26"),
    ("How do I deploy with Docker or run CLI commands?", "cli_mcp_deploy", "docker compose"),
    ("How does the search box auto-detect targets?", "search_box", "13"),
    ("Guide me on entire tool", "platform_overview", "Search Home"),
    ("How to check batch ioc", "threat_ops_and_recon", "Batch IOC Triage"),
    ("How to export report", "reports_and_exports", "STIX"),
])
async def test_aria_answers_platform_manual_questions(question, expected_section, expected_snippet):
    engine = AIAssistantEngine()
    engine.model = None  # Deterministic check of built-in trained engine
    res = await engine.process_user_query(question)
    assert res["intent"] == "platform_kb_qa"
    assert res["kb_section"] == expected_section
    assert expected_snippet.lower() in res["reply"].lower()
    assert "How It Works" in res["reply"] or "How to Operate" in res["reply"]
    assert len(res["suggested_prompts"]) >= 3
    assert len(res["ui_actions"]) >= 1
    for forbidden in (".py", "vault.db", "arsenal.db", "osint.db", "/api/v2/", "#section-", "#omni-input", "autoDetectOmni", "runLiveInvestigation"):
        assert forbidden not in res["reply"], f"Unexpected internal reference {forbidden} in reply for {question}"


@pytest.mark.asyncio
async def test_aria_direct_navigation_commands():
    engine = AIAssistantEngine()
    engine.model = None
    res = await engine.process_user_query("Open Threat Graph")
    assert res["intent"] == "navigate_ui"
    assert res["action_trigger"]["ui_action"] == "section:threatgraph"
    assert len(res["ui_actions"]) >= 1


@pytest.mark.asyncio
async def test_aria_still_investigates_explicit_targets():
    engine = AIAssistantEngine()
    engine.model = None
    res = await engine.process_user_query("Investigate domain hackerone.com")
    assert res["intent"] == "investigate_target"
    assert res["target"] == "hackerone.com"
