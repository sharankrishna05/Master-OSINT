from osint_arsenal.db import DB
from osint_arsenal.models import (
    Investigation, InvestigationKind, ModuleResult, Status, Verdict,
)


def test_investigation_roundtrip(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    inv = Investigation(id="x", kind=InvestigationKind.LOOKUP,
                        subkind="username", query="alice")
    db.create_investigation(inv)
    db.add_result("x", "GitHub", ModuleResult(
        module="GitHub", category="major", status=Status.FOUND,
        url="https://github.com/alice", confidence=0.9, evidence={"a": 1}))
    db.update_investigation("x", status="done")
    got = db.get_investigation("x")
    assert got["status"] == "done"
    assert got["results"][0]["source"] == "GitHub"
    assert got["results"][0]["data"] == {"a": 1}


def test_key_lifecycle(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    db.ensure_key("abc", "test")
    assert db.is_valid_key("abc") is True
    db.revoke_key("abc")
    assert db.is_valid_key("abc") is False


def test_list_and_delete(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    db.create_investigation(Investigation(id="1", kind=InvestigationKind.LOOKUP,
                                          query="a"))
    db.create_investigation(Investigation(id="2", kind=InvestigationKind.WEBCHECK,
                                          query="https://x"))
    assert len(db.list_investigations()) == 2
    assert len(db.list_investigations(kind="webcheck")) == 1
    db.delete_investigation("1")
    assert db.get_investigation("1") is None
