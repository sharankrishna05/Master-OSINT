import pytest
import osint_arsenal.lookup  # noqa
from osint_arsenal.lookup.modules import registry
from osint_arsenal.lookup.consensus import compute_verdict
from osint_arsenal.models import ModuleResult, Status, LookupKind


def test_registry_has_builtins():
    names = {m.name for m in registry.all()}
    for expected in ("GitHub", "Gravatar", "PhoneParse", "WHOIS", "DNS", "IPInfo"):
        assert expected in names


def _r(mod, status, cat="major", conf=0.9):
    return ModuleResult(module=mod, category=cat, status=status, confidence=conf)


def test_high_verdict():
    results = [_r(f"m{i}", Status.FOUND) for i in range(5)] + \
              [_r("n1", Status.NOT_FOUND), _r("n2", Status.NOT_FOUND)]
    v = compute_verdict(LookupKind.USERNAME, "alice", results)
    assert v.label == "high"
    assert v.confidence > 0.7


def test_insufficient():
    results = [_r(f"m{i}", Status.NOT_FOUND) for i in range(5)]
    v = compute_verdict(LookupKind.USERNAME, "zzz", results)
    assert v.label == "insufficient"
    assert v.found == 0
