import pytest
import osint_arsenal.webcheck  # noqa
from osint_arsenal.webcheck.jobs import registry
from osint_arsenal.webcheck.jobs.loader import BUILTIN
from osint_arsenal.webcheck.engine import _normalize_url


def test_all_builtin_registered():
    # loader is called elsewhere; import to populate
    from osint_arsenal.webcheck.jobs.loader import load_all
    load_all()
    names = {j.name for j in registry.all()}
    for b in BUILTIN:
        assert b in names, f"missing job: {b}"


def test_normalize_url():
    u, h, s = _normalize_url("example.com")
    assert s == "https"
    assert h == "example.com"
