import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    from osint_arsenal import config
    monkeypatch.setattr(config.settings, "db_path", str(tmp_path / "t.db"))
    return str(tmp_path / "t.db")
