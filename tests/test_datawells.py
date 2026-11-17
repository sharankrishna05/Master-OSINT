import pytest
from httpx import AsyncClient, ASGITransport
from osint_arsenal.api.server import create_app
from osint_arsenal.cti.datawells import datawells_service, DATAWELLS_CATALOG

@pytest.mark.asyncio
async def test_datawells_catalog_count():
    catalog = datawells_service.get_catalog()
    assert len(catalog) == 13
    catalog_ids = {s["id"] for s in catalog}
    expected_ids = {
        "snusbase", "intelx", "leakcheck", "whiteintel", "leakeddomains",
        "leaklookup", "libraryofleaks", "breachdirectory", "infostealers",
        "spycloud", "scamsearch", "greynoise", "hibp"
    }
    assert expected_ids == catalog_ids

@pytest.mark.asyncio
async def test_datawells_sources_endpoint():
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v2/datawells/sources")
        assert res.status_code == 200
        data = res.json()
        assert "sources" in data
        assert len(data["sources"]) == 13

@pytest.mark.asyncio
async def test_breach_analytics_endpoint():
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v2/analytics/breach/test@example.com")
        assert res.status_code == 200
        data = res.json()
        assert data["target"] == "test@example.com"
        assert "datawells_summary" in data
        assert len(data["datawells_summary"]) == 13
        assert "catalog_exposures" in data
        assert len(data["catalog_exposures"]) > 0
