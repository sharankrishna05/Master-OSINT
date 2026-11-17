from osint_arsenal.directory.loader import load_directory, filter_tools


def test_directory_loads():
    ds = load_directory()
    assert len(ds.tools) > 0
    assert len(ds.categories) > 0
    assert len(ds.platforms) > 0


def test_filter_tools():
    ds = load_directory()
    free = filter_tools(ds.tools, free=True)
    assert all(t.free for t in free)
    oss = filter_tools(ds.tools, open_source=True)
    assert all(t.open_source for t in oss)
    gh = filter_tools(ds.tools, q="sherlock")
    assert any("sherlock" in t.name.lower() for t in gh)
