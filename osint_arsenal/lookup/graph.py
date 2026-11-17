from __future__ import annotations
import networkx as nx
from ..models import ModuleResult


class EvidenceGraph:
    def __init__(self):
        self.g = nx.MultiDiGraph()

    def add_query(self, kind: str, query: str) -> str:
        nid = f"{kind}:{query}"
        self.g.add_node(nid, kind="query", label=query)
        return nid

    def add_result(self, query_node: str, r: ModuleResult) -> str:
        nid = f"module:{r.module}"
        self.g.add_node(nid, kind="module", label=r.module, category=r.category)
        self.g.add_edge(query_node, nid, relation="checked_on",
                        status=r.status.value, url=r.url)
        for key, val in (r.evidence or {}).items():
            values = val if isinstance(val, list) else [val]
            for v in values:
                if not v:
                    continue
                ev_id = f"ev:{key}:{v}"
                self.g.add_node(ev_id, kind="evidence", label=str(v))
                self.g.add_edge(nid, ev_id, relation=f"exposes_{key}")
        return nid

    def to_cytoscape(self) -> dict:
        return {
            "elements": {
                "nodes": [{"data": {"id": n, **d}}
                          for n, d in self.g.nodes(data=True)],
                "edges": [{"data": {"source": u, "target": v, **d}}
                          for u, v, d in self.g.edges(data=True)],
            }
        }
