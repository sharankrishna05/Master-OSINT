import uuid
from typing import List, Dict, Any

class GraphEngine:
    """
    Builds entity relationship graph nodes and edges
    from normalized findings for React Flow and Force Graph rendering.
    """
    @staticmethod
    def build_network_graph(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        edges = []
        seen_nodes = set()

        # Center Root Target Node
        root_id = f"node-root-{target}"
        nodes.append({
            "id": root_id,
            "label": target,
            "type": "target",
            "group": "target",
            "val": 25,
            "color": "#00f5ff"
        })
        seen_nodes.add(root_id)

        for finding in findings:
            source_id = f"node-src-{finding.get('source_name')}"
            if source_id not in seen_nodes:
                nodes.append({
                    "id": source_id,
                    "label": finding.get("source_name"),
                    "type": "source",
                    "group": finding.get("category", "general"),
                    "val": 15,
                    "color": "#39ff14"
                })
                seen_nodes.add(source_id)

            # Edge from Target to Source
            edges.append({
                "id": f"edge-{root_id}-{source_id}",
                "source": root_id,
                "target": source_id,
                "label": "QUERIED_BY",
                "color": "#142a47"
            })

            # Discovered Entities
            for ent in finding.get("entities_discovered", []):
                val = ent.get("value", "")
                if not val:
                    continue
                ent_id = f"node-ent-{val}"
                if ent_id not in seen_nodes:
                    nodes.append({
                        "id": ent_id,
                        "label": val,
                        "type": "entity",
                        "group": ent.get("type", "entity"),
                        "val": 12,
                        "color": "#bf5af2" if ent.get("type") == "asn" else "#ff6b00"
                    })
                    seen_nodes.add(ent_id)

                edges.append({
                    "id": f"edge-{source_id}-{ent_id}",
                    "source": source_id,
                    "target": ent_id,
                    "label": "RESOLVED",
                    "color": "#ff003c" if "malicious" in str(finding) else "#00f5ff"
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }
