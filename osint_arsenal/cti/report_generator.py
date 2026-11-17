import datetime
import json
from typing import Dict, Any, List

class ReportGenerator:
    def generate(self, inv_id: str, query: str, query_type: str, verified_data: Dict, analysis: Dict) -> Dict:
        report = {
            "report_id": inv_id,
            "classification": "TLP:WHITE - For authorized use only",
            "generated_at": datetime.datetime.utcnow().isoformat(),
            "analyst_note": "AI-generated report. Human analyst review recommended.",
            "executive_summary": {
                "target": query,
                "target_type": query_type,
                "risk_score": analysis.get("risk_score", 0),
                "threat_level": analysis.get("threat_level", "UNKNOWN"),
                "confidence": analysis.get("confidence", 0.5),
                "sources_analyzed": analysis.get("sources_analyzed", 0),
                "key_finding": analysis.get("ai_assessment", "No assessment available")
            },
            "methodology": {
                "phases": [
                    {"phase": 1, "name": "Open Source Intelligence Collection", "description": "Automated collection from multiple OSINT sources"},
                    {"phase": 2, "name": "Data Normalization", "description": "Converting data to unified schema"},
                    {"phase": 3, "name": "Multi-Source Verification", "description": "Cross-referencing data across sources"},
                    {"phase": 4, "name": "AI-Powered Analysis", "description": "Machine learning threat assessment"},
                    {"phase": 5, "name": "Report Generation", "description": "Structured intelligence report creation"}
                ],
                "sources_queried": verified_data.get("sources_queried", 0),
                "normalization_records": verified_data.get("sources_queried", 0)
            },
            "findings": {
                "threat_indicators": analysis.get("indicators", {}),
                "corroborated_entities": analysis.get("corroborated_entities", {}),
                "timeline": analysis.get("timeline", []),
                "entity_relationships": analysis.get("entity_graph", {})
            },
            "risk_assessment": {
                "score": analysis.get("risk_score", 0),
                "level": analysis.get("threat_level", "UNKNOWN"),
                "reasoning": analysis.get("ai_reasoning", ""),
                "confidence_score": analysis.get("confidence", 0.5),
                "mitre_techniques": analysis.get("mitre_techniques", [])
            },
            "recommendations": analysis.get("recommendations", []),
            "raw_intelligence": [
                {
                    "source": r.get("source", ""),
                    "type": r.get("type", ""),
                    "timestamp": r.get("timestamp", ""),
                    "confidence": r.get("confidence", 0.5)
                } for r in verified_data.get("normalized_records", [])
            ]
        }
        return report
