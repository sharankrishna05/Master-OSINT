import json
import uuid
import datetime
from typing import Dict, Any, List

class StixExporter:
    @staticmethod
    def generate_bundle(target: str, findings: List[Dict[str, Any]], ai_summary: Dict[str, Any]) -> str:
        bundle_id = f"bundle--{uuid.uuid4()}"
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        objects = []
        
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": "NOSTROMO-OSINT Full Spectrum Engine",
            "identity_class": "system"
        }
        objects.append(identity)

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"OSINT Target: {target}",
            "description": ai_summary.get("explainable_reasoning", "Automated threat intelligence capture"),
            "pattern": f"[{target.split('.')[0]}:value = '{target}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "confidence": int(ai_summary.get("risk_score", 50))
        }
        objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
        return json.dumps(bundle, indent=2)
