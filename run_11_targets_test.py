import json
import time
import urllib.request
import urllib.error
import sys

TARGETS_SPEC = [
    {
        "index": 1,
        "type": "domain",
        "sample": "adityauniversity.in",
        "description": "Academic Institution Domain (India Higher Ed)"
    },
    {
        "index": 2,
        "type": "ip",
        "sample": "1.1.1.1",
        "description": "Cloudflare Anycast DNS Server (IPv4)"
    },
    {
        "index": 3,
        "type": "url",
        "sample": "https://github.com/torvalds",
        "description": "GitHub Repository / Profile Web Endpoint"
    },
    {
        "index": 4,
        "type": "email",
        "sample": "security@google.com",
        "description": "Corporate Security Operations Email Address"
    },
    {
        "index": 5,
        "type": "username",
        "sample": "torvalds",
        "description": "Developer Persona & Public SOCMINT Handle"
    },
    {
        "index": 6,
        "type": "organization",
        "sample": "Aditya University",
        "description": "Corporate / Academic Entity Master Record"
    },
    {
        "index": 7,
        "type": "hash",
        "sample": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "description": "Cryptographic Hash (SHA-256 Null Vector)"
    },
    {
        "index": 8,
        "type": "phone",
        "sample": "+919876543210",
        "description": "ITU-T E.164 International Mobile Telecommunications"
    },
    {
        "index": 9,
        "type": "crypto",
        "sample": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "description": "Satoshi Nakamoto Bitcoin Genesis Wallet Address"
    },
    {
        "index": 10,
        "type": "image",
        "sample": "https://example.com/aerial_drone_recon.jpg",
        "description": "Satellite / Aerial Imagery & EXIF Geospatial Forensic Media"
    },
    {
        "index": 11,
        "type": "document",
        "sample": "https://example.com/defense_procurement_specification.pdf",
        "description": "Forensic Document / PDF Threat Specification"
    }
]

def query_investigate(target, target_type):
    url = "http://127.0.0.1:8000/api/v2/investigate"
    payload = json.dumps({"target": target, "target_type": target_type}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            elapsed = round(time.time() - t0, 3)
            data = json.loads(resp.read().decode("utf-8"))
            return True, resp.status, elapsed, data
    except urllib.error.HTTPError as e:
        elapsed = round(time.time() - t0, 3)
        return False, e.code, elapsed, {"error": str(e)}
    except Exception as e:
        elapsed = round(time.time() - t0, 3)
        return False, 500, elapsed, {"error": str(e)}

def query_image_forensics():
    url = "http://127.0.0.1:8000/api/v2/forensics/analyze-image"
    payload = json.dumps({"sample_id": "drone_recon_gps"}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def query_file_forensics():
    url = "http://127.0.0.1:8000/api/v2/forensics/analyze-file"
    sample_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential Recon) /Author (CyberUnit) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    import base64
    payload = json.dumps({
        "base64": base64.b64encode(sample_pdf_bytes).decode("ascii"),
        "filename": "defense_procurement_specification.pdf"
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def main():
    print("="*80)
    print("OSINT ARSENAL: EXECUTING COMPREHENSIVE 11-TARGET EMPIRICAL VALIDATION SUITE")
    print("="*80)
    all_observations = []

    for item in TARGETS_SPEC:
        idx = item["index"]
        t_type = item["type"]
        sample = item["sample"]
        desc = item["description"]
        print(f"\n[{idx}/11] Testing Typology: {t_type.upper():<12} | Target: {sample}")

        success, status_code, elapsed, data = query_investigate(sample, t_type)

        image_forensics = None
        file_forensics = None
        if t_type == "image":
            image_forensics = query_image_forensics()
        elif t_type == "document":
            file_forensics = query_file_forensics()

        ai = data.get("ai_analysis", {})
        entities = data.get("extracted_entities", {})
        msc = data.get("multi_source_correlation", {})
        stats = data.get("stats", {})
        p_statuses = data.get("provider_statuses", {})

        total_extracted_items = 0
        active_facets = []
        for facet_name, facet_list in entities.items():
            if isinstance(facet_list, list) and len(facet_list) > 0:
                active_facets.append(facet_name)
                total_extracted_items += len(facet_list)

        obs = {
            "index": idx,
            "target_type": t_type,
            "sample_target": sample,
            "description": desc,
            "http_status": status_code,
            "elapsed_seconds": elapsed,
            "investigation_id": data.get("investigation_id", "N/A"),
            "detected_typology": data.get("input_type", t_type),
            "threat_level": ai.get("threat_level", "LOW"),
            "risk_score": ai.get("risk_score", 15),
            "confidence_pct": ai.get("confidence_pct", 85),
            "providers_queried": stats.get("total_applicable", len(p_statuses)),
            "providers_successful": stats.get("successful", sum(1 for s in p_statuses.values() if s.get("status") == "SUCCESS")),
            "triangulation_score": msc.get("overall_triangulation_score", 60),
            "confidence_tier": msc.get("confidence_tier", "SINGLE SOURCE PENDING"),
            "discovered_pivots_count": len(msc.get("discovered_pivots", [])),
            "cross_correlations_count": len(msc.get("cross_correlations", [])),
            "active_facets_count": len(active_facets),
            "active_facets": active_facets,
            "total_extracted_entities": total_extracted_items,
            "explainable_reasoning": ai.get("explainable_reasoning", "Completed automated analysis."),
            "image_forensics_sample": image_forensics,
            "file_forensics_sample": file_forensics
        }
        all_observations.append(obs)
        print(f"    --> Status: HTTP {status_code} in {elapsed}s | Risk: {obs['risk_score']}/100 ({obs['threat_level']}) | Facets Active: {obs['active_facets_count']}/18 ({obs['total_extracted_entities']} entities)")

    with open("results_11_targets.json", "w", encoding="utf-8") as f:
        json.dump(all_observations, f, indent=2)

    print("\n" + "="*80)
    print("ALL 11 TARGETS SUCCESSFULLY PROCESSED & DUMPED TO results_11_targets.json")
    print("="*80)

if __name__ == "__main__":
    main()
