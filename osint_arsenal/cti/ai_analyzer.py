import asyncio
import json
import datetime
import os
import re
from typing import Dict, Any, List

class AIAnalyzer:
    def __init__(self):
        self.model = None
        self._init_gemini()
    
    def _init_gemini(self):
        try:
            import google.generativeai as genai
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if api_key:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                self.gemini_available = True
            else:
                self.gemini_available = False
                self.model = None
        except ImportError:
            self.gemini_available = False
            self.model = None
    
    async def analyze(self, query: str, query_type: str, verified_data: Dict) -> Dict:
        # Calculate risk score based on data
        risk_score = self._calculate_risk_score(verified_data)
        threat_level = self._get_threat_level(risk_score)
        indicators = verified_data.get("confirmed_indicators", {})
        
        # Try AI analysis
        if self.gemini_available and self.model:
            ai_analysis = await self._gemini_analyze(query, query_type, verified_data, risk_score)
        else:
            ai_analysis = self._rule_based_analysis(query, query_type, verified_data, risk_score)
        
        return {
            "query": query,
            "query_type": query_type,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "confidence": verified_data.get("avg_confidence", 0.5),
            "sources_analyzed": verified_data.get("sources_queried", 0),
            "indicators": indicators,
            "corroborated_entities": verified_data.get("corroborated_entities", {}),
            "ai_assessment": ai_analysis.get("assessment", ""),
            "ai_reasoning": ai_analysis.get("reasoning", ""),
            "recommendations": ai_analysis.get("recommendations", []),
            "mitre_techniques": ai_analysis.get("mitre_techniques", []),
            "related_iocs": ai_analysis.get("related_iocs", []),
            "timeline": self._build_timeline(verified_data),
            "entity_graph": self._build_entity_graph(verified_data),
            "ai_powered": self.gemini_available,
            "analysis_timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    async def _gemini_analyze(self, query: str, query_type: str, verified_data: Dict, risk_score: int) -> Dict:
        try:
            # Prepare context for Gemini
            sources = [r.get("source", "") for r in verified_data.get("normalized_records", [])]
            indicators = verified_data.get("confirmed_indicators", {})
            entities = verified_data.get("corroborated_entities", {})
            
            prompt = f"""You are a Cyber Threat Intelligence analyst. Analyze this OSINT data and provide a structured assessment.

Target: {query}
Type: {query_type}
Risk Score: {risk_score}/100
Sources Queried: {', '.join(sources[:8])}
Confirmed Indicators: {json.dumps(indicators)}
Corroborated Entities: {json.dumps(list(entities.keys())[:10])}

Provide your analysis in this EXACT JSON format (no markdown, pure JSON):
{{
  "assessment": "2-3 sentence threat assessment summary",
  "reasoning": "Detailed explanation of why this risk level was assigned, referencing specific evidence",
  "recommendations": ["Action 1", "Action 2", "Action 3", "Action 4", "Action 5"],
  "mitre_techniques": ["T1566 - Phishing", "T1190 - Exploit Public-Facing Application"],
  "related_iocs": ["ioc1", "ioc2"],
  "next_investigation_steps": ["Step 1", "Step 2", "Step 3"]
}}"""
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.model.generate_content(prompt)
            )
            
            text = response.text.strip()
            # Extract JSON from response
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0].strip()
            elif '```' in text:
                text = text.split('```')[1].split('```')[0].strip()
            
            return json.loads(text)
        except Exception as e:
            return self._rule_based_analysis(query, query_type, verified_data, risk_score)
    
    def _rule_based_analysis(self, query: str, query_type: str, verified_data: Dict, risk_score: int) -> Dict:
        indicators = verified_data.get("confirmed_indicators", {})
        sources = verified_data.get("sources_queried", 0)
        
        # Build assessment
        if risk_score >= 75:
            assessment = f"HIGH RISK: The target '{query}' shows significant threat indicators across {sources} data sources. Immediate investigation recommended."
        elif risk_score >= 40:
            assessment = f"MEDIUM RISK: The target '{query}' has suspicious characteristics that warrant further investigation across {sources} queried sources."
        else:
            assessment = f"LOW RISK: Initial analysis of '{query}' across {sources} sources shows limited threat indicators. Standard monitoring recommended."
        
        reasoning_parts = [f"Analysis performed across {sources} OSINT sources."]
        if "MALICIOUS" in indicators:
            reasoning_parts.append("Malicious indicators detected in threat intelligence feeds.")
        if "BREACH" in indicators:
            reasoning_parts.append("Target appears in known data breach databases.")
        if "PHISHING" in indicators:
            reasoning_parts.append("Phishing-related indicators identified.")
        if "BOTNET" in indicators:
            reasoning_parts.append("Botnet-related activity patterns detected.")
        
        recommendations = [
            f"Monitor {query} for any changes in threat intelligence feeds",
            "Cross-reference findings with internal threat database",
            "Check for related infrastructure or associated entities",
            "Document findings and update incident tracking system",
            "Share IOCs with threat intelligence community if policy permits"
        ]
        
        if risk_score >= 75:
            recommendations.insert(0, f"URGENT: Block or restrict access to {query} immediately")
            recommendations.insert(1, "Initiate incident response procedure")
        
        return {
            "assessment": assessment,
            "reasoning": " ".join(reasoning_parts),
            "recommendations": recommendations[:6],
            "mitre_techniques": self._suggest_mitre(indicators),
            "related_iocs": list(verified_data.get("corroborated_entities", {}).keys())[:5],
            "next_investigation_steps": [
                "Expand search to related infrastructure",
                "Check historical DNS records",
                "Review certificate transparency logs",
                "Search for mentions in threat actor reports"
            ]
        }
    
    def _calculate_risk_score(self, verified_data: Dict) -> int:
        score = 0
        indicators = verified_data.get("confirmed_indicators", {})
        
        if "MALICIOUS" in indicators:
            score += 40 * indicators["MALICIOUS"]
        if "PHISHING" in indicators:
            score += 35 * indicators["PHISHING"]
        if "BOTNET" in indicators:
            score += 50 * indicators["BOTNET"]
        if "BREACH" in indicators:
            score += 25 * indicators["BREACH"]
        if "SPAM" in indicators:
            score += 15 * indicators["SPAM"]
        
        # Confidence-based adjustment
        avg_conf = verified_data.get("avg_confidence", 0.5)
        score = int(score * avg_conf)
        
        # Sources corroboration bonus
        corroborated = len(verified_data.get("corroborated_entities", {}))
        if corroborated > 3:
            score += 10
        
        return min(score, 100)
    
    def _get_threat_level(self, score: int) -> str:
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        if score >= 10: return "LOW"
        return "MINIMAL"
    
    def _suggest_mitre(self, indicators: Dict) -> List[str]:
        techniques = []
        if "PHISHING" in indicators:
            techniques.append("T1566 - Phishing")
            techniques.append("T1598 - Phishing for Information")
        if "MALICIOUS" in indicators:
            techniques.append("T1190 - Exploit Public-Facing Application")
            techniques.append("T1203 - Exploitation for Client Execution")
        if "BOTNET" in indicators:
            techniques.append("T1071 - Application Layer Protocol")
            techniques.append("T1573 - Encrypted Channel")
        if not techniques:
            techniques = ["T1589 - Gather Victim Identity Information", "T1591 - Gather Victim Org Information"]
        return techniques[:4]
    
    def _build_timeline(self, verified_data: Dict) -> List[Dict]:
        timeline = []
        for record in verified_data.get("normalized_records", []):
            timeline.append({
                "timestamp": record.get("timestamp", ""),
                "source": record.get("source", ""),
                "event": f"Data collected from {record.get('source', 'Unknown')}",
                "type": record.get("type", "unknown")
            })
        return sorted(timeline, key=lambda x: x["timestamp"])
    
    def _build_entity_graph(self, verified_data: Dict) -> Dict:
        nodes = []
        edges = []
        
        for record in verified_data.get("normalized_records", []):
            source_node = {"id": record.get("source", ""), "type": "source", "label": record.get("source", "")}
            if source_node not in nodes:
                nodes.append(source_node)
            
            for entity in record.get("entities", [])[:3]:
                entity_node = {"id": entity, "type": "entity", "label": entity}
                if entity_node not in nodes:
                    nodes.append(entity_node)
                edges.append({"from": record.get("source", ""), "to": entity, "type": "found_in"})
        
        return {"nodes": nodes[:20], "edges": edges[:30]}
