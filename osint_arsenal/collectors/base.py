import abc
import hashlib
import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class RawFinding(BaseModel):
    source_module: str
    collector_category: str
    target: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    payload: Dict[str, Any]
    evidence_sha256: str = ""

    def compute_hash(self):
        content = f"{self.source_module}:{self.target}:{str(sorted(self.payload.items()))}"
        self.evidence_sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()

class NormalizedFinding(BaseModel):
    id: str
    target: str
    target_type: str
    source_name: str
    category: str
    timestamp: str
    confidence: float
    threat_indicators: List[str] = []
    entities_discovered: List[Dict[str, str]] = []
    mitre_attack_ids: List[str] = []
    attributes: Dict[str, Any] = {}
    evidence_hash: str

class BaseCollector(abc.ABC):
    name: str = "BaseCollector"
    category: str = "surface"
    legal_class: str = "public"
    rate_limit: int = 10
    requires_key: bool = False

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    @abc.abstractmethod
    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        pass

    @abc.abstractmethod
    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        pass
