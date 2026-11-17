import abc
import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class ProviderStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NO_RESULT = "NO_RESULT"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    DISABLED = "DISABLED"

class InputType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    ORGANIZATION = "organization"
    HASH = "hash"
    PHONE = "phone"
    CRYPTO = "crypto"
    IMAGE = "image"
    DOCUMENT = "document"

class ProviderConfig(BaseModel):
    name: str
    website: str
    api_endpoint: str
    method: str = "GET"
    authentication: str = "none"  # "none" | "api_key" | "oauth"
    supported_inputs: List[InputType]
    enabled: bool = True

class RawProviderResponse(BaseModel):
    collection_id: str
    provider: str
    target: str
    input_type: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    status: ProviderStatus
    status_message: str = ""
    http_status_code: Optional[int] = None
    endpoint_queried: str = ""
    raw_response: Dict[str, Any] = {}

class BaseOSINTProvider(abc.ABC):
    name: str = ""
    website: str = ""
    api_endpoint: str = ""
    method: str = "GET"
    authentication: str = "none"
    supported_inputs: List[InputType] = []
    enabled: bool = True

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def can_process(self, input_type: InputType) -> bool:
        return self.enabled and input_type in self.supported_inputs

    def get_config(self) -> ProviderConfig:
        return ProviderConfig(
            name=self.name,
            website=self.website,
            api_endpoint=self.api_endpoint,
            method=self.method,
            authentication=self.authentication,
            supported_inputs=self.supported_inputs,
            enabled=self.enabled
        )

    @abc.abstractmethod
    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        pass

    @abc.abstractmethod
    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        pass
