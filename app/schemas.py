"""Pydantic schemas and dataclass compatibility layer for request validation and structured scan output."""

from enum import Enum
import json
from typing import List, Optional, Dict, Any

try:
    from pydantic import BaseModel as _PydanticBaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

    def Field(default=None, default_factory=None, **kwargs):
        if default_factory is not None:
            return default_factory()
        return default

    class _PydanticBaseModel:
        def __init__(self, **kwargs):
            # Apply class defaults
            for k, v in self.__class__.__dict__.items():
                if not k.startswith("_") and not callable(v):
                    setattr(self, k, v)
            # Apply passed kwargs
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            res = {}
            for k, v in self.__dict__.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, _PydanticBaseModel):
                    res[k] = v.model_dump()
                elif isinstance(v, list):
                    res[k] = [item.model_dump() if isinstance(item, _PydanticBaseModel) else (item.value if isinstance(item, Enum) else item) for item in v]
                elif isinstance(v, Enum):
                    res[k] = v.value
                else:
                    res[k] = v
            return res

        def model_dump_json(self) -> str:
            return json.dumps(self.model_dump(), default=str)

        def __repr__(self):
            return f"{self.__class__.__name__}({self.model_dump()})"


class BaseModel(_PydanticBaseModel):
    """Base schema class supporting both Pydantic and stdlib fallback."""
    pass


class FindingStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    INFO = "INFO"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScanRequest(BaseModel):
    """Scan request payload."""
    url: str = Field(..., description="Target website URL to analyze (must be authorized).", examples=["https://example.com"])


class RedirectHop(BaseModel):
    """Information regarding a single redirect in the request chain."""
    step: int = 1
    url: str = ""
    status_code: int = 200
    location: Optional[str] = None


class CookieFinding(BaseModel):
    """Analyzed cookie metadata without revealing sensitive cookie values."""
    name: str = ""
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = "None"
    path: Optional[str] = "/"
    domain: Optional[str] = None
    expires_or_max_age: Optional[str] = None
    status: FindingStatus = FindingStatus.PASS
    severity: FindingSeverity = FindingSeverity.INFO
    notes: List[str] = Field(default_factory=list)


class HeaderFinding(BaseModel):
    """Detailed evaluation finding for a specific security header."""
    header: str = ""
    status: FindingStatus = FindingStatus.INFO
    severity: FindingSeverity = FindingSeverity.INFO
    value: Optional[str] = None
    message: str = ""
    recommendation: str = ""
    score_contribution: int = 0
    max_score_contribution: int = 0


class ScoringRule(BaseModel):
    """Information on how points are assigned for each checked header."""
    header: str = ""
    allocated_points: int = 0
    description: str = ""


class ScanResponse(BaseModel):
    """Complete scan response structure."""
    id: str = ""
    target: str = ""
    final_url: str = ""
    timestamp: str = ""
    status_code: int = 200
    is_https: bool = False
    score: int = 0
    max_score: int = 11
    score_percentage: float = 0.0
    redirect_count: int = 0
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    findings: List[HeaderFinding] = Field(default_factory=list)
    cookies: List[CookieFinding] = Field(default_factory=list)
    raw_headers: Dict[str, str] = Field(default_factory=dict)
    scoring_methodology: List[ScoringRule] = Field(default_factory=list)
    disclaimer: str = (
        "This score is a measurement of the checked HTTP security header configurations and cookie flags, "
        "not a definitive evaluation of overall application security or server posture."
    )


class ScanSummary(BaseModel):
    """Abbreviated summary for scan history listing."""
    id: str = ""
    original_url: str = ""
    final_url: str = ""
    timestamp: str = ""
    status_code: int = 200
    score: int = 0
    max_score: int = 11
    is_https: bool = False
