"""
Vigil Guard SDK Type Definitions.

Public exports:
    - Enums: Decision, ThreatLevel, Source
    - Response models: DetectionResult, BatchResult, BatchItemResult
    - Branch models: HeuristicsBranch, SemanticBranch, PiiBranch, ContentModBranch, DetectionBranches
"""

from __future__ import annotations

from .branches import (
    ContentModBranch,
    ContentModCategoryResult,
    DetectionBranches,
    HeuristicsBranch,
    LlmGuardBranch,
    PiiBranch,
    SemanticBranch,
)
from .enums import Decision, Source, ThreatLevel
from .responses import (
    BatchItemError,
    BatchItemResult,
    BatchResult,
    DetectionResult,
    LanguageInfo,
    LicenseStatus,
)

__all__ = [
    # Enums
    "Decision",
    "ThreatLevel",
    "Source",
    # Response models
    "DetectionResult",
    "BatchResult",
    "BatchItemResult",
    "BatchItemError",
    # Branch models
    "DetectionBranches",
    "HeuristicsBranch",
    "SemanticBranch",
    "PiiBranch",
    "LlmGuardBranch",
    "ContentModBranch",
    "ContentModCategoryResult",
    # Other models
    "LanguageInfo",
    "LicenseStatus",
]
