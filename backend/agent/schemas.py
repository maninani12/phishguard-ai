"""Pydantic response contract for the PhishGuard agent endpoint.

The label convention is the project's own, taken from the shipped model
metadata: ``label_mapping = {"1": "Legitimate", "0": "Potential Phishing"}``.
It is not assumed here; it is read from the model at runtime.
"""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class AgentSignal(BaseModel):
    code: str = Field(..., description="Stable machine-readable signal identifier.")
    label: str = Field(..., description="Short human-readable signal name.")
    value: Optional[float] = Field(None, description="The measured feature value that triggered it.")
    observation: str = Field(..., description="One factual sentence about the URL string.")
    risk_relevant: bool = Field(True, description="Whether the signal counts toward the phishing-style observations.")


class AgentModelInfo(BaseModel):
    name: str
    feature_count: int
    label_mapping: dict
    trained_on: str


class AgentResponse(BaseModel):
    url: str = Field(..., description="The URL exactly as submitted by the user.")
    normalized_url: str = Field(..., description="The canonical form the model actually scored.")
    prediction: str = Field(..., description="Human-readable class name for the predicted label.")
    label: int = Field(..., description="Project label. 1 = Legitimate, 0 = Potential Phishing.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Classifier score for the predicted class.")
    confidence_semantics: str = Field(..., description="What the confidence value does and does not mean.")
    risk_level: str = Field(..., description="Coarse presentation band derived from label and score.")
    explanation: List[str] = Field(..., description="Evidence-based sentences about the URL string.")
    signals: List[AgentSignal] = Field(default_factory=list, description="URL characteristics actually present.")
    training_distribution_gaps: List[str] = Field(default_factory=list,
                                                   description="Shapes underrepresented or absent in the training data.")
    recommendation: str = Field(..., description="The single most useful next action.")
    advisories: List[str] = Field(default_factory=list, description="Additional safe-handling advice.")
    disclaimer: str = Field(..., description="Scope limits of the analysis.")
    research_notice: str = Field(..., description="Research / demonstration status and dataset limitation.")
    website_visited: Literal[False] = Field(False, description="Always false. The agent never fetches the URL.")
    model: AgentModelInfo
    agent: str = Field(..., description="Agent identifier and version.")
