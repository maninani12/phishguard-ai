"""Deterministic PhishGuard agent layer (offline, no external LLM, no URL fetching)."""
from .agent import AGENT_NAME, AGENT_VERSION, analyze_url
from .explanation import CONFIDENCE_SEMANTICS, DISCLAIMER, RESEARCH_NOTICE

__all__ = ["analyze_url", "AGENT_NAME", "AGENT_VERSION",
           "CONFIDENCE_SEMANTICS", "DISCLAIMER", "RESEARCH_NOTICE"]
