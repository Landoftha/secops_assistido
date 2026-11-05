"""Subpacote de explicação de alertas via IA Local (Ollama + Jinja2)."""

from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.explainer.prompt_builder import (
    render_alert_prompt,
    render_fallback_explanation,
)

__all__ = [
    "OllamaExplainerClient",
    "render_alert_prompt",
    "render_fallback_explanation",
]
