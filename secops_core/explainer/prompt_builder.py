"""Renderizador de templates Jinja2 para prompts e explicações de alertas SecOps (SEC-09)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_alert_prompt(alert_data: Dict[str, Any]) -> str:
    """Renderiza o prompt estruturado Jinja2 para envio ao LLM local (Ollama)."""
    env = _get_jinja_env()
    template = env.get_template("alert_explanation.j2")
    return template.render(alert=alert_data).strip()


def render_fallback_explanation(alert_data: Dict[str, Any]) -> str:
    """Renderiza a explicação determinística em português via template Jinja2 (modo fallback)."""
    env = _get_jinja_env()
    template = env.get_template("fallback_explanation.j2")
    return template.render(alert=alert_data).strip()
