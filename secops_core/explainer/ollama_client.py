"""Cliente de integração com Ollama local e fallback resiliente Jinja2 (SEC-10).

Envia prompts estruturados para a API local do Ollama (`POST /api/generate`) e,
caso o serviço local esteja desligado ou inacessível, aciona automaticamente o
Fallback Inteligente Jinja2 em português, garantindo custo zero e disponibilidade 100%.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

import httpx

from secops_core.config import get_settings
from secops_core.db import SecOpsDatabase
from secops_core.explainer.prompt_builder import (
    render_alert_prompt,
    render_fallback_explanation,
)

logger = logging.getLogger(__name__)


class OllamaExplainerClient:
    """Cliente HTTP resiliente para geração de explicações SecOps via Ollama ou Fallback Jinja2."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 6.0,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout_seconds = float(timeout_seconds)
        self._cached_online: Optional[bool] = None
        self._cache_timestamp: float = 0.0

    def check_health(self, use_cache: bool = False) -> Dict[str, Any]:
        """Verifica se o servidor Ollama local está ativo e lista modelos disponíveis."""
        now = time.monotonic()
        if use_cache and self._cached_online is not None and (now - self._cache_timestamp) < 15.0:
            return {
                "online": self._cached_online,
                "base_url": self.base_url,
                "configured_model": self.model,
                "available_models": [],
                "mode": "ollama_local" if self._cached_online else "jinja2_fallback",
            }

        try:
            with httpx.Client(timeout=0.8) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    payload = resp.json()
                    models = [m.get("name", "") for m in payload.get("models", [])]
                    self._cached_online = True
                    self._cache_timestamp = now
                    return {
                        "online": True,
                        "base_url": self.base_url,
                        "configured_model": self.model,
                        "available_models": models,
                        "mode": "ollama_local",
                    }
        except Exception as exc:
            logger.debug("Ollama local indisponível (%s): usando modo fallback Jinja2.", exc)

        self._cached_online = False
        self._cache_timestamp = now
        return {
            "online": False,
            "base_url": self.base_url,
            "configured_model": self.model,
            "available_models": [],
            "mode": "jinja2_fallback",
        }

    def explain_alert(self, alert_data: Dict[str, Any], force_fallback: bool = False) -> str:
        """Gera a explicação em linguagem simples via Ollama local ou Fallback Jinja2."""
        if force_fallback:
            return render_fallback_explanation(alert_data)

        health = self.check_health(use_cache=True)
        if not health["online"]:
            return render_fallback_explanation(alert_data)

        prompt = render_alert_prompt(alert_data)
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.2},
                    },
                )
                resp.raise_for_status()
                body = resp.json()
                text = str(body.get("response") or "").strip()
                if text:
                    return text
        except Exception as exc:
            self._cached_online = False
            self._cache_timestamp = time.monotonic()
            logger.info("Acionando fallback Jinja2 para event_id=%s (%s)", alert_data.get("event_id"), exc)

        return render_fallback_explanation(alert_data)

    def explain_and_persist(
        self,
        event_id: str,
        db: Optional[SecOpsDatabase] = None,
        force_fallback: bool = False,
    ) -> Optional[str]:
        """Busca o alerta no SQLite, gera a explicação e persiste na coluna ai_explanation."""
        target_db = db or SecOpsDatabase()
        record = target_db.get_by_event_id(event_id)
        if not record:
            return None

        explanation = self.explain_alert(record, force_fallback=force_fallback)
        target_db.update_ai_explanation(event_id, explanation)
        return explanation
