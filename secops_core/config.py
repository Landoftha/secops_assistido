"""Carregamento centralizado de configurações via variáveis de ambiente (SEC-01)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Configurações de execução local com valores default seguros."""

    sqlite_db_path: Path = Path(os.getenv("SQLITE_DB_PATH", "data/secops.db"))
    logs_jsonl_path: Path = Path(os.getenv("LOGS_JSONL_PATH", "data/logs_simulados.jsonl"))
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    api_base_url: str = os.getenv("API_BASE_URL", "http://localhost:8000")
    zscore_threshold: float = float(os.getenv("ZSCORE_THRESHOLD", "3.0"))
    iforest_contamination: float = float(os.getenv("IFOREST_CONTAMINATION", "0.06"))


def get_settings() -> Settings:
    """Retorna instância imutável de configuração atual."""
    return Settings()
