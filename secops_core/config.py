"""Carregamento centralizado de configurações via variáveis de ambiente (SEC-01)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    """Configurações de execução local com valores default seguros.

    Os valores são lidos do ambiente no momento em que `Settings()` é instanciado
    (e não no import do módulo), para que alterações em variáveis de ambiente
    — ex.: testes com `monkeypatch.setenv` ou `.env` carregado depois — tenham efeito.
    """

    sqlite_db_path: Path = field(default_factory=lambda: Path(_env("SQLITE_DB_PATH", "data/secops.db")))
    logs_jsonl_path: Path = field(
        default_factory=lambda: Path(_env("LOGS_JSONL_PATH", "data/logs_simulados.jsonl"))
    )
    ollama_base_url: str = field(default_factory=lambda: _env("OLLAMA_BASE_URL", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "llama3.2"))
    api_base_url: str = field(default_factory=lambda: _env("API_BASE_URL", "http://localhost:8000"))
    zscore_threshold: float = field(default_factory=lambda: float(_env("ZSCORE_THRESHOLD", "3.0")))
    iforest_contamination: float = field(default_factory=lambda: float(_env("IFOREST_CONTAMINATION", "0.06")))


def get_settings() -> Settings:
    """Retorna instância imutável de configuração atual (relida do ambiente a cada chamada)."""
    return Settings()
