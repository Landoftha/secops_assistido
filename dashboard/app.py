"""Painel Interativo Streamlit — SecOps Assistido por IA (SEC-13 / SEC-14).

Consome a API REST FastAPI (com fallback transparente para a camada de serviço local
caso o servidor uvicorn não esteja rodando em processo separado) para exibir:
1. Visão Executiva de KPIs, Séries Temporais e Distribuição de Anomalias (SEC-13)
2. Painel de Investigação de Alertas com Filtros e Explicações da IA Ollama/Jinja2 (SEC-14)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx
import pandas as pd
import streamlit as st

from secops_core.config import get_settings
from secops_core.db import SecOpsDatabase
from secops_core.explainer.ollama_client import OllamaExplainerClient
from secops_core.pipeline import run_detection_pipeline

st.set_page_config(
    page_title="SecOps Assistido por IA — Mãos na Tech",
    page_icon="🛡️",
    layout="wide",
)


def _api_base() -> str:
    return get_settings().api_base_url.rstrip("/")


def fetch_health() -> Dict[str, Any]:
    """Consulta /health na FastAPI ou usa fallback local transparente."""
    try:
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(f"{_api_base()}/health")
            if resp.status_code == 200:
                data = resp.json()
                data["api_online"] = True
                return data
    except Exception:
        pass

    db = SecOpsDatabase()
    stats = db.get_summary_stats()
    ollama = OllamaExplainerClient().check_health(use_cache=True)
    return {
        "status": "local_service",
        "api_online": False,
        "sqlite_connected": True,
        "sqlite_db_path": str(db.db_path),
        "total_logs_in_db": stats["total_logs"],
        "ollama": ollama,
    }


def fetch_stats() -> Dict[str, Any]:
    """Consulta /stats na FastAPI ou no banco SQLite local."""
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{_api_base()}/stats")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return SecOpsDatabase().get_summary_stats()


def fetch_logs(
    is_anomaly: Optional[bool] = None,
    severity: Optional[str] = None,
    event_name: Optional[str] = None,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    detector_type: Optional[str] = None,
    limit: int = 1500,
) -> List[Dict[str, Any]]:
    """Consulta /logs na FastAPI ou no banco SQLite local."""
    params: Dict[str, Any] = {"limit": limit, "offset": 0}
    if is_anomaly is not None:
        params["is_anomaly"] = is_anomaly
    if severity:
        params["severity"] = severity
    if event_name:
        params["event_name"] = event_name
    if user:
        params["user"] = user
    if source_ip:
        params["source_ip"] = source_ip
    if detector_type:
        params["detector_type"] = detector_type

    try:
        with httpx.Client(timeout=2.5) as client:
            resp = client.get(f"{_api_base()}/logs", params=params)
            if resp.status_code == 200:
                return resp.json().get("items", [])
    except Exception:
        pass

    return SecOpsDatabase().query_logs(
        is_anomaly=is_anomaly,
        severity=severity,
        event_name=event_name,
        user_name=user,
        source_ip=source_ip,
        detector_type=detector_type,
        limit=limit,
    )


def trigger_pipeline_execution(
    regenerate_logs: bool,
    total_records: int,
    anomaly_rate: float,
    seed: int,
) -> Dict[str, Any]:
    """Aciona POST /pipeline/run na FastAPI ou executa localmente."""
    payload = {
        "regenerate_logs": regenerate_logs,
        "total_records": total_records,
        "anomaly_rate": anomaly_rate,
        "seed": seed,
        "generate_explanations": True,
    }
    try:
        with httpx.Client(timeout=25.0) as client:
            resp = client.post(f"{_api_base()}/pipeline/run", json=payload)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass

    return run_detection_pipeline(
        regenerate_logs=regenerate_logs,
        total_records=total_records,
        anomaly_rate=anomaly_rate,
        seed=seed,
        generate_explanations=True,
    )


def trigger_explain_alert(event_id: str) -> str:
    """Aciona POST /anomalies/{event_id}/explain na FastAPI ou localmente."""
    try:
        with httpx.Client(timeout=12.0) as client:
            resp = client.post(f"{_api_base()}/anomalies/{event_id}/explain")
            if resp.status_code == 200:
                return resp.json().get("ai_explanation", "")
    except Exception:
        pass

    explainer = OllamaExplainerClient()
    return explainer.explain_and_persist(event_id) or "Explicação indisponível."


def main() -> None:
    st.title("🛡️ SecOps Assistido por IA — Painel de Monitoramento & Investigação")
    st.caption(
        "Pipeline Local a Custo Zero (Mãos na Tech) • JSONL ➔ LGMS ➔ Z-Score + Isolation Forest + Regras CloudTrail ➔ Ollama/Jinja2 ➔ SQLite ➔ FastAPI ➔ Streamlit"
    )

    health = fetch_health()
    stats = fetch_stats()

    # Garante que o banco esteja populado no primeiro acesso
    if stats.get("total_logs", 0) == 0:
        with st.spinner("Inicializando base SQLite e executando detecção híbrida..."):
            trigger_pipeline_execution(regenerate_logs=False, total_records=1500, anomaly_rate=0.06, seed=42)
            stats = fetch_stats()
            health = fetch_health()

    # Barra Lateral: Simulação e Orquestração (SEC-13)
    with st.sidebar:
        st.header("⚙️ Orquestração do Pipeline")
        st.markdown(
            f"**Backend FastAPI:** {'🟢 Online' if health.get('api_online') else '🟡 Modo Serviço Local'}\n\n"
            f"**Banco SQLite:** `{health.get('sqlite_db_path', 'data/secops.db')}`\n\n"
            f"**Motor IA:** `{health.get('ollama', {}).get('mode', 'jinja2_fallback')}`"
        )
        st.divider()
        regen = st.checkbox("Regenerar logs sintéticos (JSONL)", value=False)
        rec_count = st.slider("Total de eventos", min_value=200, max_value=5000, value=1500, step=100)
        anom_rate = st.slider("Taxa de anomalia injetada", min_value=0.02, max_value=0.20, value=0.06, step=0.01)
        seed_val = st.number_input("Seed aleatória", min_value=1, max_value=99999, value=42)

        if st.button("🚀 Executar Pipeline SecOps", use_container_width=True, type="primary"):
            with st.spinner("Processando logs com Z-Score, Isolation Forest, Regras CloudTrail e IA..."):
                res = trigger_pipeline_execution(regen, int(rec_count), float(anom_rate), int(seed_val))
                st.success(
                    f"Concluído em {res.get('elapsed_ms')} ms! "
                    f"{res.get('anomalies_detected')} anomalias detectadas."
                )
                st.rerun()

    # Cards de KPIs Executivos (SEC-13)
    by_sev = stats.get("by_severity", {})
    crit_high = int(by_sev.get("CRITICAL", 0)) + int(by_sev.get("HIGH", 0))
    ollama_mode_label = (
        "Ollama Ativo" if health.get("ollama", {}).get("online") else "Fallback Jinja2 Ativo"
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total de Logs Analisados", f"{stats.get('total_logs', 0):,}")
    col2.metric("Total de Anomalias", f"{stats.get('total_anomalies', 0):,}")
    col3.metric("% de Anomalias", f"{stats.get('anomaly_rate', 0.0) * 100:.2f}%")
    col4.metric("Alertas Críticos / Altos", f"{crit_high:,}", delta=f"{by_sev.get('CRITICAL', 0)} CRITICAL", delta_color="inverse")
    col5.metric("Status do Motor IA", ollama_mode_label)

    st.divider()

    tab_exec, tab_invest = st.tabs(
        ["📊 1. Visão Executiva & Séries Temporais (SEC-13)", "🔍 2. Investigação de Alertas & Explicações IA (SEC-14)"]
    )

    with tab_exec:
        all_logs = fetch_logs(limit=2000)
        if all_logs:
            df_all = pd.DataFrame(all_logs)
            df_all["ts_parsed"] = pd.to_datetime(df_all["timestamp"], errors="coerce")
            df_all["bucket_4h"] = df_all["ts_parsed"].dt.floor("4h")

            st.subheader("📈 Série Temporal: Eventos Normais vs. Anômalos (Janelas de 4h)")
            ts_pivot = (
                df_all.groupby(["bucket_4h", "is_anomaly"])
                .size()
                .unstack(fill_value=0)
                .rename(columns={False: "Tráfego Normal", True: "Anomalias Detectadas"})
            )
            st.area_chart(ts_pivot)

        c_left, c_mid, c_right = st.columns(3)
        with c_left:
            st.subheader("🚨 Alertas por Severidade")
            sev_df = pd.DataFrame(
                [
                    {"Severidade": k, "Quantidade": v}
                    for k, v in stats.get("by_severity", {}).items()
                ]
            ).set_index("Severidade")
            st.bar_chart(sev_df)

        with c_mid:
            st.subheader("🧠 Detecções por Método (`secops_core`)")
            det_map = stats.get("by_detector", {})
            det_df = pd.DataFrame(
                [
                    {"Método": "Z-Score (Estatístico)", "Alertas": det_map.get("zscore", 0)},
                    {"Método": "Isolation Forest (ML)", "Alertas": det_map.get("isolation_forest", 0)},
                    {"Método": "Regras CloudTrail", "Alertas": det_map.get("cloudtrail_rules", 0)},
                ]
            ).set_index("Método")
            st.bar_chart(det_df)

        with c_right:
            st.subheader("🌐 Top 5 IPs e Eventos com Anomalias")
            top_ips_df = pd.DataFrame(stats.get("top_suspicious_ips", []))
            top_ev_df = pd.DataFrame(stats.get("top_anomalous_events", []))
            if not top_ips_df.empty:
                st.markdown("**Top IPs Suspeitos:**")
                st.dataframe(top_ips_df, use_container_width=True, hide_index=True)
            if not top_ev_df.empty:
                st.markdown("**Top Eventos Anômalos:**")
                st.dataframe(top_ev_df, use_container_width=True, hide_index=True)

    with tab_invest:
        st.subheader("🔎 Filtros de Investigação SecOps")
        f1, f2, f3, f4 = st.columns(4)
        sev_filter = f1.selectbox("Severidade", ["TODAS", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        det_filter = f2.selectbox(
            "Detector que Sinalizou",
            ["TODOS", "ZSCORE", "IFOREST", "CLOUDTRAIL"],
        )
        ev_filter = f3.text_input("Filtrar por Evento (ex: ConsoleLogin, StopLogging)", value="")
        user_or_ip = f4.text_input("Filtrar por Usuário AWS", value="")

        anomalies = fetch_logs(
            is_anomaly=True,
            severity=None if sev_filter == "TODAS" else sev_filter,
            detector_type=None if det_filter == "TODOS" else det_filter,
            event_name=ev_filter.strip() or None,
            user=user_or_ip.strip() or None,
            limit=500,
        )

        st.markdown(f"**{len(anomalies)} alertas encontrados** com os filtros selecionados.")

        if not anomalies:
            st.info("Nenhuma anomalia encontrada para a combinação de filtros atual.")
        else:
            df_anom = pd.DataFrame(anomalies)
            display_cols = [
                "event_id",
                "timestamp",
                "final_severity",
                "event_name",
                "user_name",
                "source_ip",
                "aws_region",
                "request_count",
                "bytes_transferred",
                "zscore_value",
                "iforest_score",
                "is_cloudtrail_anomaly",
            ]
            st.dataframe(
                df_anom[display_cols],
                use_container_width=True,
                hide_index=True,
            )

            st.divider()
            options_map = {
                f"[{a['final_severity']}] {a['timestamp']} | {a['event_name']} | user={a['user_name']} | ip={a['source_ip']} ({a['event_id'][:8]})": a
                for a in anomalies
            }
            selected_label = st.selectbox(
                "Selecione um alerta para inspeção detalhada e explicação da IA:",
                list(options_map.keys()),
            )
            selected_alert = options_map[selected_label]

            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Severidade Consolidada", selected_alert["final_severity"])
            b2.metric(
                "Z-Score Estatístico",
                f"{selected_alert['zscore_value']:.2f}",
                delta="Anômalo" if selected_alert["is_zscore_anomaly"] else "Normal",
                delta_color="inverse" if selected_alert["is_zscore_anomaly"] else "off",
            )
            b3.metric(
                "Isolation Forest Score",
                f"{selected_alert['iforest_score']:.4f}",
                delta="Anômalo (-1)" if selected_alert["is_iforest_anomaly"] else "Normal (1)",
                delta_color="inverse" if selected_alert["is_iforest_anomaly"] else "off",
            )
            rules_list = selected_alert.get("cloudtrail_rules_triggered", [])
            b4.metric("Regras CloudTrail Violadas", len(rules_list))

            if rules_list:
                for r in rules_list:
                    st.warning(
                        f"**[{r.get('severity')}] `{r.get('rule_code')}` — {r.get('rule_name')}:** {r.get('reason')}"
                    )

            st.markdown("### 🤖 Explicação do Alerta em Linguagem Simples (Ollama / Jinja2)")
            if st.button("🔄 Regenerar Explicação com IA", key=f"regen_{selected_alert['event_id']}"):
                with st.spinner("Consultando motor de explicação IA (Ollama / Fallback Jinja2)..."):
                    updated_text = trigger_explain_alert(selected_alert["event_id"])
                    selected_alert["ai_explanation"] = updated_text
                    st.success("Explicação atualizada com sucesso no SQLite!")

            explanation_md = selected_alert.get("ai_explanation")
            if not explanation_md:
                explanation_md = trigger_explain_alert(selected_alert["event_id"])
            st.info(explanation_md)

            with st.expander("📄 Visualizar JSON Normalizado (Modelo Canônico LGMS)"):
                st.code(json.dumps(selected_alert, indent=2, ensure_ascii=False), language="json")


if __name__ == "__main__":
    main()
