"""Motor de regras determinísticas de segurança baseadas no AWS CloudTrail (SEC-07).

Implementa 6 regras modulares cobrindo escalação de privilégio IAM, sabotagem de
trilhas CloudTrail, uso de conta Root, força bruta em ConsoleLogin, rajadas de
acesso negado (AccessDenied/UnauthorizedOperation) e exposição pública de buckets S3.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List

from secops_core.lgms import LGMSRecord

IAM_ESCALATION_EVENTS = {
    "PutUserPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "AddUserToGroup",
    "UpdateAssumeRolePolicy",
}

TRAIL_TAMPERING_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
}

S3_PUBLIC_EXPOSURE_EVENTS = {
    "PutBucketAcl",
    "PutBucketPolicy",
    "DeletePublicAccessBlock",
    "PutBucketPublicAccessBlock",
}

UNAUTHORIZED_ERROR_CODES = {
    "AccessDenied",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "AccessDeniedException",
}


@dataclass(frozen=True)
class TriggeredRule:
    """Representa uma regra determinística CloudTrail violada por um evento."""

    rule_code: str
    rule_name: str
    severity: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


RuleEvaluator = Callable[[LGMSRecord], TriggeredRule | None]


def check_iam_privilege_escalation(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 1: Detecta alterações de permissões IAM sensíveis ou criação de chaves."""
    if rec.event_name in IAM_ESCALATION_EVENTS and rec.user_type != "Root":
        return TriggeredRule(
            rule_code="RULE_IAM_PRIVILEGE_ESCALATION",
            rule_name="Escalação de Privilégio IAM",
            severity="CRITICAL",
            reason=(
                f"Ação crítica de modificação IAM ({rec.event_name}) executada por "
                f"'{rec.user_name}' a partir do IP {rec.source_ip}."
            ),
        )
    return None


def check_trail_tampering(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 2: Detecta desativação, remoção ou alteração de trilhas de auditoria CloudTrail."""
    if rec.event_name in TRAIL_TAMPERING_EVENTS:
        return TriggeredRule(
            rule_code="RULE_TRAIL_TAMPERING",
            rule_name="Sabotagem de Auditoria CloudTrail",
            severity="CRITICAL",
            reason=(
                f"Tentativa de interromper ou modificar o rastreamento de auditoria "
                f"via '{rec.event_name}' no recurso '{rec.resource_arn}'."
            ),
        )
    return None


def check_root_activity(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 3: Detecta uso direto da conta Root da organização."""
    if rec.user_type.lower() == "root" or rec.user_name.lower() == "root":
        return TriggeredRule(
            rule_code="RULE_ROOT_ACTIVITY",
            rule_name="Uso Direto da Conta Root",
            severity="CRITICAL",
            reason=(
                f"Uso direto da identidade Root detectado no evento '{rec.event_name}' "
                f"(MFA={rec.mfa_authenticated}, IP={rec.source_ip})."
            ),
        )
    return None


def check_brute_force_console(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 4: Detecta múltiplas falhas de autenticação no ConsoleLogin."""
    is_failed_login = (
        rec.event_name == "ConsoleLogin"
        and (rec.status == "FAILURE" or rec.error_code == "FailedAuthentication")
        and rec.request_count >= 10
    )
    if is_failed_login:
        return TriggeredRule(
            rule_code="RULE_BRUTE_FORCE_CONSOLE",
            rule_name="Força Bruta em Login de Console",
            severity="HIGH",
            reason=(
                f"Rajada de {rec.request_count} falhas de autenticação em ConsoleLogin "
                f"para '{rec.user_name}' via IP {rec.source_ip}."
            ),
        )
    return None


def check_unauthorized_api_burst(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 5: Detecta varredura de recursos com rajadas de AccessDenied / UnauthorizedOperation."""
    if rec.error_code in UNAUTHORIZED_ERROR_CODES and rec.request_count >= 15:
        return TriggeredRule(
            rule_code="RULE_UNAUTHORIZED_API_BURST",
            rule_name="Rajada de Chamadas Não Autorizadas (Reconhecimento)",
            severity="HIGH",
            reason=(
                f"Detectadas {rec.request_count} chamadas negadas ({rec.error_code}) "
                f"no evento '{rec.event_name}' pelo usuário '{rec.user_name}'."
            ),
        )
    return None


def check_sensitive_s3_public_access(rec: LGMSRecord) -> TriggeredRule | None:
    """Regra 6: Detecta abertura de ACLs ou bloqueio público de buckets S3."""
    if rec.event_name in S3_PUBLIC_EXPOSURE_EVENTS:
        return TriggeredRule(
            rule_code="RULE_SENSITIVE_S3_PUBLIC_ACCESS",
            rule_name="Exposição Pública de Bucket S3 Sensível",
            severity="HIGH",
            reason=(
                f"Modificação de política/ACL de visibilidade pública S3 ('{rec.event_name}') "
                f"no bucket '{rec.resource_arn}'."
            ),
        )
    return None


DEFAULT_CLOUDTRAIL_RULES: List[RuleEvaluator] = [
    check_iam_privilege_escalation,
    check_trail_tampering,
    check_root_activity,
    check_brute_force_console,
    check_unauthorized_api_burst,
    check_sensitive_s3_public_access,
]


class CloudTrailRuleEngine:
    """Motor determinístico extensível para avaliação de regras AWS CloudTrail."""

    def __init__(self, rules: List[RuleEvaluator] | None = None) -> None:
        self.rules: List[RuleEvaluator] = list(rules) if rules is not None else list(DEFAULT_CLOUDTRAIL_RULES)

    def evaluate_record(self, rec: LGMSRecord) -> List[TriggeredRule]:
        """Avalia um único registro LGMS contra todas as regras ativas."""
        triggered: List[TriggeredRule] = []
        for rule_fn in self.rules:
            match = rule_fn(rec)
            if match is not None:
                triggered.append(match)
        return triggered

    def evaluate_batch(self, records: Iterable[LGMSRecord]) -> Dict[str, List[Dict[str, Any]]]:
        """Avalia um lote de registros retornando mapa event_id -> lista de regras acionadas."""
        results: Dict[str, List[Dict[str, Any]]] = {}
        for rec in records:
            matches = self.evaluate_record(rec)
            results[rec.event_id] = [m.to_dict() for m in matches]
        return results
