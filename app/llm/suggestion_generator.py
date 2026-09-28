import os
from typing import Optional

import httpx
import structlog

_logger = structlog.get_logger(__name__)

_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_MAX_TOKENS = 200

_SYSTEM_PROMPT = (
    "Eres un revisor de código de seguridad. Dado un hallazgo detectado por una regla "
    "de análisis estático, escribe UNA sola sugerencia de remediación en español, breve "
    "(máximo 2 frases), concreta y específica al fragmento de código mostrado: menciona "
    "la librería, función, algoritmo o clave de configuración real que aplicaría -- igual "
    "de específica que el ejemplo de estilo, nunca genérica tipo 'siga buenas prácticas'. "
    "No repitas el fragmento de código. No inventes hechos sobre el proyecto que no "
    "puedas inferir del fragmento. Responde solo con la sugerencia, sin preámbulo."
)


def is_enabled() -> bool:
    return os.environ.get("LLM_SUGGESTIONS_ENABLED", "false").strip().lower() == "true"


async def generate_suggestion(
    *,
    category: str,
    cwe_id: Optional[str],
    evidence_snippet: str,
    style_example: Optional[str],
) -> Optional[str]:
    """
    Best-effort enrichment of a finding's suggestedAction using an LLM.
    Called once per rule execution (not once per match) by the caller.

    Returns None on ANY failure -- missing/invalid API key, timeout, non-200
    response, unexpected payload shape -- so the existing static-text
    fallback in Rule.payload.suggestedAction (applied Java-side) takes over
    exactly as it does today. This function must never raise: a flaky LLM
    call must never be able to break rule execution.
    """
    if not is_enabled():
        return None

    api_key = os.environ.get("LLM_API_KEY", "")
    if not api_key:
        _logger.warning("llm_suggestion_skipped_no_api_key")
        return None

    model = os.environ.get("LLM_MODEL", "claude-haiku-4-5-20251001")
    try:
        timeout = float(os.environ.get("LLM_TIMEOUT_SECONDS", "8"))
    except ValueError:
        timeout = 8.0

    user_content = (
        f"Categoría: {category}\n"
        f"CWE: {cwe_id or 'N/A'}\n"
        f"Fragmento detectado:\n{evidence_snippet}\n"
    )
    if style_example:
        user_content += f"\nEjemplo de estilo esperado (de otra regla ya existente):\n{style_example}\n"

    try:
        async with httpx.AsyncClient(timeout=timeout) as http_client:
            response = await http_client.post(
                _API_URL,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": _MAX_TOKENS,
                    "system": _SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_content}],
                },
            )
        if response.status_code != 200:
            _logger.warning("llm_suggestion_failed", status=response.status_code)
            return None

        data = response.json()
        blocks = data.get("content", [])
        text = "".join(
            block.get("text", "") for block in blocks if block.get("type") == "text"
        ).strip()
        return text or None
    except Exception as exc:  # noqa: BLE001 -- must never propagate, see docstring
        _logger.warning("llm_suggestion_error", error=str(exc))
        return None
