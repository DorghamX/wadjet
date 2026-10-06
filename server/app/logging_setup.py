"""Logging setup. Every line is filtered so no secret can reach a log sink."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from app.config import Settings, redact_text


class RedactingFilter(logging.Filter):
    """Replace known secrets in a record before it is formatted."""

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets = tuple(secret for secret in secrets if secret)

    def add_secrets(self, secrets: Iterable[str]) -> None:
        """Merge more secrets; handlers outlive a single settings object."""
        merged = list(self._secrets)
        for secret in secrets:
            if secret and secret not in merged:
                merged.append(secret)
        self._secrets = tuple(merged)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record must not break logging
            return True
        cleaned = redact_text(message, self._secrets)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


def configure_logging(settings: Settings) -> None:
    """Configure the root logger once, with redaction attached."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    redactor = RedactingFilter(settings.secrets)
    for log_handler in root.handlers:
        existing = next(
            (f for f in log_handler.filters if isinstance(f, RedactingFilter)),
            None,
        )
        if existing is None:
            log_handler.addFilter(redactor)
        else:
            existing.add_secrets(settings.secrets)
