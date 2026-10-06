"""Scanner adapters (section 6). One file per tool."""

from __future__ import annotations

from .bandit import BanditAdapter
from .base import Adapter, AdapterInfo, RawOutput, RunContext
from .pip_audit import PipAuditAdapter

#: Every adapter the agent can run; T3.2/T3.3 add ruff and detect-secrets.
ADAPTERS: dict[str, Adapter] = {
    "bandit": BanditAdapter(),
    "pip_audit": PipAuditAdapter(),
}


def enabled_adapters(ctx: RunContext) -> list[Adapter]:
    """Adapters enabled for this run, in registry order."""
    return [adapter for adapter in ADAPTERS.values() if ctx.tool_enabled(adapter.name)]


__all__ = [
    "ADAPTERS",
    "Adapter",
    "AdapterInfo",
    "RawOutput",
    "RunContext",
    "enabled_adapters",
]
