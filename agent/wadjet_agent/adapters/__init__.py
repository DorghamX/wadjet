"""Scanner adapters (section 6). One file per tool."""

from __future__ import annotations

from .bandit import BanditAdapter
from .base import Adapter, AdapterInfo, RawOutput, RunContext
from .pip_audit import PipAuditAdapter
from .ruff import RuffAdapter

#: Every adapter the agent can run; T3.3 adds detect-secrets.
ADAPTERS: dict[str, Adapter] = {
    "bandit": BanditAdapter(),
    "pip_audit": PipAuditAdapter(),
    "ruff": RuffAdapter(),
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
