"""Server-side exclusion settings (section 10).

The matching itself lives in :mod:`wadjet_schema.exclusions` so the agent and
the server can never disagree; this module turns the stored project settings
into the effective glob list.
"""

from __future__ import annotations

from wadjet_schema import DEFAULT_EXCLUSION_GLOBS


def effective_exclusion_globs(settings: dict[str, object]) -> list[str]:
    """The globs for a project: its stored scope, or the defaults."""
    scope = settings.get("scope")
    if isinstance(scope, dict):
        exclude = scope.get("exclude")
        if isinstance(exclude, list):
            return [str(glob) for glob in exclude]
    return list(DEFAULT_EXCLUSION_GLOBS)
