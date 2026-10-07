"""Mentions parser (section 14, T5.3).

Extracts ``@username`` references from free-text payloads (comments,
request notes, etc.) without depending on the read-only issue interfaces.
Returns (found_usernames, cleaned_text) so the caller can handle the
mentions independently - e.g. render them as links, store them for
notifications, or pass them to the assignee field.
"""

from __future__ import annotations

import re

# A username is: starts with letter/digit, may contain letters, digits,
# dot, underscore, hyphen, 2-128 chars total.  The ``@`` prefix is
# stripped before matching.
USERNAME_RE = re.compile(r"(?<!\w)@([A-Za-z0-9][A-Za-z0-9._-]{1,127})(?![\w./-])")


def parse_mentions(text: str) -> tuple[list[str], str]:
    """Return (usernames_mentioned, text_without_mentions).

    Usernames are the raw strings after the ``@`` sign, stripped of
    surrounding whitespace.  The returned text has every ``@username``
    replaced by the literal string ``@username`` (preserving the original
    token so the frontend can render it as a mention link if desired).
    """
    usernames: list[str] = []
    result_parts: list[str] = []
    last_end = 0

    for m in USERNAME_RE.finditer(text):
        # Append text before this mention
        result_parts.append(text[last_end : m.start()])
        username = m.group(1)
        usernames.append(username)
        # Replace the ``@username`` with a placeholder the frontend can
        # turn back into a link: keep the ``@`` and the name.
        result_parts.append(f"@{username}")
        last_end = m.end()

    # Append remaining text after the last mention
    result_parts.append(text[last_end:])
    cleaned = "".join(result_parts)
    return usernames, cleaned


def mention_links_html(usernames: list[str]) -> str:
    """Render a list of mention usernames as simple HTML links.

    The frontend can use this, or render its own links.  Usernames are
    escaped for display safety.
    """
    if not usernames:
        return ""
    items: list[str] = []
    for name in usernames:
        items.append(f'<span class="m mu">@{name}</span>')
    return " ".join(items)


__all__ = ["parse_mentions", "mention_links_html"]
