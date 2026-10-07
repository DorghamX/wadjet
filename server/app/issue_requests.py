"""The request-action workflow (section 8): ask, approve, decline, cancel.

Somebody who cannot flag an issue asks somebody who can. The answer lands
in two places: on the request itself (pending -> approved/declined/
cancelled, with who decided and an optional note) and, when it is "yes" to
a flag action, on the issue - applied *by the target*, with the requester's
message as the reason, so the timeline tells the truth about who decided
what and why.

The vocabulary is section 4's: ``confirm``, ``false_positive``,
``accepted_risk``, ``wont_fix``, ``fix_help``, ``other``. Only the first
four set a status; ``fix_help`` and ``other`` ask for a hand and their
target needs ``issue.assign`` instead of a flag (section 8).

No ``request_created`` / ``request_resolved`` events are written: the
timeline renders the live rows, where the current state (pending,
declined, the note) actually lives - an event copy would go stale the
moment somebody decides.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, text

from app.issues import (
    REASON_MAX,
    REASON_MIN,
    BadIssueAction,
    IssuePermissionDenied,
    load_issue,
    permission_holders,
    set_triage,
)
from app.permissions import Permission, can

#: Section 4's vocabulary: ``requested_action`` -> (the triage status an
#: approval would set, the permission the target must hold to give it).
REQUEST_ACTIONS: dict[str, tuple[str | None, Permission]] = {
    "confirm": ("confirmed", Permission.FLAG_CONFIRM),
    "false_positive": ("false_positive", Permission.FLAG_FALSE_POSITIVE),
    "accepted_risk": ("accepted_risk", Permission.FLAG_ACCEPTED_RISK),
    "wont_fix": ("wont_fix", Permission.FLAG_WONT_FIX),
    "fix_help": (None, Permission.ISSUE_ASSIGN),
    "other": (None, Permission.ISSUE_ASSIGN),
}

#: The message is required (section 8); its lengths follow the reason rule
#: so the message can be quoted straight into a triage reason on approval.
MESSAGE_MIN = REASON_MIN
MESSAGE_MAX = REASON_MAX

#: How a pending request may end (section 8).
RESOLUTIONS = ("approve", "decline", "cancel")

#: state -> how each resolution ends.
_RESOLVED_STATE = {"approve": "approved", "decline": "declined", "cancel": "cancelled"}


class RequestNotFound(LookupError):
    """Unknown id and a request you may not see share one answer (section 7)."""


def action_targets(
    engine: Engine, *, project_id: int, action: str, requester_id: int | None = None
) -> list[dict[str, Any]]:
    """Who may decide this action here: holders of its permission (section 8).

    The requester is never a target - asking yourself is not asking. An
    unknown action is a programming error, not a user error: the panel only
    ever offers vocabulary from ``REQUEST_ACTIONS``.
    """
    if action not in REQUEST_ACTIONS:
        raise BadIssueAction(
            f"Unknown requested action {action!r}; expected one of: {', '.join(REQUEST_ACTIONS)}"
        )
    _, permission = REQUEST_ACTIONS[action]
    holders = permission_holders(engine, project_id=project_id, permission=permission)
    if requester_id is None:
        return [dict(holder) for holder in holders]
    return [dict(holder) for holder in holders if int(holder["id"]) != requester_id]


def create_request(
    engine: Engine,
    *,
    issue: dict[str, Any],
    requested_action: str,
    target_user_id: int | None,
    message: str | None,
    actor_id: int,
) -> int:
    """Open a pending request against one issue (section 8).

    Everything is checked before the insert: the vocabulary, ``issue.request``
    for the asker, that they are not asking for a flag they could set
    themselves, a message of a real length, a target who exists and holds
    the permission the action needs and is not the asker, and no duplicate
    of a request already waiting for an answer. Either a request appears or
    nothing does.
    """
    project_id = int(issue["project_id"])
    entry = REQUEST_ACTIONS.get(requested_action)
    if entry is None:
        raise BadIssueAction(
            f"Unknown requested action {requested_action!r}; expected one of: "
            f"{', '.join(REQUEST_ACTIONS)}"
        )
    status, target_permission = entry
    if not can(engine, actor_id, Permission.ISSUE_REQUEST, project_id=project_id):
        raise IssuePermissionDenied("issue.request permission required.")
    if status is not None and can(engine, actor_id, target_permission, project_id=project_id):
        raise IssuePermissionDenied(
            f"You hold {target_permission.value} - set the status yourself."
        )
    cleaned = (message or "").strip()
    if len(cleaned) < MESSAGE_MIN:
        raise BadIssueAction(
            f"A message of at least {MESSAGE_MIN} characters is required - say what you saw."
        )
    if len(cleaned) > MESSAGE_MAX:
        raise BadIssueAction(f"A message may be at most {MESSAGE_MAX} characters.")
    if target_user_id is None:
        raise BadIssueAction("Pick somebody to ask.")
    if target_user_id == actor_id:
        raise BadIssueAction("You cannot ask yourself - pick somebody else.")
    # can() answers False for a person with no grant at all, which covers
    # "does not exist" without ever hinting at who exists elsewhere.
    if not can(engine, target_user_id, target_permission, project_id=project_id):
        raise BadIssueAction("That person does not hold the permission this action needs.")
    with engine.begin() as conn:
        pending = conn.execute(
            text(
                "SELECT id FROM issue_requests WHERE issue_id = :iid "
                "AND requested_action = :action AND target_user_id = :target "
                "AND state = 'pending'"
            ),
            {"iid": int(issue["id"]), "action": requested_action, "target": target_user_id},
        ).first()
        if pending is not None:
            raise BadIssueAction("That request is already waiting for an answer.")
        new_id = conn.execute(
            text(
                "INSERT INTO issue_requests "
                "(issue_id, requested_by, target_user_id, requested_action, message) "
                "VALUES (:iid, :by, :target, :action, :message) RETURNING id"
            ),
            {
                "iid": int(issue["id"]),
                "by": actor_id,
                "target": target_user_id,
                "action": requested_action,
                "message": cleaned,
            },
        ).scalar_one()
    return int(new_id)


def load_request(engine: Engine, *, request_id: int) -> dict[str, Any] | None:
    """One request with its issue, people and project key; ``None`` if unknown.

    Finding the row is not seeing it: callers still run ``project_key``
    through ``visible_project`` before answering.
    """
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT r.*, i.project_id, p.key AS project_key, "
                    "u.display_name AS requester_name, u.username AS requester_username, "
                    "t.display_name AS target_name, t.username AS target_username, "
                    "rv.display_name AS resolver_name, rv.username AS resolver_username "
                    "FROM issue_requests r "
                    "JOIN issues i ON i.id = r.issue_id "
                    "JOIN projects p ON p.id = i.project_id "
                    "JOIN users u ON u.id = r.requested_by "
                    "LEFT JOIN users t ON t.id = r.target_user_id "
                    "LEFT JOIN users rv ON rv.id = r.resolved_by "
                    "WHERE r.id = :rid"
                ),
                {"rid": request_id},
            )
            .mappings()
            .first()
        )
    return dict(row) if row else None


def resolve_request(
    engine: Engine,
    *,
    request: dict[str, Any],
    resolution: str,
    note: str | None,
    actor_id: int,
    ip: str | None = None,
) -> dict[str, Any]:
    """Approve, decline or cancel one pending request (section 8).

    Only the two people concerned may end it: the target decides (approve
    or decline), the requester cancels, and only while it is still pending.
    Approval of a flag action applies the flag as the target, quoting the
    requester's message as the reason; the note is optional, stored on the
    request, and shown next to the decision. The flag is applied first and
    the state second, so a failure in between leaves a request that can be
    approved again rather than a decision that never happened.
    """
    if resolution not in RESOLUTIONS:
        raise BadIssueAction(
            f"Unknown resolution {resolution!r}; expected one of: {', '.join(RESOLUTIONS)}"
        )
    state = str(request["state"])
    if state != "pending":
        raise BadIssueAction(f"This request was already {state}.")
    target = request["target_user_id"]
    if resolution == "cancel":
        if int(request["requested_by"]) != actor_id:
            raise IssuePermissionDenied("Only the person who asked may cancel a request.")
    elif target is None or int(target) != actor_id:
        raise IssuePermissionDenied("Only the person it was sent to may decide it.")
    cleaned_note = (note or "").strip() or None
    if cleaned_note and len(cleaned_note) > MESSAGE_MAX:
        raise BadIssueAction(f"A note may be at most {MESSAGE_MAX} characters.")
    entry = REQUEST_ACTIONS[str(request["requested_action"])]
    status, _target_permission = entry
    if resolution == "approve" and status is not None:
        issue = load_issue(
            engine, project_id=int(request["project_id"]), issue_id=int(request["issue_id"])
        )
        if issue is None:  # pragma: no cover - the request is on a real issue
            raise BadIssueAction("The issue this request is about is gone.")
        # set_triage re-checks the target's permission and the reason rules:
        # a target who has lost the flag since being asked is refused here,
        # exactly as anyone else would be - and the request stays pending.
        set_triage(
            engine,
            issue=issue,
            status=status,
            reason=str(request["message"] or ""),
            actor_id=actor_id,
            ip=ip,
        )
    with engine.begin() as conn:
        updated = conn.execute(
            text(
                "UPDATE issue_requests SET state = :state, resolved_by = :by, "
                "resolved_note = :note, resolved_at = now(), updated_at = now() "
                "WHERE id = :rid AND state = 'pending' RETURNING id"
            ),
            {
                "state": _RESOLVED_STATE[resolution],
                "by": actor_id,
                "note": cleaned_note,
                "rid": int(request["id"]),
            },
        ).scalar_one_or_none()
        if updated is None:  # pragma: no cover - decided between load and here
            raise BadIssueAction("This request is no longer waiting for an answer.")
    decided = load_request(engine, request_id=int(request["id"]))
    if decided is None:  # pragma: no cover - the row was just written
        raise RequestNotFound("No such request.")
    return decided


__all__ = [
    "MESSAGE_MAX",
    "MESSAGE_MIN",
    "REQUEST_ACTIONS",
    "RESOLUTIONS",
    "RequestNotFound",
    "action_targets",
    "create_request",
    "load_request",
    "resolve_request",
]
