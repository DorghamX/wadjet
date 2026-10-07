"""The inbox page (section 14, ``/inbox``): what waits on you, what you
asked, and the notes about both.

Three panels over the design's grid: **Waiting for you** carries the
sender's message in front of the decision and the same Approve/Decline
buttons the issue timeline shows - they post to the very same route,
with ``next=/inbox`` so the browser lands back here; **Requests you sent**
is the design's chip-per-outcome list; **Notifications** is section 14's
third inbox item, one line per pointer, unread marked as a word.

Every sentence is built from the *live* rows (``app.notifications`` only
stores who to tell and what about), so a request that changed state since
the notification was written reads correctly now - the same rule the
issue timeline follows.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Engine, bindparam, text

from app.issue_requests import REQUEST_ACTIONS
from app.notifications import mark_read, notifications_for
from app.projects import visible_projects
from app.web.issue_detail import _REQUEST_CHIPS
from app.web.routes import PageUser, render, require_page_user

router = APIRouter(include_in_schema=False)

#: What each action reads as in the sent panel - design copy
#: ("Accept risk on B506 in auth-service").
_ACTION_NOUNS = {
    "confirm": "Confirm",
    "false_positive": "False positive",
    "accepted_risk": "Accept risk",
    "wont_fix": "Won't fix",
    "fix_help": "Fix help",
    "other": "Other action",
}

#: The words around the linked title: action -> (verb, tail). Joined
#: with the issue title and project key they form the design's line:
#: "Omar asks you to mark Subprocess call with shell=True in payments-api
#: as a false positive."
_ASK_FORMS = {
    "confirm": ("confirm", ""),
    "false_positive": ("mark", "as a false positive"),
    "accepted_risk": ("accept the risk of", ""),
    "wont_fix": ("mark", "as won't fix"),
    "fix_help": ("help fix", ""),
    "other": ("act on", ""),
}

#: What each state reads as in the middle of a sentence.
_STATE_WORDS = {"approved": "approved", "declined": "declined", "cancelled": "cancelled"}

#: Every request the viewer touches - waiting, sent, and the ones behind
#: their notifications come from this one set of rows.
_INVOLVED_SQL = """
SELECT r.id, r.requested_action, r.message, r.state, r.created_at,
       r.requested_by, r.target_user_id, r.resolved_by,
       i.id AS issue_id, i.title, i.rule_id,
       p.key AS project_key,
       u.display_name AS requester_name, u.username AS requester_username,
       t.display_name AS target_name, t.username AS target_username,
       rv.display_name AS resolver_name, rv.username AS resolver_username
FROM issue_requests r
JOIN issues i ON i.id = r.issue_id
JOIN projects p ON p.id = i.project_id
JOIN users u ON u.id = r.requested_by
LEFT JOIN users t ON t.id = r.target_user_id
LEFT JOIN users rv ON rv.id = r.resolved_by
WHERE r.target_user_id = :me OR r.requested_by = :me
ORDER BY r.created_at DESC, r.id DESC
"""


def _who(display_name: Any, username: Any) -> str:
    return str(display_name or username or "Someone")


def _form(action: str) -> tuple[str, str, str]:
    """(permission-bound status or "", verb, tail) for one action."""
    status, _permission = REQUEST_ACTIONS.get(action, (None, None))
    verb, tail = _ASK_FORMS.get(action, _ASK_FORMS["other"])
    return (status or ""), verb, tail


def _tail(project_key: str, tail: str) -> str:
    """The part after the linked title: ' in payments as a false positive.'"""
    return f" in {project_key}{' ' + tail if tail else ''}."


def _sentence(row: dict[str, Any], viewer_id: int) -> dict[str, str]:
    """(subject, predicate, outro) around the linked title, from the
    viewer's side of the request - the design's waiting line is the
    'you are the target and it is pending' case of this one function."""
    action = str(row["requested_action"])
    _status, verb, tail = _form(action)
    out = _tail(str(row["project_key"]), tail)
    requester = _who(row["requester_name"], row["requester_username"])
    target = _who(row["target_name"], row["target_username"])
    resolver = _who(row["resolver_name"], row["resolver_username"])
    state = str(row["state"])
    word = _STATE_WORDS.get(state, state)

    if int(row["requested_by"]) == viewer_id:
        if state == "cancelled":
            return {
                "subject": "You",
                "predicate": f"cancelled your request to {verb}",
                "outro": out,
            }
        if state == "pending":
            return {
                "subject": "Your request",
                "predicate": f"to {verb}",
                "outro": f"{out[:-1]} is waiting for {target}.",
            }
        return {
            "subject": resolver,
            "predicate": f"{word} your request to {verb}",
            "outro": out,
        }
    if state == "pending":
        # The design's copy, verbatim: <b>Omar</b> asks you to mark ...
        return {"subject": requester, "predicate": f"asks you to {verb}", "outro": out}
    if state == "cancelled":
        return {
            "subject": requester,
            "predicate": f"cancelled the request to {verb}",
            "outro": out,
        }
    if row["resolved_by"] is not None and int(row["resolved_by"]) == viewer_id:
        return {
            "subject": "You",
            "predicate": f"{word} {requester}'s request to {verb}",
            "outro": out,
        }
    return {
        "subject": resolver,
        "predicate": f"{word} {requester}'s request to {verb}",
        "outro": out,
    }


def _entry(row: dict[str, Any], viewer_id: int) -> dict[str, Any]:
    """One sentence plus where its title links to."""
    sentence = _sentence(row, viewer_id)
    sentence.update(
        title=str(row["title"]),
        url=f"/projects/{row['project_key']}/issues/{row['issue_id']}",
    )
    return sentence


def _sent_line(row: dict[str, Any]) -> dict[str, str]:
    """One 'Accept risk on B506 in auth-service <chip>' line (design)."""
    action = str(row["requested_action"])
    chip, word = _REQUEST_CHIPS.get(str(row["state"]), ("nt", str(row["state"]).title()))
    return {
        "noun": _ACTION_NOUNS.get(action, "Other action"),
        "identifier": str(row["rule_id"] or row["title"]),
        "key": str(row["project_key"]),
        "chip": chip,
        "word": word,
    }


#: The comment behind a mention notification, with everything its line
#: needs. Deleted comments drop out; visibility is the caller's call.
_MENTION_SQL = """
SELECT c.id AS comment_id, i.id AS issue_id, i.title, p.key AS project_key,
       u.display_name AS author_name, u.username AS author_username
FROM issue_comments c
JOIN issues i ON i.id = c.issue_id
JOIN projects p ON p.id = i.project_id
JOIN users u ON u.id = c.author_id
WHERE c.deleted_at IS NULL AND c.id IN :ids
"""


def _mentioned_comments(engine: Engine, comment_ids: list[int]) -> dict[int, dict[str, Any]]:
    """The live comments behind this user's mention notifications."""
    if not comment_ids:
        return {}
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(_MENTION_SQL).bindparams(bindparam("ids", expanding=True)),
                {"ids": comment_ids},
            )
            .mappings()
            .all()
        )
    return {int(row["comment_id"]): dict(row) for row in rows}


def _mention_entry(row: dict[str, Any]) -> dict[str, Any]:
    """'{commenter} mentioned you on {title} in {key}.' - same shape as
    a request sentence, so the template renders both with one line."""
    return {
        "subject": _who(row["author_name"], row["author_username"]),
        "predicate": "mentioned you on",
        "outro": f" in {row['project_key']}.",
        "title": str(row["title"]),
        "url": f"/projects/{row['project_key']}/issues/{row['issue_id']}",
    }


def inbox_context(request: Request, user: PageUser) -> dict[str, Any]:
    """Everything the three panels render - one query's rows, three views."""
    engine = request.app.state.engine
    visible = {
        str(project["key"])
        for project in visible_projects(engine, user_id=user.id, is_admin=user.is_admin)
    }
    with engine.connect() as conn:
        involved = [
            dict(row) for row in conn.execute(text(_INVOLVED_SQL), {"me": user.id}).mappings().all()
        ]
    involved = [row for row in involved if str(row["project_key"]) in visible]
    by_id = {int(row["id"]): row for row in involved}

    waiting = []
    for row in involved:
        if int(row["target_user_id"] or -1) != user.id or str(row["state"]) != "pending":
            continue
        entry = _entry(row, user.id)
        status, _verb, _tail = _form(str(row["requested_action"]))
        entry.update(
            id=int(row["id"]),
            message=str(row["message"] or ""),
            approve_label="Approve and flag" if status else "Approve",
        )
        waiting.append(entry)

    sent = [_sent_line(row) for row in involved if int(row["requested_by"]) == user.id]

    notifications: list[dict[str, Any]] = []
    parsed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for note in notifications_for(engine, user_id=user.id):
        raw = note["ref"]
        ref: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else (raw or {})
        parsed.append((note, ref))
    mentions = _mentioned_comments(
        engine,
        [
            int(ref["comment"])
            for note, ref in parsed
            if str(note["type"]) == "mention" and ref.get("comment") is not None
        ],
    )
    for note, ref in parsed:
        if str(note["type"]) == "mention":
            source = mentions.get(int(ref.get("comment") or -1))
            if source is None or str(source["project_key"]) not in visible:
                continue  # comment deleted, or hidden with its project
            entry = _mention_entry(source)
        elif str(note["type"]) == "request":
            source = by_id.get(int(ref["request"])) if ref.get("request") is not None else None
            if source is None:  # the request is gone, or in a project since hidden
                continue
            entry = _entry(source, user.id)
        else:  # an unknown type: never render what cannot be read
            continue
        entry.update(id=int(note["id"]), read=note["read_at"] is not None)
        notifications.append(entry)

    unread = sum(1 for note in notifications if not note["read"])
    return {
        "nav": "inbox",
        "user": user,
        "waiting": waiting,
        "sent": sent,
        "notifications": notifications,
        "unread": unread,
    }


@router.get("/inbox")
def inbox_page(request: Request, user: PageUser = Depends(require_page_user)) -> HTMLResponse:
    """The design's /inbox: waiting, sent, and what you have not read."""
    return render(request, "inbox.html", context=inbox_context(request, user))


@router.post("/inbox/read")
def inbox_mark_all_read(
    request: Request, user: PageUser = Depends(require_page_user)
) -> RedirectResponse:
    """Mark every unread notification of this user and come back (PRG)."""
    mark_read(request.app.state.engine, user_id=user.id)
    return RedirectResponse("/inbox", status_code=303)


__all__ = ["inbox_context", "router"]
