#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Lifecycle audit (#7504): events written in the transaction that makes the change

Rows land in the auth_core inbox; the admin plugin in pylon_main drains them into the
partitioned audit table. Payloads carry raw facts only: the admin drainer (``events.normalize``)
is the one place that scrubs them and derives admin access and project type. Like revocation.py,
shared logic lives here as plain functions.
"""

import datetime
import uuid

from pylon.core.tools import log  # pylint: disable=E0401,E0611

from . import revocation

CTX_KEYS = ("actor_type", "actor_id", "actor_name", "actor_email", "source", "request_id")

SYSTEM_CTX = {"actor_type": "system", "actor_id": None, "actor_name": "System",
              "actor_email": None, "source": "system", "request_id": None}


class AuditWriteError(Exception):
    """ The inbox insert failed; the change itself is fine """


def actor(audit_ctx):
    """ The actor fields of an event; never guessed when the caller passed none """
    if not audit_ctx:
        log.warning("Lifecycle audit: no audit_ctx passed, actor recorded as unknown")
        return {key: None for key in CTX_KEYS} | {"actor_type": "unknown"}
    #
    result = {key: audit_ctx.get(key) for key in CTX_KEYS}
    result["actor_type"] = result["actor_type"] or "unknown"
    return result


def build(  # pylint: disable=R0913
        event_type, audit_ctx, scope, user=None, project_id=None,
        roles_before=None, roles_after=None, changes=None, details=None,
):
    """ One inbox payload """
    user = user or {}
    event = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "scope": scope,
        "result": "success",
        "failure_reason": None,
        "imported": False,
        "project_id": project_id,
        "user_id": user.get("id"),
        "user_name": user.get("name"),
        "user_email": user.get("email"),
        "roles_before": roles_before,
        "roles_after": roles_after,
        "admin_access": None,
        "changes": changes or {},
        "details": details or {},
    }
    event.update(actor(audit_ctx))
    return event


def membership_event(audit_ctx, project_id, user, before, after, details=None):
    """ Project role set before -> after as one event; None when unchanged """
    before, after = sorted(set(before)), sorted(set(after))
    if before == after:
        return None
    if not before:
        event_type = "project.member_added"
    elif not after:
        event_type = "project.member_removed"
    else:
        event_type = "project.member_role_changed"
    return build(
        event_type, audit_ctx, "project", user=user, project_id=project_id,
        roles_before=before, roles_after=after, details=details,
    )


def user_row(connection, db, user_id, for_update=False):
    """ id / name / email / suspended of one user, or None """
    tbl = db.tbl.user
    query = tbl.select().with_only_columns(
        tbl.c.id, tbl.c.name, tbl.c.email, tbl.c.suspended,
    ).where(tbl.c.id == user_id)
    if for_update:
        query = query.with_for_update()
    row = connection.execute(query).mappings().first()
    return None if row is None else dict(row)


def _tables(db, *names):
    """ The named tables, or None when one is not loaded """
    tables = tuple(getattr(db.tbl, name, None) for name in names)
    return None if any(tbl is None for tbl in tables) else tables


def project_role_names(connection, db, project_id, user_id):
    """ Sorted project role names of a user in one project """
    pur, role = db.tbl.project_user_role, db.tbl.project_role
    rows = connection.execute(
        pur.join(role, pur.c.role_id == role.c.id).select().with_only_columns(role.c.name).where(
            pur.c.project_id == project_id, pur.c.user_id == user_id,
        )
    ).all()
    return sorted({row[0] for row in rows})


def user_memberships(connection, db, user_id):
    """ {project_id: sorted role names} for a user """
    tables = _tables(db, "project_user_role", "project_role")
    if tables is None:
        return {}
    pur, role = tables
    rows = connection.execute(
        pur.join(role, pur.c.role_id == role.c.id).select().with_only_columns(
            pur.c.project_id, role.c.name,
        ).where(pur.c.user_id == user_id)
    ).all()
    result = {}
    for project_id, name in rows:
        result.setdefault(project_id, set()).add(name)
    return {project_id: sorted(names) for project_id, names in sorted(result.items())}


def platform_role_names(connection, db, user_id, mode):
    """ Sorted platform role names of a user in one mode """
    tables = _tables(db, "user_role", "role")
    if tables is None:
        return []
    user_role, role = tables
    rows = connection.execute(
        user_role.join(role, user_role.c.role_id == role.c.id).select().with_only_columns(
            role.c.name,
        ).where(user_role.c.user_id == user_id, role.c.mode == mode)
    ).all()
    return sorted({row[0] for row in rows})


def insert(connection, db, events):
    """ Write events on the caller's connection; AuditWriteError when that fails """
    events = [event for event in events if event]
    if not events:
        return
    tbl = getattr(db.tbl, "lifecycle_audit_inbox", None)
    if tbl is None:
        log.warning("Lifecycle audit inbox is not loaded; %s event(s) not recorded", len(events))
        return
    try:
        connection.execute(tbl.insert(), [
            {
                "event_id": event["event_id"],
                "occurred_at": datetime.datetime.fromisoformat(event["occurred_at"]),
                "event_type": event["event_type"],
                "payload": event,
            } for event in events
        ])
    except Exception as exception:  # pylint: disable=W0703
        raise AuditWriteError(str(exception)) from exception


def transact(db, change):
    """ Run change(connection) -> (result, events) in one transaction with its events

    If only the event write fails, the change is applied again without events: an audit
    outage must never block a login or an admin operation (AC-23). It is logged loudly.
    change may therefore run twice: it must not keep state across calls, except values it
    overwrites on every run (the callers' epoch).
    """
    try:
        with revocation.transaction(db) as connection:
            result, events = change(connection)
            insert(connection, db, events)
        return result
    except AuditWriteError:
        log.exception("Lifecycle audit write failed; applying the change without its audit event")
    #
    with revocation.transaction(db) as connection:
        result, _ = change(connection)
    return result


def insert_best_effort(connection, db, events):
    """ For paths that are not transactional themselves (bulk snapshot apply) """
    try:
        insert(connection, db, events)
    except AuditWriteError:
        log.exception("Lifecycle audit write failed")
