"""Revocation epochs (C-1009, issue #6944; token rotation leak #6489).

pylon_main caches identity and permissions for up to a minute. These tests pin the
auth_core half of the fix: every operation that revokes or narrows access bumps
the user's or token's epoch in the same transaction as the change, announces it
after commit, and the epoch RPC reports both the counters and the admission verdict.
"""
import datetime
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

PAST = datetime.datetime(2020, 1, 1, 12, 0, 0)
FUTURE = datetime.datetime(2099, 1, 1, 12, 0, 0)


def add_user(rpc, user_id, suspended=False):
    with rpc.db.engine.connect() as connection:
        connection.execute(
            rpc.db.tbl.user.insert().values(
                id=user_id, email=f"user{user_id}@example.com", suspended=suspended,
            )
        )


def epoch_of(rpc, kind, id_):
    tbl = getattr(rpc.db.tbl, kind)
    with rpc.db.engine.connect() as connection:
        return connection.execute(
            sa.select(tbl.c.revocation_epoch).where(tbl.c.id == id_)
        ).scalar()


# --- bump helper and RPCs --------------------------------------------------


def test_bump_returns_the_new_epoch_and_counts_up(rpc):
    add_user(rpc, 1)

    assert rpc.bump_revocation_epoch("user", 1) == 1
    assert rpc.bump_revocation_epoch("user", 1) == 2
    assert epoch_of(rpc, "user", 1) == 2


def test_bump_issues_update_with_returning(rpc, engine):
    add_user(rpc, 1)
    statements = []
    sa.event.listen(engine, "before_cursor_execute", lambda c, cur, stmt, *a: statements.append(stmt))

    rpc.bump_revocation_epoch("user", 1)

    updates = [s for s in statements if s.startswith("UPDATE")]
    assert len(updates) == 1
    assert "revocation_epoch=" in updates[0].replace(" ", "")
    assert "RETURNING" in updates[0]


def test_bump_fires_one_invalidate_event_after_commit(rpc):
    add_user(rpc, 1)

    rpc.bump_revocation_epoch("user", 1)

    assert rpc.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})]


def test_bump_of_a_missing_row_is_none_and_silent(rpc):
    assert rpc.bump_revocation_epoch("token", 999) is None
    assert rpc.events.fired == []


def test_bump_rejects_an_unknown_kind(rpc):
    with pytest.raises(RuntimeError, match="Unknown revocation kind"):
        rpc.bump_revocation_epoch("group", 1)


def test_a_failing_event_manager_does_not_fail_the_committed_bump(rpc):
    add_user(rpc, 1)

    def boom(*_a, **_k):
        raise ConnectionError("redis down")

    rpc.context.event_manager.fire_event = boom

    assert rpc.bump_revocation_epoch("user", 1) == 1
    assert epoch_of(rpc, "user", 1) == 1


def test_rpc_signatures(rpc):
    import inspect

    assert list(inspect.signature(rpc.get_revocation_epochs).parameters) == ["user_id", "token_id"]
    assert inspect.signature(rpc.get_revocation_epochs).parameters["token_id"].default is None
    assert list(inspect.signature(rpc.bump_revocation_epoch).parameters) == ["kind", "id"]
    assert list(inspect.signature(rpc.set_token_expiry).parameters) == ["token_id", "expires"]


# --- get_revocation_epochs -------------------------------------------------


def test_epochs_for_a_user(rpc):
    add_user(rpc, 1)
    rpc.bump_revocation_epoch("user", 1)

    result = rpc.get_revocation_epochs(user_id=1)

    assert result == {"user": 1, "token": None, "user_id": 1, "active": True, "reason": None}


def test_epochs_for_a_token_resolve_the_owner_from_the_token(rpc):
    add_user(rpc, 7)
    token_id = rpc.add_token(user_id=7, name="mine")

    result = rpc.get_revocation_epochs(token_id=token_id)

    assert result["user_id"] == 7
    assert result["user"] == 0 and result["token"] == 0
    assert result["active"] is True


def test_unknown_user_is_inactive(rpc):
    result = rpc.get_revocation_epochs(user_id=404)

    assert (result["user"], result["active"], result["reason"]) == (None, False, "user_missing")


def test_suspended_user_is_inactive_for_session_and_token_alike(rpc):
    add_user(rpc, 1, suspended=True)
    token_id = rpc.add_token(user_id=1, name="mine")

    assert rpc.get_revocation_epochs(user_id=1)["reason"] == "user_suspended"
    assert rpc.get_revocation_epochs(token_id=token_id)["reason"] == "user_suspended"


def test_expired_token_is_inactive_and_future_token_is_active(rpc):
    add_user(rpc, 1)
    expired = rpc.add_token(user_id=1, name="old", expires=PAST)
    fresh = rpc.add_token(user_id=1, name="new", expires=FUTURE)

    assert rpc.get_revocation_epochs(token_id=expired)["reason"] == "token_expired"
    assert rpc.get_revocation_epochs(token_id=fresh)["active"] is True


def test_deleted_token_reads_back_as_missing(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="mine")
    rpc.delete_token(token_id)

    result = rpc.get_revocation_epochs(token_id=token_id)

    assert (result["token"], result["active"], result["reason"]) == (None, False, "token_missing")


def test_epoch_rpc_needs_an_identity(rpc):
    with pytest.raises(RuntimeError, match="user_id or token_id"):
        rpc.get_revocation_epochs()


# --- the revoking paths bump -----------------------------------------------


def test_suspending_a_user_bumps_and_announces(rpc):
    add_user(rpc, 1)

    rpc.update_user(1, suspended=True)

    assert epoch_of(rpc, "user", 1) == 1
    assert rpc.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})]
    assert rpc.get_revocation_epochs(user_id=1)["reason"] == "user_suspended"


def test_a_rename_does_not_bump(rpc):
    add_user(rpc, 1)

    rpc.update_user(1, name="renamed")

    assert epoch_of(rpc, "user", 1) == 0
    assert rpc.events.fired == []


def test_deleting_a_user_announces_without_an_epoch(rpc):
    add_user(rpc, 1)

    assert rpc.delete_user(1) == 1

    assert rpc.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": None})]
    assert rpc.get_revocation_epochs(user_id=1)["active"] is False


def test_deleting_a_token_announces_without_an_epoch(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="mine")

    assert rpc.delete_token(token_id) == 1

    assert rpc.events.fired == [("auth_invalidate", {"kind": "token", "id": token_id, "epoch": None})]


def test_deleting_nothing_announces_nothing(rpc):
    assert rpc.delete_token(12345) == 0
    assert rpc.events.fired == []


def test_the_protected_system_token_is_not_announced_as_deleted(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    system_id = rpc.list_tokens(user_id=1, include_system=True)[0]["id"]

    assert rpc.delete_token(system_id) == 0
    assert rpc.events.fired == []


def test_set_token_expiry_retires_the_token_and_bumps_its_epoch(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="api")

    epoch = rpc.set_token_expiry(token_id, FUTURE)

    assert epoch == 1
    assert rpc.get_token(token_id=token_id)["expires"] == FUTURE
    assert rpc.events.fired == [("auth_invalidate", {"kind": "token", "id": token_id, "epoch": 1})]


def test_a_retired_token_stops_working_once_the_expiry_passes(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="api")
    encoded = rpc.encode_token(token_id=token_id)

    rpc.set_token_expiry(token_id, PAST)

    with pytest.raises(RuntimeError, match="expired"):
        rpc.handle_bearer_token("source", encoded)


def test_set_token_expiry_refuses_the_system_token(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    system = rpc.list_tokens(user_id=1, include_system=True)[0]

    assert rpc.set_token_expiry(system["id"], PAST) is None

    assert rpc.get_token(token_id=system["id"])["expires"] is None
    assert rpc.events.fired == []


def test_set_token_expiry_on_a_missing_token_is_none(rpc):
    assert rpc.set_token_expiry(404, PAST) is None
    assert rpc.events.fired == []


# --- role paths -------------------------------------------------------------


@pytest.fixture
def access(rpc, roles, project_roles, engine):
    """The role RPCs next to the token ones, over the same engine."""
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text), sa.Column("mode", sa.Text),
    )
    user_role = sa.Table(
        f"{TABLE_PREFIX}__user_role", metadata,
        sa.Column("user_id", sa.Integer), sa.Column("role_id", sa.Integer),
    )
    project_user_role = sa.Table(
        f"{TABLE_PREFIX}__project_user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer), sa.Column("user_id", sa.Integer),
        sa.Column("role_id", sa.Integer),
    )
    project_role = sa.Table(
        f"{TABLE_PREFIX}__project_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer), sa.Column("name", sa.Text),
    )
    project_role_permission = sa.Table(
        f"{TABLE_PREFIX}__project_role_permission", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer), sa.Column("role_id", sa.Integer),
        sa.Column("permission", sa.Text),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(role.insert().values(id=1, name="admin", mode="administration"))
        connection.execute(role.insert().values(id=2, name="viewer", mode="administration"))

    class Subject(roles.RPC, project_roles.RPC):
        pass

    subject = Subject()
    subject.db = rpc.db
    subject.db.tbl.role = role
    subject.db.tbl.user_role = user_role
    subject.db.tbl.project_user_role = project_user_role
    subject.db.tbl.project_role = project_role
    subject.db.tbl.project_role_permission = project_role_permission
    subject.context = rpc.context
    subject.events = rpc.events
    subject.descriptor = types.SimpleNamespace(config={})
    add_user(rpc, 1)
    return subject


def test_assigning_an_administration_role_bumps_the_user(access):
    access.assign_user_to_role(1, "admin")

    assert epoch_of(access, "user", 1) == 1
    assert access.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})]


def test_removing_an_administration_role_bumps_the_user(access):
    access.assign_user_to_role(1, "admin")
    access.events.fired.clear()

    access.remove_user_from_role(1, "admin")

    assert epoch_of(access, "user", 1) == 2
    assert access.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": 2})]


def test_removing_an_unknown_role_changes_nothing(access):
    access.remove_user_from_role(1, "no-such-role")

    assert epoch_of(access, "user", 1) == 0
    assert access.events.fired == []


def test_project_role_add_delete_and_replace_all_bump_the_user(access):
    access.add_project_user_role(10, 1, 1)
    assert epoch_of(access, "user", 1) == 1

    assert access.delete_project_user_role(10, 1, 1) == 1
    assert epoch_of(access, "user", 1) == 2

    access.update_project_user_roles(10, 1, [1, 2])
    assert epoch_of(access, "user", 1) == 3

    assert [e[1]["epoch"] for e in access.events.fired] == [1, 2, 3]


def test_deleting_a_project_role_that_was_not_assigned_does_not_bump(access):
    assert access.delete_project_user_role(10, 1, 1) == 0

    assert epoch_of(access, "user", 1) == 0
    assert access.events.fired == []


def test_applying_a_snapshot_bumps_only_users_that_got_an_assignment(access, rpc):
    add_user(rpc, 2)
    snapshot = [{
        "project_id": 10,
        "roles": [{"name": "member", "permissions": ["x.y"]}],
        "assignments": [{"user_id": 1, "role": "member"}],
    }]

    access.apply_project_roles_snapshot(snapshot)
    assert epoch_of(access, "user", 1) == 1
    assert epoch_of(access, "user", 2) == 0

    access.apply_project_roles_snapshot(snapshot)  # nothing new to assign
    assert epoch_of(access, "user", 1) == 1
    assert access.events.fired == [("auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})]


# --- same connection, before commit ------------------------------------------


def record_sql(engine):
    log = []
    sa.event.listen(
        engine, "before_cursor_execute",
        lambda conn, cur, stmt, params, ctx, many: log.append(("sql", stmt.split(" ", 1)[0], stmt, id(conn))),
    )
    sa.event.listen(engine, "commit", lambda conn: log.append(("commit", None, None, id(conn))))
    return log


def test_suspension_and_bump_share_a_connection_and_commit_together(rpc, engine):
    add_user(rpc, 1)
    log = record_sql(engine)

    rpc.update_user(1, suspended=True)

    updates = [i for i, item in enumerate(log) if item[0] == "sql" and item[1] == "UPDATE"]
    commits = [i for i, item in enumerate(log) if item[0] == "commit"]
    assert len(updates) == 2  # the change, then the bump
    assert "revocation_epoch" in log[updates[1]][2]
    assert len({log[i][3] for i in updates}) == 1
    assert commits and commits[0] > updates[1]
    assert len(commits) == 1
    assert rpc.events.fired  # announced only after the block above ended


def test_expiry_change_and_bump_share_a_connection_and_commit_together(rpc, engine):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="api")
    log = record_sql(engine)

    rpc.set_token_expiry(token_id, FUTURE)

    updates = [i for i, item in enumerate(log) if item[0] == "sql" and item[1] == "UPDATE"]
    commits = [i for i, item in enumerate(log) if item[0] == "commit"]
    assert len(updates) == 2
    assert len({log[i][3] for i in updates}) == 1
    assert len(commits) == 1 and commits[0] > updates[1]


def test_a_failure_after_the_change_rolls_the_change_back(rpc, plugin_root, monkeypatch):
    """No bump without the change and no change without the bump."""
    add_user(rpc, 1)
    revocation = helpers.import_plugin_module(plugin_root, "tools.revocation")

    def boom(*_a, **_k):
        raise RuntimeError("bump failed")

    monkeypatch.setattr(revocation, "bump_epoch", boom)

    with pytest.raises(RuntimeError):
        rpc.update_user(1, suspended=True)

    with rpc.db.engine.connect() as connection:
        suspended = connection.execute(
            sa.select(rpc.db.tbl.user.c.suspended).where(rpc.db.tbl.user.c.id == 1)
        ).scalar()
    assert not suspended
    assert rpc.events.fired == []
