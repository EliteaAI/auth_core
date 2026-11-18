"""EL-7504: lifecycle audit events written by auth_core in the changing transaction.

Contract under test (plan D2-D4):
- every user / platform-role / project-role RPC takes an optional ``audit_ctx``;
- the event lands in ``auth_core__lifecycle_audit_inbox`` in the same transaction
  as the change, so a rolled-back change leaves no event;
- an unchanged value records nothing; a missing ctx records actor_type=unknown.
"""
import datetime
import json
import types

import pytest
import sqlalchemy as sa

from fixtures import helpers
from conftest import RecordingEvents, SECRET_KEY, TABLE_PREFIX, define_tables

INBOX = f"{TABLE_PREFIX}__lifecycle_audit_inbox"

ADMIN_CTX = {
    "actor_type": "user", "actor_id": 7, "actor_name": "Root Admin",
    "actor_email": "root@example.com", "source": "ui", "request_id": "req-1",
}
SCIM_CTX = {
    "actor_type": "service", "actor_id": None, "actor_name": "SCIM",
    "actor_email": None, "source": "provisioning", "request_id": None,
}


def define_role_tables(metadata):
    """Role DDL from the core migrations; only what the RPCs touch."""
    role = sa.Table(
        f"{TABLE_PREFIX}__role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text),
        sa.Column("mode", sa.Text),
    )
    user_role = sa.Table(
        f"{TABLE_PREFIX}__user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer,
                  sa.ForeignKey(f"{TABLE_PREFIX}__user.id", ondelete="CASCADE")),
        sa.Column("role_id", sa.Integer,
                  sa.ForeignKey(f"{TABLE_PREFIX}__role.id", ondelete="CASCADE")),
    )
    project_role = sa.Table(
        f"{TABLE_PREFIX}__project_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer),
        sa.Column("name", sa.Text),
    )
    project_user_role = sa.Table(
        f"{TABLE_PREFIX}__project_user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer),
        sa.Column("user_id", sa.Integer,
                  sa.ForeignKey(f"{TABLE_PREFIX}__user.id", ondelete="CASCADE")),
        sa.Column("role_id", sa.Integer,
                  sa.ForeignKey(f"{TABLE_PREFIX}__project_role.id", ondelete="CASCADE")),
    )
    role_permission = sa.Table(
        f"{TABLE_PREFIX}__role_permission", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer,
                  sa.ForeignKey(f"{TABLE_PREFIX}__role.id", ondelete="CASCADE")),
        sa.Column("permission", sa.Text),
    )
    return role, user_role, project_role, project_user_role, role_permission


def define_inbox(metadata):
    """The inbox the new auth_core migration creates (plan task 11)."""
    return sa.Table(
        INBOX, metadata,
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(36), nullable=False, unique=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )


@pytest.fixture
def audit(plugin_root, tokens, credential_handlers, users, roles, project_roles,
          revocation_rpc, engine):
    """All user/role RPCs mixed into one module, as Pylon binds them."""
    metadata = sa.MetaData()
    token_tbl, user_tbl = define_tables(metadata)
    role, user_role, project_role, project_user_role, role_permission = define_role_tables(metadata)
    inbox = define_inbox(metadata)
    metadata.create_all(engine)

    class Subject(tokens.RPC, credential_handlers.RPC, users.RPC, roles.RPC,
                  project_roles.RPC, revocation_rpc.RPC):
        pass

    subject = Subject()
    subject.db = types.SimpleNamespace(
        engine=engine, url=str(engine.url),
        tbl=types.SimpleNamespace(
            token=token_tbl, user=user_tbl, role=role, user_role=user_role,
            project_role=project_role, project_user_role=project_user_role,
            role_permission=role_permission,
            lifecycle_audit_inbox=inbox,
        ),
    )
    subject.events = RecordingEvents()
    subject.context = types.SimpleNamespace(
        app=types.SimpleNamespace(secret_key=SECRET_KEY),
        event_manager=subject.events,
    )
    subject.descriptor = types.SimpleNamespace(config={})
    subject.tbl = subject.db.tbl

    with engine.connect() as connection:
        connection.execute(role.insert(), [
            {"id": 1, "name": "super_admin", "mode": "administration"},
            {"id": 2, "name": "admin", "mode": "administration"},
            {"id": 3, "name": "viewer", "mode": "administration"},
        ])
        connection.execute(project_role.insert(), [
            {"id": 10, "project_id": 5, "name": "admin"},
            {"id": 11, "project_id": 5, "name": "editor"},
            {"id": 12, "project_id": 5, "name": "viewer"},
        ])
    return subject


def events(subject, event_type=None):
    """Inbox payloads in insert order, optionally of one type."""
    tbl = subject.db.tbl.lifecycle_audit_inbox
    with subject.db.engine.connect() as connection:
        rows = connection.execute(sa.select(tbl).order_by(tbl.c.id)).mappings().all()
    out = []
    for row in rows:
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if event_type is None or row["event_type"] == event_type:
            out.append(payload)
    return out


def make_user(subject, email="ann@example.com", name="Ann"):
    return subject.add_user(email=email, name=name, audit_ctx=ADMIN_CTX)


# --- AC-4 user.created / user.first_login -------------------------------------

def test_add_user_records_created_with_creator(audit):
    user_id = make_user(audit)

    [event] = events(audit, "user.created")
    assert event["user_id"] == user_id
    assert event["user_email"] == "ann@example.com"
    assert event["user_name"] == "Ann"
    assert event["actor_id"] == 7
    assert event["actor_name"] == "Root Admin"
    assert event["source"] == "ui"
    assert event["scope"] == "platform"
    assert event["result"] == "success"
    assert event["imported"] is False
    assert event["request_id"] == "req-1"


def test_add_user_from_provisioning_records_service_actor(audit):
    audit.add_user(email="bob@example.com", name="Bob", audit_ctx=SCIM_CTX)

    [event] = events(audit, "user.created")
    assert event["actor_type"] == "service"
    assert event["actor_id"] is None
    assert event["source"] == "provisioning"


def test_missing_ctx_records_unknown_actor_never_a_guess(audit):
    audit.add_user(email="eve@example.com", name="Eve")

    [event] = events(audit, "user.created")
    assert event["actor_type"] == "unknown"
    assert event["actor_id"] is None


def test_first_login_recorded_once(audit):
    user_id = make_user(audit)
    when = datetime.datetime(2026, 11, 16, 9, 30)

    assert audit.record_first_login(user_id=user_id, when=when) is True
    assert audit.record_first_login(user_id=user_id, when=when) is False

    [event] = events(audit, "user.first_login")
    assert event["user_id"] == user_id
    assert event["details"]["first_login"].startswith("2026-11-16T09:30")


# --- AC-7 name / email / delete ------------------------------------------------

def test_name_and_email_change_record_before_and_after(audit):
    user_id = make_user(audit)

    audit.update_user(id_=user_id, name="Ann B", email="ann.b@example.com", audit_ctx=ADMIN_CTX)

    [name_event] = events(audit, "user.name_changed")
    assert name_event["changes"] == {"name": {"before": "Ann", "after": "Ann B"}}
    [email_event] = events(audit, "user.email_changed")
    assert email_event["changes"] == {
        "email": {"before": "ann@example.com", "after": "ann.b@example.com"},
    }


def test_unchanged_name_records_nothing(audit):
    user_id = make_user(audit)

    audit.update_user(id_=user_id, name="Ann", audit_ctx=ADMIN_CTX)
    audit.update_user(id_=user_id, last_login=datetime.datetime(2026, 11, 16), audit_ctx=ADMIN_CTX)

    assert events(audit, "user.name_changed") == []
    assert events(audit, "user.email_changed") == []


def test_delete_user_records_snapshot_and_memberships(audit):
    user_id = make_user(audit)
    audit.add_project_user_role(project_id=5, user_id=user_id, role_id=11, audit_ctx=ADMIN_CTX)

    audit.delete_user(user_id=user_id, audit_ctx=ADMIN_CTX)

    [deleted] = events(audit, "user.deleted")
    assert deleted["user_name"] == "Ann"
    assert deleted["user_email"] == "ann@example.com"
    removed = events(audit, "project.member_removed")
    assert len(removed) == 1
    assert removed[0]["project_id"] == 5
    assert removed[0]["roles_before"] == ["editor"]
    assert removed[0]["details"]["reason"] == "user_deleted"


def test_project_removal_never_records_user_deleted(audit):
    user_id = make_user(audit)
    audit.add_project_user_role(project_id=5, user_id=user_id, role_id=11, audit_ctx=ADMIN_CTX)

    audit.delete_project_user_role(project_id=5, user_id=user_id, role_id=11, audit_ctx=ADMIN_CTX)

    assert events(audit, "user.deleted") == []
    assert len(events(audit, "project.member_removed")) == 1


# --- AC-25 suspend / unsuspend -------------------------------------------------

def test_suspend_and_unsuspend_recorded_only_on_change(audit):
    user_id = make_user(audit)

    audit.update_user(id_=user_id, suspended=True, audit_ctx=ADMIN_CTX)
    audit.update_user(id_=user_id, suspended=True, audit_ctx=ADMIN_CTX)
    audit.update_user(id_=user_id, suspended=False, audit_ctx=SCIM_CTX)

    assert len(events(audit, "user.suspended")) == 1
    [restored] = events(audit, "user.unsuspended")
    assert restored["source"] == "provisioning"


# --- AC-3 project membership -----------------------------------------------------

def test_member_added_records_roles(audit):
    user_id = make_user(audit)

    audit.add_project_user_role(project_id=5, user_id=user_id, role_id=12, audit_ctx=ADMIN_CTX)

    [event] = events(audit, "project.member_added")
    assert event["project_id"] == 5
    assert event["user_id"] == user_id
    assert event["user_email"] == "ann@example.com"
    assert event["roles_before"] == []
    assert event["roles_after"] == ["viewer"]
    assert event["scope"] == "project"


@pytest.mark.parametrize("before, after, expected", [
    ([], [11], "project.member_added"),
    ([11], [], "project.member_removed"),
    ([11], [10], "project.member_role_changed"),
])
def test_replace_all_roles_maps_to_one_event(audit, before, after, expected):
    user_id = make_user(audit)
    if before:
        audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=before)
    already = len(events(audit))

    audit.update_project_user_roles(
        project_id=5, user_id=user_id, role_ids=after, audit_ctx=ADMIN_CTX,
    )

    new = events(audit)[already:]
    assert [e["event_type"] for e in new] == [expected]


def test_replace_all_with_same_roles_records_nothing(audit):
    user_id = make_user(audit)
    audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=[11])
    already = len(events(audit))

    audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=[11], audit_ctx=ADMIN_CTX)

    assert len(events(audit)) == already


# --- AC-5 / AC-6 platform roles and administrator access -------------------------

# admin_access is derived by the admin drainer (events.normalize); the inbox carries the role sets

def test_platform_admin_grant_and_revoke_recorded(audit):
    user_id = make_user(audit)
    audit.assign_user_to_role(user_id=user_id, role_name="viewer", audit_ctx=ADMIN_CTX)

    audit.assign_user_to_role(user_id=user_id, role_name="super_admin", audit_ctx=ADMIN_CTX)
    audit.remove_user_from_role(user_id=user_id, role_name="super_admin", audit_ctx=ADMIN_CTX)

    changes = events(audit, "user.platform_role_changed")
    assert [(c["roles_before"], c["roles_after"]) for c in changes] == [
        ([], ["viewer"]), (["viewer"], ["super_admin"]), (["super_admin"], []),
    ]
    assert all(c["scope"] == "platform" for c in changes)
    assert changes[1]["roles_before"] == ["viewer"]
    assert changes[1]["roles_after"] == ["super_admin"]
    assert changes[1]["details"]["mode"] == "administration"


def test_project_admin_role_change_recorded(audit):
    user_id = make_user(audit)
    audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=[11])

    audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=[10], audit_ctx=ADMIN_CTX)

    [event] = events(audit, "project.member_role_changed")
    assert (event["roles_before"], event["roles_after"]) == (["editor"], ["admin"])
    assert event["scope"] == "project"


# --- AC-9 / AC-10 same transaction -----------------------------------------------

def test_failed_change_leaves_no_event(audit, plugin_root, monkeypatch):
    user_id = make_user(audit)
    already = len(events(audit))
    revocation = helpers.import_plugin_module(plugin_root, "tools.revocation")

    def boom(*_a, **_k):
        raise RuntimeError("bump failed")

    # fails after the membership insert, inside the same transaction
    monkeypatch.setattr(revocation, "bump_epoch", boom)

    with pytest.raises(RuntimeError):
        audit.update_project_user_roles(project_id=5, user_id=user_id, role_ids=[11], audit_ctx=ADMIN_CTX)

    assert len(events(audit)) == already
    with audit.db.engine.connect() as connection:
        assert connection.execute(
            sa.select(audit.db.tbl.project_user_role)
        ).all() == []


# --- AC-20 no secrets ------------------------------------------------------------

def test_event_never_contains_secret_keys(audit):
    ctx = dict(ADMIN_CTX, token="tkn", password="pw")
    audit.add_user(email="z@example.com", name="Z", audit_ctx=ctx)

    blob = json.dumps(events(audit)).lower()
    assert "tkn" not in blob
    assert "password" not in blob


# --- AC-23 login safety ----------------------------------------------------------

def test_audit_failure_does_not_break_first_login(audit, engine):
    user_id = make_user(audit)
    with engine.connect() as connection:
        connection.execute(sa.text(f"DROP TABLE {INBOX}"))

    assert audit.record_first_login(
        user_id=user_id, when=datetime.datetime(2026, 11, 16),
    ) is True


# --- cascades: role definition deletes, bulk snapshot ----------------------------

def test_deleting_project_role_records_change_for_each_holder(audit):
    ann = make_user(audit)
    bob = make_user(audit, email="bob@example.com", name="Bob")
    audit.update_project_user_roles(project_id=5, user_id=ann, role_ids=[10, 11])
    audit.update_project_user_roles(project_id=5, user_id=bob, role_ids=[10])
    already = len(events(audit))

    audit.delete_project_role(project_id=5, name="admin", audit_ctx=ADMIN_CTX)

    new = {e["user_id"]: e for e in events(audit)[already:]}
    assert new[ann]["event_type"] == "project.member_role_changed"
    assert new[ann]["roles_after"] == ["editor"]
    assert new[ann]["roles_before"] == ["admin", "editor"]
    assert new[bob]["event_type"] == "project.member_removed"
    assert new[bob]["details"]["reason"] == "role_deleted"


def test_deleting_platform_role_records_change_for_each_holder(audit):
    ann = make_user(audit)
    audit.assign_user_to_role(user_id=ann, role_name="admin", audit_ctx=ADMIN_CTX)
    already = len(events(audit))

    audit.delete_role(name="admin", audit_ctx=ADMIN_CTX)

    [event] = events(audit)[already:]
    assert event["event_type"] == "user.platform_role_changed"
    assert event["roles_before"] == ["admin"]
    assert event["roles_after"] == []
    assert event["details"]["reason"] == "role_deleted"


def test_snapshot_apply_records_added_members_as_system(audit, engine):
    ann = make_user(audit)
    already = len(events(audit))
    perm = sa.Table(
        f"{TABLE_PREFIX}__project_role_permission", sa.MetaData(),
        sa.Column("project_id", sa.Integer), sa.Column("role_id", sa.Integer),
        sa.Column("permission", sa.Text),
    )
    perm.create(engine)
    audit.db.tbl.project_role_permission = perm

    audit.apply_project_roles_snapshot([{
        "project_id": 5, "roles": [{"name": "viewer", "permissions": []}],
        "assignments": [{"user_id": ann, "role": "viewer"}],
    }])

    [event] = events(audit)[already:]
    assert event["event_type"] == "project.member_added"
    assert event["actor_type"] == "system"
    assert event["source"] == "system"
