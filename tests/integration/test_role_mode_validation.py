"""Role-writing RPCs must reject any mode other than administration/default."""
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX, helpers


@pytest.fixture(scope="session")
def roles(plugin_root):
    return helpers.import_plugin_module(plugin_root, "rpc.roles")


@pytest.fixture
def subject(roles, engine):
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text), sa.Column("mode", sa.Text),
    )
    metadata.create_all(engine)
    obj = roles.RPC()
    obj.db = types.SimpleNamespace(engine=engine, url=str(engine.url), tbl=types.SimpleNamespace(role=role))
    obj.role = role
    return obj


def role_count(subject, engine):
    with engine.connect() as connection:
        return connection.execute(sa.select(sa.func.count()).select_from(subject.role)).scalar()


@pytest.mark.parametrize("mode", ["developer", "", "ADMINISTRATION", None])
def test_add_role_rejects_unknown_mode(subject, engine, mode):
    with pytest.raises(RuntimeError, match="Unknown role mode"):
        subject.add_role("x", mode=mode)

    assert role_count(subject, engine) == 0


@pytest.mark.parametrize("mode", ["administration", "default"])
def test_add_role_accepts_known_modes(subject, engine, mode):
    subject.add_role("x", mode=mode)

    assert role_count(subject, engine) == 1


def test_update_role_name_rejects_unknown_mode(subject):
    with pytest.raises(RuntimeError, match="Unknown role mode"):
        subject.update_role_name("a", "b", mode="developer")


def test_assign_user_to_role_rejects_unknown_mode(subject):
    with pytest.raises(ValueError, match="Unknown role mode"):
        subject.assign_user_to_role(1, "admin", mode="developer")


def test_set_permission_for_role_rejects_unknown_mode(subject):
    with pytest.raises(ValueError, match="Unknown role mode"):
        subject.set_permission_for_role("admin", "p", mode="developer")


def test_insert_permissions_skips_modes_without_roles(roles, engine):
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text), sa.Column("mode", sa.Text),
    )
    role_permission = sa.Table(
        f"{TABLE_PREFIX}__role_permission", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer, nullable=False),
        sa.Column("permission", sa.String(64)),
        sa.UniqueConstraint("role_id", "permission"),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(role.insert(), [{"id": 1, "name": "admin", "mode": "administration"}])
    subject = roles.RPC()
    subject.db = types.SimpleNamespace(
        engine=engine, url=str(engine.url), tbl=types.SimpleNamespace(role=role, role_permission=role_permission)
    )

    subject.insert_permissions([("admin", "developer", "p.x"), ("admin", "administration", "p.x")])
    subject.insert_permissions([("admin", "developer", "p.y")])

    with engine.connect() as connection:
        rows = connection.execute(sa.select(role_permission.c.role_id, role_permission.c.permission)).all()
    assert rows == [(1, "p.x")]
