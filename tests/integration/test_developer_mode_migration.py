"""Coverage for alembic revision 202610021500 (issue #6880).

Developer-mode roles were seeded on every install but never assigned or checked.
The revision must drop them together with their grants and leave every other
mode untouched; it must also tolerate re-runs and a schema without the tables.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION_FILE = "202610021500_delete_developer_mode_roles.py"


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202610021500")


@pytest.fixture
def module():
    return types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))


@pytest.fixture
def tables(engine):
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text), sa.Column("mode", sa.Text),
    )
    role_permission = sa.Table(
        f"{TABLE_PREFIX}__role_permission", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer), sa.Column("permission", sa.Text),
    )
    user_role = sa.Table(
        f"{TABLE_PREFIX}__user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer), sa.Column("role_id", sa.Integer),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(role.insert(), [
            {"id": 1, "name": "admin", "mode": "administration"},
            {"id": 2, "name": "admin", "mode": "default"},
            {"id": 3, "name": "admin", "mode": "developer"},
            {"id": 4, "name": "viewer", "mode": "developer"},
        ])
        connection.execute(role_permission.insert(), [
            {"role_id": r, "permission": "p"} for r in (1, 2, 3, 3, 4)
        ])
        connection.execute(user_role.insert(), [
            {"user_id": 7, "role_id": 1}, {"user_id": 7, "role_id": 3},
        ])
    return types.SimpleNamespace(role=role, role_permission=role_permission, user_role=user_role)


def run(revision_module, engine, module, direction="upgrade"):
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision_module, direction)(module, None)


def column(engine, table, name):
    with engine.connect() as connection:
        return sorted(connection.execute(sa.select(table.c[name])).scalars())


def test_deletes_developer_roles_and_grants_only(revision, engine, module, tables):
    run(revision, engine, module)

    assert column(engine, tables.role, "mode") == ["administration", "default"]
    assert column(engine, tables.role_permission, "role_id") == [1, 2]
    assert column(engine, tables.user_role, "role_id") == [1]


def test_rerun_is_a_noop(revision, engine, module, tables):
    run(revision, engine, module)
    run(revision, engine, module)

    assert column(engine, tables.role, "mode") == ["administration", "default"]


def test_missing_tables_are_skipped(revision, engine, module):
    run(revision, engine, module)


def test_downgrade_is_a_noop(revision, engine, module, tables):
    run(revision, engine, module, "downgrade")

    assert len(column(engine, tables.role, "mode")) == 4
