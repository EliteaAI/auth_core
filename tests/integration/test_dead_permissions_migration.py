"""Coverage for alembic revision 202610021200 (issue #6874).

Fresh installs re-run 202602261000, which seeds the Collections strings, so this
revision deletes every dead string from all four grant tables. Live strings that
share a prefix with a dead one (projects.projects vs projects) must survive.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION_FILE = "202610021200_delete_dead_permissions.py"
TABLES = ("role_permission", "project_role_permission", "group_permission", "user_permission")
LIVE = ["projects.projects", "configuration.roles", "runtime.plugins", "admin.auth.users"]


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202610021200")


@pytest.fixture
def module():
    return types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))


@pytest.fixture
def tables(engine):
    metadata = sa.MetaData()
    created = {
        name: sa.Table(
            f"{TABLE_PREFIX}__{name}", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("permission", sa.Text, nullable=False),
        )
        for name in TABLES
    }
    metadata.create_all(engine)
    return created


def run(revision_module, engine, module, direction="upgrade"):
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision_module, direction)(module, None)


def seed(engine, tables, permissions):
    with engine.connect() as connection:
        for table in tables.values():
            connection.execute(table.insert(), [{"permission": p} for p in permissions])


def remaining(engine, tables):
    with engine.connect() as connection:
        return {
            name: sorted(connection.execute(sa.select(table.c.permission)).scalars())
            for name, table in tables.items()
        }


def test_deletes_dead_strings_from_every_table_and_keeps_live_ones(revision, engine, module, tables):
    seed(engine, tables, revision.DEAD_PERMISSIONS + LIVE)

    run(revision, engine, module)

    assert remaining(engine, tables) == {name: sorted(LIVE) for name in TABLES}


def test_rerun_is_a_noop(revision, engine, module, tables):
    seed(engine, tables, LIVE)

    run(revision, engine, module)
    run(revision, engine, module)

    assert remaining(engine, tables) == {name: sorted(LIVE) for name in TABLES}


def test_missing_table_is_skipped(revision, engine, module):
    run(revision, engine, module)


def test_no_live_string_is_targeted(revision):
    assert not set(revision.DEAD_PERMISSIONS) & set(LIVE)
    assert len(set(revision.DEAD_PERMISSIONS)) == len(revision.DEAD_PERMISSIONS)

