"""Coverage for alembic revision 202609251200 (issue #5633).

Upgrade grants configuration.secrets.private_secret.get to the built-in roles of
projects that hold an override snapshot. Downgrade must take back only what the
upgrade granted: a project admin who later gave the same permission to a custom
role (or re-granted it after removing ours) keeps that grant on rollback.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

PERMISSION = "configuration.secrets.private_secret.get"
LEDGER = f"{TABLE_PREFIX}__mig_202609251200_granted"
REVISION_FILE = "202609251200_grant_private_secret_perm_to_project_overrides.py"


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202609251200")


@pytest.fixture
def module():
    return types.SimpleNamespace(
        descriptor=types.SimpleNamespace(name=TABLE_PREFIX),
    )


@pytest.fixture
def tables(engine):
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__project_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
    )
    permission = sa.Table(
        f"{TABLE_PREFIX}__project_role_permission", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer, nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey(role.c.id)),
        sa.Column("permission", sa.Text, nullable=False),
        # Never reuse ids, like the Postgres sequence behind this table; plain SQLite
        # rowids recycle the max id after a delete, which the ledger relies on not happening.
        sqlite_autoincrement=True,
    )
    metadata.create_all(engine)
    return types.SimpleNamespace(role=role, permission=permission)


def run(revision_module, engine, module, direction="upgrade"):
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision_module, direction)(module, None)


def add_role(engine, tables, name):
    with engine.connect() as connection:
        return connection.execute(
            tables.role.insert().values(name=name)
        ).inserted_primary_key[0]


def grant(engine, tables, project_id, role_id, permission):
    with engine.connect() as connection:
        return connection.execute(
            tables.permission.insert().values(
                project_id=project_id, role_id=role_id, permission=permission,
            )
        ).inserted_primary_key[0]


def holders(engine, tables):
    with engine.connect() as connection:
        return set(connection.execute(
            sa.select(tables.permission.c.project_id, tables.permission.c.role_id)
            .where(tables.permission.c.permission == PERMISSION)
        ).all())


@pytest.fixture
def snapshot(engine, tables):
    """Project 1 has an override snapshot for viewer and a custom role."""
    viewer = add_role(engine, tables, "viewer")
    custom = add_role(engine, tables, "auditor")
    grant(engine, tables, 1, viewer, "models.read")
    grant(engine, tables, 1, custom, "models.read")
    return types.SimpleNamespace(viewer=viewer, custom=custom)


def test_upgrade_grants_builtin_roles_only(revision, engine, module, tables, snapshot):
    run(revision, engine, module)

    assert holders(engine, tables) == {(1, snapshot.viewer)}


def test_downgrade_removes_what_upgrade_granted(
        revision, engine, module, tables, snapshot,
):
    run(revision, engine, module)
    run(revision, engine, module, "downgrade")

    assert holders(engine, tables) == set()
    assert not sa.inspect(engine).has_table(LEDGER)


def test_downgrade_keeps_independent_grants(
        revision, engine, module, tables, snapshot,
):
    run(revision, engine, module)
    # After the upgrade a project admin grants it to a custom role themselves.
    grant(engine, tables, 1, snapshot.custom, PERMISSION)

    run(revision, engine, module, "downgrade")

    assert holders(engine, tables) == {(1, snapshot.custom)}


def test_downgrade_keeps_a_regrant_of_a_removed_row(
        revision, engine, module, tables, snapshot,
):
    run(revision, engine, module)
    with engine.connect() as connection:
        connection.execute(
            tables.permission.delete().where(tables.permission.c.permission == PERMISSION)
        )
    grant(engine, tables, 1, snapshot.viewer, PERMISSION)

    run(revision, engine, module, "downgrade")

    assert holders(engine, tables) == {(1, snapshot.viewer)}


def test_downgrade_without_ledger_touches_nothing(
        revision, engine, module, tables, snapshot,
):
    grant(engine, tables, 1, snapshot.viewer, PERMISSION)

    run(revision, engine, module, "downgrade")

    assert holders(engine, tables) == {(1, snapshot.viewer)}


def test_upgrade_with_nothing_to_grant_still_round_trips(
        revision, engine, module, tables,
):
    run(revision, engine, module)
    assert sa.inspect(engine).has_table(LEDGER)

    run(revision, engine, module, "downgrade")
    assert not sa.inspect(engine).has_table(LEDGER)
