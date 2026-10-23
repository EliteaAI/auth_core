"""Alembic revision 202610151200: revocation_epoch on user and token (#6944).

Both columns are BIGINT NOT NULL DEFAULT 0, the upgrade and the downgrade can be
re-run safely, and rows that exist before the upgrade start at epoch 0.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION_FILE = "202610151200_add_revocation_epoch.py"


@pytest.fixture(scope="module")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202610151200")


@pytest.fixture
def pre_migration_tables(engine):
    """User and token as they were before the revision: no epoch column."""
    metadata = sa.MetaData()
    sa.Table(
        f"{TABLE_PREFIX}__user", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("suspended", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    sa.Table(
        f"{TABLE_PREFIX}__token", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("uuid", sa.String(36)),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(sa.text(f"INSERT INTO {TABLE_PREFIX}__user (id) VALUES (1)"))
        connection.execute(sa.text(f"INSERT INTO {TABLE_PREFIX}__token (id, uuid) VALUES (1, 'u')"))


def run_migration(revision, engine, direction):
    module = types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision, direction)(module, None)


def columns(engine, table):
    return {c["name"]: c for c in sa.inspect(engine).get_columns(f"{TABLE_PREFIX}__{table}")}


def test_revision_chains_onto_the_current_head(revision):
    assert revision.revision == "202610151200"
    assert revision.down_revision == "202610051500"


def test_upgrade_adds_both_columns_defaulting_existing_rows_to_zero(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")

    for table in ("user", "token"):
        column = columns(engine, table)["revocation_epoch"]
        assert column["nullable"] is False
        assert isinstance(column["type"], sa.BigInteger) or "INT" in str(column["type"]).upper()
    with engine.connect() as connection:
        assert connection.execute(sa.text(f"SELECT revocation_epoch FROM {TABLE_PREFIX}__user")).scalar() == 0
        assert connection.execute(sa.text(f"SELECT revocation_epoch FROM {TABLE_PREFIX}__token")).scalar() == 0


def test_upgrade_is_idempotent(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "upgrade")

    assert "revocation_epoch" in columns(engine, "user")


def test_downgrade_drops_the_columns_and_is_idempotent(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "downgrade")
    run_migration(revision, engine, "downgrade")

    assert "revocation_epoch" not in columns(engine, "user")
    assert "revocation_epoch" not in columns(engine, "token")
