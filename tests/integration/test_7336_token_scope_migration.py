"""Alembic revision 202611021200: the scope columns of API tokens (C-1009, #7336).

Two nullable JSON columns; tokens that exist before the upgrade stay unscoped; both directions can be re-run.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION_FILE = "202611021200_add_token_scope.py"


# --- migration ---------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202611021200")


@pytest.fixture
def pre_migration_token(engine):
    """The token table as it is before the revision, with one legacy row."""
    metadata = sa.MetaData()
    sa.Table(
        f"{TABLE_PREFIX}__token", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("uuid", sa.String(36)),
        sa.Column("expires", sa.DateTime, nullable=True),
        sa.Column("user_id", sa.Integer),
        sa.Column("name", sa.Text),
        sa.Column("revocation_epoch", sa.BigInteger, nullable=False, server_default=sa.text("0")),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(sa.text(
            f"INSERT INTO {TABLE_PREFIX}__token (id, uuid, user_id, name) VALUES (1, 'u', 7, 'api')"))


def run_migration(revision, engine, direction):
    module = types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision, direction)(module, None)


def token_columns(engine):
    return {c["name"]: c for c in sa.inspect(engine).get_columns(f"{TABLE_PREFIX}__token")}


def test_revision_chains_onto_the_current_head(revision):
    assert (revision.revision, revision.down_revision) == ("202611021200", "202610191200")


def test_upgrade_adds_two_nullable_columns_and_existing_tokens_stay_unscoped(revision, engine, pre_migration_token):
    run_migration(revision, engine, "upgrade")

    columns = token_columns(engine)
    assert columns["scope_projects"]["nullable"] is True and columns["scope_operations"]["nullable"] is True
    with engine.connect() as connection:
        row = connection.execute(sa.text(
            f"SELECT scope_projects, scope_operations, name FROM {TABLE_PREFIX}__token WHERE id = 1")).one()
    assert tuple(row) == (None, None, "api")


def test_upgrade_and_downgrade_are_idempotent(revision, engine, pre_migration_token):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "downgrade")
    run_migration(revision, engine, "downgrade")

    columns = token_columns(engine)
    assert "scope_projects" not in columns and "scope_operations" not in columns
    with engine.connect() as connection:
        assert connection.execute(sa.text(f"SELECT name FROM {TABLE_PREFIX}__token WHERE id = 1")).scalar() == "api"


def test_the_downgrade_says_how_many_scoped_tokens_it_unscopes(revision, engine, pre_migration_token, monkeypatch):
    warnings = []
    monkeypatch.setattr(revision, "log", types.SimpleNamespace(warning=lambda msg, *a: warnings.append(msg % a)))
    run_migration(revision, engine, "upgrade")
    with engine.connect() as connection:
        connection.execute(sa.text(
            f"INSERT INTO {TABLE_PREFIX}__token (id, uuid, user_id, name, scope_projects, scope_operations) "
            "VALUES (2, 'v', 7, 'ci', '[2]', '[\"run\"]')"))
    run_migration(revision, engine, "downgrade")
    assert warnings == ["Downgrade unscopes 1 scoped API token(s): they keep their expiry"]
