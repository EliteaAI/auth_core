"""Alembic revision 202610160900: IdP subject columns on user (#6941).

Three nullable TEXT columns and a partial unique index over them that only
constrains rows where all three are set. The upgrade and the downgrade can be
re-run safely and rows that exist before the upgrade are left untouched.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION_FILE = "202610160900_add_idp_subject_to_user.py"
INDEX = f"uq_{TABLE_PREFIX}__user_idp_subject"
NEW_COLUMNS = {"idp_issuer", "idp_tid", "idp_oid"}


@pytest.fixture(scope="module")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202610160900")


@pytest.fixture
def pre_migration_tables(engine):
    """User as it was before the revision: no subject columns."""
    metadata = sa.MetaData()
    sa.Table(
        f"{TABLE_PREFIX}__user", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), nullable=True),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(sa.text(
            f"INSERT INTO {TABLE_PREFIX}__user (id, email) VALUES (1, 'a@example.com')"
        ))


def run_migration(revision, engine, direction):
    module = types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision, direction)(module, None)


def columns(engine):
    return {c["name"]: c for c in sa.inspect(engine).get_columns(f"{TABLE_PREFIX}__user")}


def indexes(engine):
    return {i["name"]: i for i in sa.inspect(engine).get_indexes(f"{TABLE_PREFIX}__user")}


def insert(engine, user_id, issuer=None, tid=None, oid=None):
    with engine.connect() as connection:
        connection.execute(
            sa.text(
                f"INSERT INTO {TABLE_PREFIX}__user (id, email, idp_issuer, idp_tid, idp_oid) "
                "VALUES (:id, :email, :i, :t, :o)"
            ),
            {"id": user_id, "email": f"u{user_id}@example.com", "i": issuer, "t": tid, "o": oid},
        )


def test_revision_chains_onto_the_current_head(revision):
    assert revision.revision == "202610160900"
    assert revision.down_revision == "202610151200"


def test_upgrade_adds_nullable_text_columns_and_keeps_existing_rows(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")

    found = columns(engine)
    for name in NEW_COLUMNS:
        assert found[name]["nullable"] is True
        assert "TEXT" in str(found[name]["type"]).upper()
    with engine.connect() as connection:
        row = connection.execute(sa.text(
            f"SELECT idp_issuer, idp_tid, idp_oid FROM {TABLE_PREFIX}__user WHERE id = 1"
        )).one()
    assert tuple(row) == (None, None, None)


def test_upgrade_creates_a_unique_index_over_the_three_columns(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")

    index = indexes(engine)[INDEX]
    assert index["unique"]
    assert list(index["column_names"]) == ["idp_issuer", "idp_tid", "idp_oid"]


def test_the_index_rejects_a_duplicate_full_subject(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")
    insert(engine, 10, "iss", "tid", "oid")

    with pytest.raises(sa.exc.IntegrityError):
        insert(engine, 11, "iss", "tid", "oid")


def test_the_index_ignores_rows_with_any_part_missing(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")

    insert(engine, 10)
    insert(engine, 11)
    insert(engine, 12, "iss", "tid", None)
    insert(engine, 13, "iss", "tid", None)


def test_upgrade_is_idempotent(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "upgrade")

    assert NEW_COLUMNS <= set(columns(engine))
    assert INDEX in indexes(engine)


def test_downgrade_drops_index_and_columns_and_is_idempotent(revision, engine, pre_migration_tables):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "downgrade")
    run_migration(revision, engine, "downgrade")

    assert not NEW_COLUMNS & set(columns(engine))
    assert INDEX not in indexes(engine)
