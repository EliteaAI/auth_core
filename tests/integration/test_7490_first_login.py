"""First login is recorded once, and only for a user who never logged in (#7490).

Users are created before they log in (SCIM, invites, the system user), so the
creation time is not the first login. Users that logged in before the column
existed have no real first login, so none is ever invented for them.
"""
import datetime
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX
from fixtures import helpers
from test_7011_migration_single_head import find_heads, read_links

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

REVISION = "202611121200"
PARENT_REVISION = "202611031200"
REVISION_FILE = f"{REVISION}_add_first_login_to_user.py"

FIRST = datetime.datetime(2026, 11, 12, 9, 0, 0)
LATER = datetime.datetime(2026, 11, 13, 9, 0, 0)


def add_user(rpc, user_id, last_login=None):
    with rpc.db.engine.connect() as connection:
        connection.execute(
            rpc.db.tbl.user.insert().values(
                id=user_id, email=f"user{user_id}@example.com", last_login=last_login,
            )
        )


def first_login(rpc, user_id):
    return rpc.get_user(user_id=user_id)["first_login"]


# --- RPC ------------------------------------------------------------------


def test_a_user_who_never_logged_in_gets_a_first_login(rpc):
    add_user(rpc, 1)

    assert rpc.record_first_login(1, FIRST) is True
    assert first_login(rpc, 1) == FIRST


def test_the_first_login_is_never_overwritten(rpc):
    add_user(rpc, 1)
    rpc.record_first_login(1, FIRST)

    assert rpc.record_first_login(1, LATER) is False
    assert first_login(rpc, 1) == FIRST


def test_a_user_who_already_logged_in_gets_none(rpc):
    """No real first login exists for them; the next login is not the first."""
    add_user(rpc, 1, last_login=FIRST)

    assert rpc.record_first_login(1, LATER) is False
    assert first_login(rpc, 1) is None


def test_after_the_login_completes_a_relogin_records_nothing(rpc):
    add_user(rpc, 1)
    rpc.record_first_login(1, FIRST)
    rpc.update_user(1, last_login=FIRST)

    rpc.record_first_login(1, LATER)

    assert first_login(rpc, 1) == FIRST


def test_an_unknown_user_records_nothing(rpc):
    assert rpc.record_first_login(404, FIRST) is False


def test_only_the_given_user_is_touched(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2)

    rpc.record_first_login(1, FIRST)

    assert first_login(rpc, 2) is None


# --- migration ------------------------------------------------------------


@pytest.fixture(scope="module")
def migrations_dir(plugin_root: pathlib.Path) -> pathlib.Path:
    return plugin_root / "db" / "migrations"


@pytest.fixture(scope="module")
def revision(migrations_dir):
    return helpers.load_module_from_path(migrations_dir / REVISION_FILE, f"revision_{REVISION}")


def run_migration(revision, engine, direction):
    module = types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision, direction)(module, None)


def columns(engine):
    return {c["name"]: c for c in sa.inspect(engine).get_columns(f"{TABLE_PREFIX}__user")}


@pytest.fixture
def pre_migration_user(engine):
    metadata = sa.MetaData()
    sa.Table(
        f"{TABLE_PREFIX}__user", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.Text),
        sa.Column("last_login", sa.DateTime, nullable=True),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(sa.text(
            f"INSERT INTO {TABLE_PREFIX}__user (id, email, last_login) "
            "VALUES (1, 'a@example.com', '2026-09-02 12:33:55')"
        ))


def test_the_revision_is_the_single_head(migrations_dir):
    links = read_links(migrations_dir)

    assert find_heads(links) == [REVISION]
    assert links[REVISION] == (PARENT_REVISION,)


@pytest.mark.usefixtures("pre_migration_user")
def test_upgrade_adds_a_nullable_column_without_backfill(revision, engine):
    run_migration(revision, engine, "upgrade")

    assert columns(engine)["first_login"]["nullable"] is True
    with engine.connect() as connection:
        value = connection.execute(sa.text(
            f"SELECT first_login FROM {TABLE_PREFIX}__user WHERE id = 1"
        )).scalar()
    assert value is None


@pytest.mark.usefixtures("pre_migration_user")
def test_downgrade_drops_the_column(revision, engine):
    run_migration(revision, engine, "upgrade")
    run_migration(revision, engine, "downgrade")

    assert "first_login" not in columns(engine)
