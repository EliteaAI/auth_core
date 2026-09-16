"""Shared fixtures. Mirrors the runtime shape of auth_core's DB access."""
import pathlib
import sys
import types

import pytest
import sqlalchemy as sa

TESTS_DIR = pathlib.Path(__file__).resolve().parent
PLUGIN_ROOT = TESTS_DIR.parent

sys.path.insert(0, str(TESTS_DIR))

from fixtures import helpers  # noqa: E402  pylint: disable=C0413

helpers.install_pylon_stubs()

TABLE_PREFIX = "auth_core"
# 64 bytes: shorter keys make PyJWT warn on every HS512 encode.
SECRET_KEY = "test-secret-key-" + "0" * 48


@pytest.fixture(scope="session")
def plugin_root() -> pathlib.Path:
    return PLUGIN_ROOT


@pytest.fixture(scope="session")
def tokens(plugin_root: pathlib.Path):
    """The rpc/tokens.py module under test."""
    return helpers.import_plugin_module(plugin_root, "rpc.tokens")


@pytest.fixture(scope="session")
def credential_handlers(plugin_root: pathlib.Path):
    """The rpc/credential_handlers.py module under test."""
    return helpers.import_plugin_module(plugin_root, "rpc.credential_handlers")


@pytest.fixture(scope="session")
def users(plugin_root: pathlib.Path):
    """The rpc/users.py module under test."""
    return helpers.import_plugin_module(plugin_root, "rpc.users")


def define_tables(metadata: sa.MetaData) -> tuple:
    """Mirror the token and user DDL from migration 202202021633_core.

    Only the columns the token RPC touches are declared. Anything else would
    make these tests a test of the migration chain instead.
    """
    token = sa.Table(
        f"{TABLE_PREFIX}__token", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("uuid", sa.String(36), unique=True, index=True),
        sa.Column("expires", sa.DateTime, nullable=True),
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(f"{TABLE_PREFIX}__user.id", ondelete="CASCADE"),
            index=True,
        ),
        sa.Column("name", sa.Text),
    )
    user = sa.Table(
        f"{TABLE_PREFIX}__user", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("name", sa.Text, nullable=True),
        # From migration 202602241500. Auth reads it, so it is not optional here.
        sa.Column(
            "suspended", sa.Boolean, nullable=False,
            server_default=sa.text("false"),
        ),
    )
    return token, user


def create_system_token_index(engine: sa.Engine) -> None:
    """The partial unique index that migration 202609161200 adds.

    Declared here rather than by running the migration so the RPC tests do not
    need alembic; test_reserve_system_token_migration asserts the migration
    produces an index with the same effect.
    """
    with engine.connect() as connection:
        connection.execute(sa.text(
            f"CREATE UNIQUE INDEX uq_{TABLE_PREFIX}__token_system_per_user "
            f"ON {TABLE_PREFIX}__token (user_id) WHERE name = 'elitea-system'"
        ))


@pytest.fixture
def engine(tmp_path) -> sa.Engine:
    """File-backed SQLite in AUTOCOMMIT, as auth_core's engine runs.

    File-backed rather than in-memory because each RPC call opens its own
    connection, and the race test opens a second one while the first is held.
    """
    return sa.create_engine(
        f"sqlite:///{tmp_path / 'auth_core.db'}",
        isolation_level="AUTOCOMMIT",
    )


@pytest.fixture
def rpc(tokens, credential_handlers, users, engine):
    """A token RPC bound to a real engine, shaped like the live module.

    Pylon merges every rpc/*.py RPC class into one module instance, so the
    credential handlers and the user RPC are mixed in here too:
    handle_bearer_token calls decode_token, add_user writes to the token table,
    and all three read the same self.db.
    """
    metadata = sa.MetaData()
    token_tbl, user_tbl = define_tables(metadata)
    metadata.create_all(engine)
    create_system_token_index(engine)

    class Subject(tokens.RPC, credential_handlers.RPC, users.RPC):
        pass

    subject = Subject()
    subject.db = types.SimpleNamespace(
        engine=engine,
        url=str(engine.url),
        tbl=types.SimpleNamespace(token=token_tbl, user=user_tbl),
    )
    subject.context = types.SimpleNamespace(
        app=types.SimpleNamespace(secret_key=SECRET_KEY),
    )
    subject.tbl = subject.db.tbl

    return subject


def pytest_collection_modifyitems(items):
    for item in items:
        if "/unit/" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
