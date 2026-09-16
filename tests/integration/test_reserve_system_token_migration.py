"""Coverage for alembic revision 202609161200 (issue #5262).

The revision has to hold two things true before any provisioning code runs:
every row carrying the reserved name is out of it, and the database itself
forbids a second system token per user. The eviction has to preserve the uuid
and the expiry, otherwise it is a promotion in disguise.
"""
import datetime
import pathlib
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX, define_tables
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

SYSTEM_TOKEN_NAME = "elitea-system"
TOKEN_TABLE = f"{TABLE_PREFIX}__token"
INDEX_NAME = f"uq_{TOKEN_TABLE}_system_per_user"

FUTURE = datetime.datetime(2030, 1, 1, 12, 0, 0)

REVISION_FILE = "202609161200_reserve_system_token_name.py"


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202609161200")


class RecordingLog:
    """Captures the eviction record the way an operator would read it."""

    def __init__(self):
        self.warnings = []

    def warning(self, message, *args):
        self.warnings.append(message % args if args else message)

    def __getattr__(self, _name):
        return lambda *a, **k: None

    @property
    def text(self):
        return "\n".join(self.warnings)


@pytest.fixture
def pylon_log(revision, monkeypatch):
    recorder = RecordingLog()
    monkeypatch.setattr(revision, "log", recorder)
    return recorder


@pytest.fixture
def module():
    """What the revision reads: module.descriptor.name is the table prefix."""
    return types.SimpleNamespace(
        descriptor=types.SimpleNamespace(name=TABLE_PREFIX),
    )


@pytest.fixture
def token_tbl(engine):
    metadata = sa.MetaData()
    token, _ = define_tables(metadata)
    metadata.create_all(engine)
    return token


def run(revision_module, engine, module, direction="upgrade"):
    """Apply the revision the way alembic does, against this engine."""
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision_module, direction)(module, None)


def insert(engine, token_tbl, user_id, name, uuid, expires=None):
    with engine.connect() as connection:
        return connection.execute(
            token_tbl.insert().values(
                uuid=uuid, user_id=user_id, name=name, expires=expires,
            )
        ).inserted_primary_key[0]


def fetch(engine, token_tbl, token_id):
    with engine.connect() as connection:
        return connection.execute(
            sa.select(token_tbl).where(token_tbl.c.id == token_id)
        ).mappings().one()


def indexes(engine):
    return {index["name"] for index in sa.inspect(engine).get_indexes(TOKEN_TABLE)}


def test_upgrade_evicts_a_reserved_name_row(revision, engine, module, token_tbl):
    token_id = insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "squatter-uuid")

    run(revision, engine, module)

    evicted = fetch(engine, token_tbl, token_id)
    assert evicted["name"] == f"{SYSTEM_TOKEN_NAME}-conflict-{token_id}"


def test_upgrade_preserves_uuid_and_expiry(revision, engine, module, token_tbl):
    """A rename, not a promotion: the row stays the token its owner created."""
    token_id = insert(
        engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE,
    )

    run(revision, engine, module)

    evicted = fetch(engine, token_tbl, token_id)
    assert evicted["uuid"] == "squatter-uuid"
    assert evicted["expires"] == FUTURE


def test_upgrade_evicts_duplicates_for_the_same_user(
        revision, engine, module, token_tbl,
):
    """Without this the index could not be built at all."""
    first = insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "first")
    second = insert(
        engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "second", expires=FUTURE,
    )

    run(revision, engine, module)

    assert fetch(engine, token_tbl, first)["name"] == \
        f"{SYSTEM_TOKEN_NAME}-conflict-{first}"
    assert fetch(engine, token_tbl, second)["name"] == \
        f"{SYSTEM_TOKEN_NAME}-conflict-{second}"
    assert INDEX_NAME in indexes(engine)


def test_upgrade_leaves_other_tokens_alone(revision, engine, module, token_tbl):
    ordinary = insert(engine, token_tbl, 1, f"{SYSTEM_TOKEN_NAME}-2", "mine")

    run(revision, engine, module)

    assert fetch(engine, token_tbl, ordinary)["name"] == f"{SYSTEM_TOKEN_NAME}-2"


# --- the eviction has to be findable afterwards ----------------------------


def test_each_evicted_row_is_logged(revision, engine, module, token_tbl, pylon_log):
    """A rollback cannot restore the old name, so who was renamed has to be recorded."""
    first = insert(engine, token_tbl, 7, SYSTEM_TOKEN_NAME, "first")
    second = insert(engine, token_tbl, 9, SYSTEM_TOKEN_NAME, "second")

    run(revision, engine, module)

    assert f"Renamed token {first} of user 7" in pylon_log.text
    assert f"Renamed token {second} of user 9" in pylon_log.text
    assert "Renamed 2 token(s) out of the reserved name" in pylon_log.text


def test_a_clean_table_logs_nothing(revision, engine, module, token_tbl, pylon_log):
    """The expected case must not leave a line that reads like a finding."""
    insert(engine, token_tbl, 1, "mine", "mine-uuid")

    run(revision, engine, module)

    assert pylon_log.warnings == []


def test_upgrade_creates_the_index(revision, engine, module, token_tbl):
    run(revision, engine, module)

    assert INDEX_NAME in indexes(engine)


def test_index_forbids_a_second_system_token(revision, engine, module, token_tbl):
    run(revision, engine, module)

    insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "first")

    with pytest.raises(sa.exc.IntegrityError):
        insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "second")


def test_index_is_partial(revision, engine, module, token_tbl):
    """Only the reserved name is constrained; ordinary names repeat freely."""
    run(revision, engine, module)

    insert(engine, token_tbl, 1, "mine", "first")
    insert(engine, token_tbl, 1, "mine", "second")

    insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "system")
    insert(engine, token_tbl, 2, SYSTEM_TOKEN_NAME, "other-user-system")


def test_upgrade_on_a_clean_table_is_a_no_op_apart_from_the_index(
        revision, engine, module, token_tbl,
):
    """The expected case on any normal environment."""
    ordinary = insert(engine, token_tbl, 1, "mine", "mine-uuid", expires=FUTURE)

    run(revision, engine, module)

    assert dict(fetch(engine, token_tbl, ordinary)) == {
        "id": ordinary,
        "uuid": "mine-uuid",
        "expires": FUTURE,
        "user_id": 1,
        "name": "mine",
    }


def test_downgrade_drops_the_index_and_keeps_the_evictions(
        revision, engine, module, token_tbl,
):
    token_id = insert(engine, token_tbl, 1, SYSTEM_TOKEN_NAME, "squatter-uuid")

    run(revision, engine, module)
    run(revision, engine, module, direction="downgrade")

    assert INDEX_NAME not in indexes(engine)
    assert fetch(engine, token_tbl, token_id)["name"] == \
        f"{SYSTEM_TOKEN_NAME}-conflict-{token_id}"
