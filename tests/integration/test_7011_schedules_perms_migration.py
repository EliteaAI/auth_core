"""Coverage for alembic revision 202610191200 (EL-7011, US-46).

Upgrade grants the schedule permission family to override roles: six user
permissions to roles that may create or edit agents, three admin permissions to
roles named admin. Downgrade removes only the rows the ledger lists.
PostgreSQL parity (TC-US46-16) and the single head check (TC-US46-17, -18)
are outside this file.
"""
import pathlib
import types

import pytest
import sqlalchemy as sa
from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

PREFIX = "models.applications.schedules."
USER_PERMISSIONS = {PREFIX + name for name in (
    "list", "details", "create", "update", "delete", "run",
)}
ADMIN_PERMISSIONS = {PREFIX + name for name in ("admin", "export", "import")}
AGENT_CREATE = "models.applications.applications.create"
AGENT_UPDATE = "models.applications.application.update"
LEDGER = f"{TABLE_PREFIX}__mig_202610191200_granted"
REVISION_FILE = "202610191200_grant_schedules_perms_to_project_overrides.py"


class RecordingLog:
    def __init__(self):
        self.warnings = []

    def warning(self, message, *args):
        self.warnings.append(message % args if args else message)

    def __getattr__(self, _name):
        return lambda *a, **k: None


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    path = plugin_root / "db" / "migrations" / REVISION_FILE
    return helpers.load_module_from_path(path, "revision_202610191200")


@pytest.fixture
def pylon_log(revision, monkeypatch):
    recorder = RecordingLog()
    monkeypatch.setattr(revision, "log", recorder)
    return recorder


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
        # Ids never recycle, like the Postgres sequence the ledger relies on.
        sqlite_autoincrement=True,
    )
    metadata.create_all(engine)
    return types.SimpleNamespace(role=role, permission=permission)


class Db:
    """Small seeding and reading helpers over the two role tables."""

    def __init__(self, engine, tables):
        self.engine = engine
        self.tables = tables
        self.roles = {}

    def role(self, name):
        if name not in self.roles:
            with self.engine.connect() as connection:
                self.roles[name] = connection.execute(
                    self.tables.role.insert().values(name=name)
                ).inserted_primary_key[0]
        return self.roles[name]

    def grant(self, project_id, role_name, *permissions):
        with self.engine.connect() as connection:
            for permission in permissions:
                connection.execute(self.tables.permission.insert().values(
                    project_id=project_id, role_id=self.role(role_name),
                    permission=permission,
                ))

    def perms(self, project_id, role_name, prefix=PREFIX):
        perm = self.tables.permission
        with self.engine.connect() as connection:
            return sorted(connection.execute(
                sa.select(perm.c.permission).where(
                    perm.c.project_id == project_id,
                    perm.c.role_id == self.role(role_name),
                    perm.c.permission.like(prefix + "%"),
                )
            ).scalars().all())

    def count(self, project_id=None):
        perm = self.tables.permission
        query = sa.select(sa.func.count()).select_from(perm)
        if project_id is not None:
            query = query.where(perm.c.project_id == project_id)
        with self.engine.connect() as connection:
            return connection.execute(query).scalar_one()

    def duplicates(self):
        perm = self.tables.permission
        with self.engine.connect() as connection:
            return connection.execute(
                sa.select(perm.c.project_id, perm.c.role_id, perm.c.permission)
                .group_by(perm.c.project_id, perm.c.role_id, perm.c.permission)
                .having(sa.func.count() > 1)
            ).all()


@pytest.fixture
def db(engine, tables):
    return Db(engine, tables)


def run(revision_module, engine, module, direction="upgrade"):
    with engine.connect() as connection:
        context = alembic_migration.MigrationContext.configure(connection)
        operations = alembic_operations.Operations(context)
        with operations.context(context):
            getattr(revision_module, direction)(module, None)


@pytest.fixture
def upgrade(revision, engine, module):
    return lambda: run(revision, engine, module)


@pytest.fixture
def downgrade(revision, engine, module):
    return lambda: run(revision, engine, module, "downgrade")


# AC1: R1.1, R1.2

def test_el_7011_r1_1_agent_create_gets_user_permissions(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE)

    upgrade()

    assert db.perms(1, "editor") == sorted(USER_PERMISSIONS)


def test_el_7011_r1_1_agent_update_only_custom_role_gets_user_permissions(db, upgrade):
    db.grant(1, "team-lead", AGENT_UPDATE)

    upgrade()

    assert db.perms(1, "team-lead") == sorted(USER_PERMISSIONS)


def test_el_7011_r1_2_existing_rows_are_skipped(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE, PREFIX + "list", PREFIX + "run")
    before = db.count()

    upgrade()

    assert db.perms(1, "editor") == sorted(USER_PERMISSIONS)
    assert db.count() - before == 4


def test_el_7011_r1_1_grant_stays_in_the_project_with_agent_rights(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE)
    db.grant(2, "editor", "models.read")

    upgrade()

    assert db.perms(1, "editor") == sorted(USER_PERMISSIONS)
    assert db.perms(2, "editor") == []


# AC2: R2.1, R2.2

def test_el_7011_r2_1_admin_role_gets_admin_permissions(db, upgrade):
    db.grant(1, "admin", AGENT_CREATE)

    upgrade()

    assert db.perms(1, "admin") == sorted(USER_PERMISSIONS | ADMIN_PERMISSIONS)


def test_el_7011_r2_2_editor_gets_no_admin_permissions(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE, AGENT_UPDATE)

    upgrade()

    assert not set(db.perms(1, "editor")) & ADMIN_PERMISSIONS


@pytest.mark.parametrize("role_name", ["super_admin", "system"])
def test_el_7011_r2_2_other_admin_like_roles_get_user_permissions_only(
        db, upgrade, role_name,
):
    db.grant(1, role_name, AGENT_CREATE)

    upgrade()

    assert db.perms(1, role_name) == sorted(USER_PERMISSIONS)


# AC3: R1.3, R1.4

def test_el_7011_r1_3_only_agent_roles_gain_rows(db, upgrade):
    db.grant(1, "admin", AGENT_CREATE)
    db.grant(1, "editor", AGENT_UPDATE)
    db.grant(1, "viewer", "models.read")

    upgrade()

    assert db.perms(1, "admin")
    assert db.perms(1, "editor")
    assert db.perms(1, "viewer") == []


def test_el_7011_r1_3_viewer_row_count_is_unchanged(db, upgrade):
    db.grant(1, "viewer", "models.applications.applications.list",
             "models.applications.application.details")
    db.grant(1, "editor", AGENT_CREATE)
    before = len(db.perms(1, "viewer", prefix=""))

    upgrade()

    assert len(db.perms(1, "viewer", prefix="")) == before
    assert db.perms(1, "viewer") == []


def test_el_7011_r1_4_project_without_override_rows_is_unchanged(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE)
    db.role("admin")

    upgrade()

    assert db.count(project_id=3) == 0


# AC4: R3.1, R3.2, R3.3

def ledger_ids(engine):
    with engine.connect() as connection:
        return set(connection.execute(sa.text(f"SELECT id FROM {LEDGER}")).scalars())


def test_el_7011_r3_1_ledger_lists_every_inserted_row(db, engine, upgrade):
    db.grant(1, "admin", AGENT_CREATE)
    seeded = db.count()

    upgrade()

    assert len(ledger_ids(engine)) == db.count() - seeded == 9


def test_el_7011_r3_2_downgrade_removes_ledger_rows_and_drops_ledger(
        db, engine, upgrade, downgrade,
):
    db.grant(1, "editor", AGENT_CREATE)
    upgrade()

    downgrade()

    assert db.perms(1, "editor") == []
    assert db.perms(1, "editor", prefix="models.") == [AGENT_CREATE]
    assert not sa.inspect(engine).has_table(LEDGER)


def test_el_7011_r3_2_downgrade_keeps_a_later_admin_grant(db, upgrade, downgrade):
    db.grant(1, "editor", AGENT_CREATE)
    upgrade()
    db.grant(1, "reviewer", PREFIX + "list")

    downgrade()

    assert db.perms(1, "reviewer") == [PREFIX + "list"]
    assert db.perms(1, "editor") == []


def test_el_7011_r3_3_missing_ledger_warns_and_deletes_nothing(
        db, engine, upgrade, downgrade, pylon_log,
):
    db.grant(1, "editor", AGENT_CREATE)
    upgrade()
    with engine.connect() as connection:
        connection.execute(sa.text(f"DROP TABLE {LEDGER}"))
    before = db.count()

    downgrade()

    assert db.count() == before
    assert any(LEDGER in warning for warning in pylon_log.warnings)


# AC5: R1.2 (no duplicates, SQLite)

def test_el_7011_r1_2_upgrade_inserts_no_duplicate(db, upgrade):
    db.grant(1, "editor", AGENT_CREATE, PREFIX + "list")
    db.grant(1, "admin", AGENT_UPDATE)

    upgrade()

    assert db.duplicates() == []


def test_el_7011_r1_2_upgrade_downgrade_upgrade_adds_no_duplicate(
        db, upgrade, downgrade,
):
    db.grant(1, "editor", AGENT_CREATE, PREFIX + "run")

    upgrade()
    downgrade()
    upgrade()

    assert db.duplicates() == []
    assert db.perms(1, "editor") == sorted(USER_PERMISSIONS)
