"""Coverage for alembic revision 202611271200 (#7757).

Upgrade grants models.chat.conversations.manage_shared to project roles named admin
or editor that already carry override rows. Viewers and custom roles gain nothing,
projects without overrides are untouched. Downgrade removes only the rows the ledger
lists. The revision chain keeps a single head.
"""
import ast
import pathlib
import types

import pytest
import sqlalchemy as sa
from conftest import TABLE_PREFIX
from fixtures import helpers

alembic_migration = pytest.importorskip("alembic.migration")
alembic_operations = pytest.importorskip("alembic.operations")

MANAGE_SHARED = "models.chat.conversations.manage_shared"
OTHER = "models.chat.conversations.list"
LEDGER = f"{TABLE_PREFIX}__mig_202611271200_granted"
REVISION_FILE = "202611271200_grant_chat_manage_shared_to_project_overrides.py"


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
    return helpers.load_module_from_path(path, "revision_202611271200")


@pytest.fixture
def pylon_log(revision, monkeypatch):
    recorder = RecordingLog()
    monkeypatch.setattr(revision, "log", recorder)
    return recorder


@pytest.fixture
def module():
    return types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))


@pytest.fixture
def tables(engine):
    metadata = sa.MetaData()
    role = sa.Table(
        f"{TABLE_PREFIX}__project_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer, nullable=False),
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
    """Seeding and reading helpers; a project role belongs to one project."""

    def __init__(self, engine, tables):
        self.engine = engine
        self.tables = tables
        self.roles = {}

    def role(self, project_id, name):
        key = (project_id, name)
        if key not in self.roles:
            with self.engine.connect() as connection:
                self.roles[key] = connection.execute(
                    self.tables.role.insert().values(project_id=project_id, name=name)
                ).inserted_primary_key[0]
        return self.roles[key]

    def grant(self, project_id, role_name, *permissions):
        with self.engine.connect() as connection:
            for permission in permissions:
                connection.execute(self.tables.permission.insert().values(
                    project_id=project_id, role_id=self.role(project_id, role_name), permission=permission,
                ))

    def perms(self, project_id, role_name):
        perm = self.tables.permission
        with self.engine.connect() as connection:
            return sorted(connection.execute(
                sa.select(perm.c.permission).where(
                    perm.c.project_id == project_id,
                    perm.c.role_id == self.role(project_id, role_name),
                )
            ).scalars().all())

    def count(self):
        with self.engine.connect() as connection:
            return connection.execute(
                sa.select(sa.func.count()).select_from(self.tables.permission)
            ).scalar_one()


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


def ledger_ids(engine):
    with engine.connect() as connection:
        return set(connection.execute(sa.text(f"SELECT id FROM {LEDGER}")).scalars())


def test_admin_and_editor_with_overrides_get_the_permission(db, upgrade):
    db.grant(1, "admin", OTHER)
    db.grant(1, "editor", OTHER)

    upgrade()

    assert db.perms(1, "admin") == sorted([OTHER, MANAGE_SHARED])
    assert db.perms(1, "editor") == sorted([OTHER, MANAGE_SHARED])


def test_viewer_and_custom_roles_gain_nothing(db, upgrade):
    db.grant(1, "viewer", OTHER)
    db.grant(1, "team-lead", OTHER)

    upgrade()

    assert db.perms(1, "viewer") == [OTHER]
    assert db.perms(1, "team-lead") == [OTHER]


def test_role_without_override_rows_is_untouched(db, upgrade):
    # Such a project resolves through the role template, which already grants it
    db.role(2, "editor")
    db.grant(1, "admin", OTHER)

    upgrade()

    assert db.perms(2, "editor") == []


def test_existing_grant_is_kept_and_not_duplicated(db, engine, upgrade):
    db.grant(1, "editor", MANAGE_SHARED)
    db.grant(1, "admin", OTHER)
    before = db.count()

    upgrade()

    assert db.perms(1, "editor") == [MANAGE_SHARED]
    assert db.count() - before == 1
    assert len(ledger_ids(engine)) == 1


def test_downgrade_removes_only_ledger_rows(db, engine, upgrade, downgrade):
    db.grant(1, "editor", MANAGE_SHARED)
    db.grant(1, "admin", OTHER)
    upgrade()
    db.grant(1, "team-lead", MANAGE_SHARED)

    downgrade()

    assert db.perms(1, "admin") == [OTHER]
    assert db.perms(1, "editor") == [MANAGE_SHARED]
    assert db.perms(1, "team-lead") == [MANAGE_SHARED]
    assert not sa.inspect(engine).has_table(LEDGER)


def test_missing_ledger_warns_and_deletes_nothing(db, engine, upgrade, downgrade, pylon_log):
    db.grant(1, "admin", OTHER)
    upgrade()
    with engine.connect() as connection:
        connection.execute(sa.text(f"DROP TABLE {LEDGER}"))
    before = db.count()

    downgrade()

    assert db.count() == before
    assert any(LEDGER in warning for warning in pylon_log.warnings)


def test_upgrade_downgrade_upgrade_is_stable(db, upgrade, downgrade):
    db.grant(1, "admin", OTHER)

    upgrade()
    downgrade()
    upgrade()

    assert db.perms(1, "admin") == sorted([OTHER, MANAGE_SHARED])


def test_revision_chain_keeps_one_head(plugin_root: pathlib.Path):
    links = {}
    for path in (plugin_root / "db" / "migrations").glob("*.py"):
        values = {
            target.id: ast.literal_eval(node.value)
            for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id in ("revision", "down_revision")
        }
        if "revision" in values:
            down = values.get("down_revision")
            links[values["revision"]] = (down,) if isinstance(down, str) else tuple(down or ())
    parents = {parent for downs in links.values() for parent in downs}

    assert sorted(set(links) - parents) == ["202611271200"]
    assert links["202611271200"] == ("202611161200",)
