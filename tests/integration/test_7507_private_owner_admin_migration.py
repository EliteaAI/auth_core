"""Alembic revision 202611131200 (#7507): the verified owner of each private project gets its project admin role.

Verified means the project is named ``project_user_<uid>``, its owner_id is ``uid`` and ``uid`` is a member. Nobody
else gains anything; unverified projects and non-owners already holding admin are reported, not changed. A re-run
inserts nothing, granted owners' revocation epochs are bumped, and downgrade removes only the ledger's rows.
"""
import pathlib
import sys
import types

import pytest
import sqlalchemy as sa
from conftest import TABLE_PREFIX
from fixtures import helpers

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_7011_migration_single_head import find_heads, read_links
from test_7011_schedules_perms_migration import RecordingLog, run  # noqa: F401  pylint: disable=W0611

REVISION_FILE = "202611131200_private_owner_admin_role.py"
LEDGER = f"{TABLE_PREFIX}__mig_202611131200_granted"


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    return helpers.load_module_from_path(plugin_root / "db" / "migrations" / REVISION_FILE, "revision_202611131200")


@pytest.fixture
def pylon_log(revision, monkeypatch):
    recorder = RecordingLog()
    monkeypatch.setattr(revision, "log", recorder)
    return recorder


@pytest.fixture
def module():
    return types.SimpleNamespace(descriptor=types.SimpleNamespace(name=TABLE_PREFIX))


class Db:
    def __init__(self, engine):
        self.engine = engine
        metadata = sa.MetaData()
        self.project = sa.Table(
            "project", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("owner_id", sa.Integer, nullable=False),
        )
        self.user = sa.Table(
            f"{TABLE_PREFIX}__user", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("revocation_epoch", sa.BigInteger, nullable=False, server_default=sa.text("0")),
        )
        self.role = sa.Table(
            f"{TABLE_PREFIX}__project_role", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("project_id", sa.Integer, nullable=False),
            sa.Column("name", sa.Text, nullable=False),
            sa.UniqueConstraint("project_id", "name"),
        )
        self.user_role = sa.Table(
            f"{TABLE_PREFIX}__project_user_role", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("project_id", sa.Integer, nullable=False),
            sa.Column("user_id", sa.Integer),
            sa.Column("role_id", sa.Integer),
            sa.UniqueConstraint("project_id", "user_id", "role_id"),
            sqlite_autoincrement=True,
        )
        metadata.create_all(engine)

    def add_project(self, project_id, name, owner_id, roles=("admin", "editor", "viewer", "system")):
        with self.engine.connect() as connection:
            connection.execute(self.project.insert().values(id=project_id, name=name, owner_id=owner_id))
            for role in roles:
                connection.execute(self.role.insert().values(project_id=project_id, name=role))

    def add_member(self, project_id, user_id, *roles):
        with self.engine.connect() as connection:
            if connection.execute(sa.select(self.user.c.id).where(self.user.c.id == user_id)).first() is None:
                connection.execute(self.user.insert().values(id=user_id))
            for role in roles:
                role_id = connection.execute(sa.select(self.role.c.id).where(
                    self.role.c.project_id == project_id, self.role.c.name == role)).scalar_one()
                connection.execute(self.user_role.insert().values(
                    project_id=project_id, user_id=user_id, role_id=role_id))

    def roles(self, project_id, user_id):
        with self.engine.connect() as connection:
            return sorted(connection.execute(
                sa.select(self.role.c.name).select_from(
                    self.user_role.join(self.role, self.role.c.id == self.user_role.c.role_id)
                ).where(self.user_role.c.project_id == project_id, self.user_role.c.user_id == user_id)
            ).scalars())

    def epoch(self, user_id):
        with self.engine.connect() as connection:
            return connection.execute(
                sa.select(self.user.c.revocation_epoch).where(self.user.c.id == user_id)).scalar_one()

    def count(self):
        with self.engine.connect() as connection:
            return connection.execute(sa.select(sa.func.count()).select_from(self.user_role)).scalar_one()


@pytest.fixture
def db(engine):
    return Db(engine)


@pytest.fixture
def upgrade(revision, engine, module, pylon_log):
    return lambda: run(revision, engine, module)


@pytest.fixture
def downgrade(revision, engine, module, pylon_log):
    return lambda: run(revision, engine, module, "downgrade")


def _private(db, project_id, owner, *owner_roles):
    db.add_project(project_id, f"project_user_{owner}", owner)
    db.add_member(project_id, owner, *(owner_roles or ("editor", "viewer")))
    db.add_member(project_id, owner + 100, "system")


def test_the_revision_is_the_one_head_on_top_of_first_login(revision, plugin_root):
    assert (revision.revision, revision.down_revision) == ("202611131200", "202611121200")
    assert len(find_heads(read_links(plugin_root / "db" / "migrations"))) == 1


def test_verified_owner_gets_admin_and_keeps_editor_viewer(db, upgrade):
    _private(db, 3, 1)

    upgrade()

    assert db.roles(3, 1) == ["admin", "editor", "viewer"]


def test_system_user_and_other_members_gain_nothing(db, upgrade):
    _private(db, 3, 1)
    db.add_member(3, 9, "viewer")

    upgrade()

    assert db.roles(3, 101) == ["system"]
    assert db.roles(3, 9) == ["viewer"]


def test_team_projects_are_untouched(db, upgrade):
    db.add_project(10, "Team Project", 5)
    db.add_member(10, 5, "editor")
    db.add_member(10, 6, "viewer")

    upgrade()

    assert db.roles(10, 5) == ["editor"] and db.roles(10, 6) == ["viewer"]


def test_rerun_inserts_nothing(db, upgrade):
    _private(db, 3, 1)
    upgrade()
    before = db.count()

    upgrade()

    assert db.count() == before
    assert db.roles(3, 1) == ["admin", "editor", "viewer"] and db.epoch(1) == 1


def test_owner_already_admin_is_left_as_is(db, upgrade, engine):
    _private(db, 3, 1, "admin", "editor", "viewer")

    upgrade()

    assert db.roles(3, 1) == ["admin", "editor", "viewer"]
    with engine.connect() as connection:
        assert connection.execute(sa.text(f"SELECT COUNT(*) FROM {LEDGER}")).scalar_one() == 0


@pytest.mark.parametrize("name, owner_id, member", [
    ("project_user_1", 2, 1),      # owner_id disagrees with the name
    ("project_user_1", 1, None),   # owner is not a member
    ("project_user_x", 1, 1),      # unparsable owner id
])
def test_unverified_private_project_is_reported_and_untouched(db, upgrade, pylon_log, name, owner_id, member):
    db.add_project(3, name, owner_id)
    if member is not None:
        db.add_member(3, member, "editor", "viewer")
    before = db.count()

    upgrade()

    assert db.count() == before
    assert any("3" in warning and "unverified" in warning for warning in pylon_log.warnings)


def test_private_project_without_admin_role_is_reported(db, upgrade, pylon_log):
    db.add_project(3, "project_user_1", 1, roles=("editor", "viewer"))
    db.add_member(3, 1, "editor", "viewer")

    upgrade()

    assert db.roles(3, 1) == ["editor", "viewer"]
    assert any("3" in warning and "admin role" in warning for warning in pylon_log.warnings)


def test_non_owner_admin_is_reported_not_removed(db, upgrade, pylon_log):
    _private(db, 4, 6)
    db.add_member(4, 3, "admin")

    upgrade()

    assert db.roles(4, 3) == ["admin"]
    assert any("non-owner" in warning and "4" in warning and "3" in warning for warning in pylon_log.warnings)


def test_granted_owner_epoch_is_bumped_others_not(db, upgrade):
    _private(db, 3, 1)
    _private(db, 5, 2, "admin", "editor", "viewer")

    upgrade()

    assert db.epoch(1) == 1
    assert db.epoch(2) == 0
    assert db.epoch(101) == 0


def test_downgrade_removes_only_the_ledgers_rows(db, upgrade, downgrade, engine):
    _private(db, 3, 1)
    _private(db, 5, 2, "admin", "editor", "viewer")
    upgrade()

    downgrade()

    assert db.roles(3, 1) == ["editor", "viewer"]
    assert db.roles(5, 2) == ["admin", "editor", "viewer"]
    assert not sa.inspect(engine).has_table(LEDGER)


def test_downgrade_without_the_ledger_leaves_everything(db, engine, revision, module, pylon_log):
    _private(db, 3, 1, "admin", "editor", "viewer")

    run(revision, engine, module, "downgrade")

    assert db.roles(3, 1) == ["admin", "editor", "viewer"]
    assert pylon_log.warnings == [f"{LEDGER} missing; leaving project user roles untouched"]


def test_missing_project_table_is_a_noop(engine, revision, module, pylon_log):
    run(revision, engine, module)

    assert sa.inspect(engine).has_table(LEDGER)
    assert any("project table missing" in warning for warning in pylon_log.warnings)
