"""Alembic revision 202611031200 (#7269): the project governance permissions for override projects.

Project roles named admin of a project with override rows get the operator permissions (bindings, mandates,
credentials) and governance.request; project roles named editor get governance.request only; viewers, the system role
and custom roles nothing; a project without override rows is untouched (it falls back to the templates, which the
plugins register). Downgrade removes only the rows the ledger lists. The tables are the ones of the #7011 test.
"""
import pathlib
import sys

import pytest
import sqlalchemy as sa
from conftest import TABLE_PREFIX
from fixtures import helpers

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_7011_migration_single_head import find_heads, read_links
from test_7011_schedules_perms_migration import (  # noqa: F401  pylint: disable=W0611
    Db, RecordingLog, db, downgrade, module, pylon_log, run, tables, upgrade,
)

REVISION_FILE = "202611031200_grant_governance_perms_to_project_overrides.py"
LEDGER = f"{TABLE_PREFIX}__mig_202611031200_granted"
OPERATOR = {
    "governance.bindings.view", "governance.bindings.manage", "governance.bindings.approve",
    "governance.mandates.view", "governance.mandates.manage", "governance.mandates.approve",
    "credentials.view", "credentials.manage", "credentials.probe", "credentials.approve",
}
REQUEST = {"governance.request"}
ANY = "models.applications.applications.list"


@pytest.fixture(scope="session")
def revision(plugin_root: pathlib.Path):
    return helpers.load_module_from_path(plugin_root / "db" / "migrations" / REVISION_FILE, "revision_202611031200")


def governance(db, project_id, role):
    return set(db.perms(project_id, role, prefix="governance.")) | set(db.perms(project_id, role, prefix="credentials."))


def test_the_revision_is_the_one_head_on_top_of_the_token_scope(revision, plugin_root):
    assert (revision.revision, revision.down_revision) == ("202611031200", "202611021200")
    assert find_heads(read_links(plugin_root / "db" / "migrations")) == ["202611031200"]


def test_admins_get_the_operator_and_request_permissions_editors_the_request_only(db, upgrade):
    for role in ("admin", "editor", "viewer", "system", "team-lead"):
        db.grant(1, role, ANY)

    upgrade()

    assert governance(db, 1, "admin") == OPERATOR | REQUEST
    assert governance(db, 1, "editor") == REQUEST
    for role in ("viewer", "system", "team-lead"):
        assert governance(db, 1, role) == set(), role


def test_a_project_without_override_rows_is_untouched(db, upgrade):
    db.grant(1, "admin", ANY)
    db.role("editor")

    upgrade()

    assert db.count(project_id=2) == 0 and governance(db, 1, "editor") == set()


def test_existing_rows_are_kept_and_not_duplicated(db, upgrade):
    db.grant(1, "admin", ANY, "credentials.view", "governance.request")
    before = db.count()

    upgrade()

    assert db.count() - before == len(OPERATOR | REQUEST) - 2
    assert db.duplicates() == []


def test_the_upgrade_is_per_project(db, upgrade):
    db.grant(1, "admin", ANY)
    db.grant(2, "viewer", ANY)

    upgrade()

    assert governance(db, 1, "admin") == OPERATOR | REQUEST and governance(db, 2, "viewer") == set()


def _ledger(engine):
    with engine.connect() as connection:
        return set(connection.execute(sa.text(f"SELECT id FROM {LEDGER}")).scalars())


def test_downgrade_removes_only_the_ledgers_rows(db, engine, upgrade, downgrade):
    db.grant(1, "admin", ANY, "credentials.view")
    db.grant(1, "editor", ANY)
    upgrade()
    assert len(_ledger(engine)) == len(OPERATOR | REQUEST) - 1 + 1
    db.grant(3, "admin", "credentials.manage")   # granted by a project admin later: kept

    downgrade()

    assert governance(db, 1, "admin") == {"credentials.view"}
    assert governance(db, 1, "editor") == set()
    assert db.perms(3, "admin", prefix="credentials.") == ["credentials.manage"]
    assert not sa.inspect(engine).has_table(LEDGER)


def test_downgrade_without_the_ledger_leaves_everything(db, engine, revision, module, pylon_log):
    db.grant(1, "admin", "credentials.view")

    run(revision, engine, module, "downgrade")

    assert governance(db, 1, "admin") == {"credentials.view"}
    assert pylon_log.warnings == [f"{LEDGER} missing; leaving project role permissions untouched"]
