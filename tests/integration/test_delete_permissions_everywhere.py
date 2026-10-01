"""delete_permissions_everywhere removes exact permission strings from every grant table.

Only the four permission tables are declared, with just the columns the RPC
reads. Dry run must count without deleting; a real run must touch only the
listed strings and never a longer string sharing the prefix.
"""
import types

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX, helpers

TABLES = ("role_permission", "project_role_permission", "group_permission", "user_permission")


@pytest.fixture(scope="session")
def roles(plugin_root):
    return helpers.import_plugin_module(plugin_root, "rpc.roles")


@pytest.fixture
def subject(roles, engine):
    metadata = sa.MetaData()
    tbl = types.SimpleNamespace()
    for name in TABLES:
        setattr(tbl, name, sa.Table(
            f"{TABLE_PREFIX}__{name}", metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner", sa.Integer),
            sa.Column("permission", sa.String(64)),
        ))
    metadata.create_all(engine)

    obj = roles.RPC()
    obj.db = types.SimpleNamespace(engine=engine, url=str(engine.url), tbl=tbl)
    return obj


def seed(subject, permissions):
    with subject.db.engine.connect() as connection:
        for name in TABLES:
            for owner, perm in enumerate(permissions):
                connection.execute(
                    getattr(subject.db.tbl, name).insert().values(owner=owner, permission=perm)
                )


def remaining(subject, name):
    tbl = getattr(subject.db.tbl, name)
    with subject.db.engine.connect() as connection:
        return sorted(r[0] for r in connection.execute(sa.select(tbl.c.permission)))


SEEDED = ["projects", "projects.projects", "configuration", "runtime.plugins"]


def test_dry_run_counts_and_keeps_rows(subject):
    seed(subject, SEEDED)

    result = subject.delete_permissions_everywhere(["projects", "configuration"])

    assert result == {"dry_run": True, "deleted": {name: 2 for name in TABLES}}
    for name in TABLES:
        assert remaining(subject, name) == sorted(SEEDED)


def test_real_run_deletes_only_exact_strings(subject):
    seed(subject, SEEDED)

    result = subject.delete_permissions_everywhere(["projects", "configuration"], dry_run=False)

    assert result["deleted"] == {name: 2 for name in TABLES}
    for name in TABLES:
        # projects.projects shares the prefix but is a real permission and must survive.
        assert remaining(subject, name) == ["projects.projects", "runtime.plugins"]


def test_rerun_is_a_noop(subject):
    seed(subject, SEEDED)
    subject.delete_permissions_everywhere(["projects"], dry_run=False)

    result = subject.delete_permissions_everywhere(["projects"], dry_run=False)

    assert result["deleted"] == {name: 0 for name in TABLES}


@pytest.mark.parametrize("permissions", [[], None, ["", None]])
def test_empty_list_touches_nothing(subject, permissions):
    seed(subject, SEEDED)

    result = subject.delete_permissions_everywhere(permissions, dry_run=False)

    assert result["deleted"] == {name: 0 for name in TABLES}
    for name in TABLES:
        assert remaining(subject, name) == sorted(SEEDED)
