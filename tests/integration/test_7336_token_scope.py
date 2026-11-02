"""Scoped, expiring API tokens (C-1009, #7336): add_token.

A token is scoped when it names its projects and operations and expires. add_token
checks the scope whoever calls it: the projects are ones the owner is a member of
(one error whether a project exists or not), the operations are known, the expiry is
set, in the future and at most SCOPED_TOKEN_MAX_TTL_DAYS away. A token without a
scope is written exactly as before, and system tokens are untouched. The migration is
covered in test_7336_token_scope_migration.py.
"""
import datetime

import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX

SOON = datetime.timedelta(days=30)


# --- add_token ---------------------------------------------------------------------------------

@pytest.fixture
def scoped_rpc(rpc, tokens, project_roles, engine):
    """The token RPC with the project membership RPC mixed in, as Pylon merges them; user 7 is a member of 3 and 5."""
    metadata = sa.MetaData()
    project_user_role = sa.Table(
        f"{TABLE_PREFIX}__project_user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer), sa.Column("user_id", sa.Integer), sa.Column("role_id", sa.Integer),
    )
    metadata.create_all(engine)
    with engine.connect() as connection:
        connection.execute(rpc.db.tbl.user.insert().values(id=7, email="u7@example.com"))
        connection.execute(rpc.db.tbl.user.insert().values(id=8, email="u8@example.com"))
        for project_id in (3, 5):
            connection.execute(project_user_role.insert().values(project_id=project_id, user_id=7, role_id=1))
        connection.execute(project_user_role.insert().values(project_id=4, user_id=8, role_id=1))

    class Subject(type(rpc), project_roles.RPC):
        pass

    subject = Subject()
    subject.__dict__.update(rpc.__dict__)
    subject.db.tbl.project_user_role = project_user_role
    return subject


def soon():
    return datetime.datetime.now() + SOON


def row_of(rpc, token_id):
    return rpc.get_token(token_id=token_id)


def test_a_scoped_token_is_stored_with_its_projects_and_operations(scoped_rpc):
    token_id = scoped_rpc.add_token(user_id=7, name="ci", expires=soon(),
                                    scope_projects=[5, 3, 5], scope_operations=["build", "run"])

    row = row_of(scoped_rpc, token_id)
    # sorted and without duplicates; operations in their canonical order
    assert (row["scope_projects"], row["scope_operations"]) == ([3, 5], ["run", "build"])


def test_a_token_without_a_scope_is_written_as_before(scoped_rpc):
    token_id = scoped_rpc.add_token(user_id=7, name="legacy")

    row = row_of(scoped_rpc, token_id)
    assert (row["expires"], row["scope_projects"], row["scope_operations"]) == (None, None, None)


@pytest.mark.parametrize("projects", [[4], [3, 4], [999]])
def test_a_project_the_owner_is_not_a_member_of_is_refused_with_one_message(scoped_rpc, projects):
    # 4 exists (user 8's), 999 does not: the same answer, so a scope cannot probe for projects
    with pytest.raises(RuntimeError, match="only to projects its owner is a member of"):
        scoped_rpc.add_token(user_id=7, name="x", expires=soon(), scope_projects=projects, scope_operations=["run"])
    assert scoped_rpc.list_tokens(user_id=7) == []


@pytest.mark.parametrize("projects, operations, expires, message", [
    ([3], ["deploy"], "soon", "operations among"),
    ([3], ["run", "admin", "root"], "soon", "operations among"),
    ([3], [], "soon", "operations among"),
    ([3], "run", "soon", "operations among"),
    ([], ["run"], "soon", "project ids"),
    (["3"], ["run"], "soon", "project ids"),
    ([True], ["run"], "soon", "project ids"),
    ([0], ["run"], "soon", "project ids"),
    (list(range(1, 102)), ["run"], "soon", "project ids"),
    ([3], None, "soon", "both projects and operations"),
    (None, ["run"], "soon", "both projects and operations"),
    ([3], ["run"], None, "needs an expiry"),
    ([3], ["run"], "past", "expires within 90 days"),
    ([3], ["run"], "too_far", "expires within 90 days"),
])
def test_an_invalid_scope_is_refused_and_nothing_is_written(scoped_rpc, projects, operations, expires, message):
    moment = {
        "soon": soon(), None: None, "past": datetime.datetime.now() - datetime.timedelta(minutes=1),
        "too_far": datetime.datetime.now() + datetime.timedelta(days=91),
    }[expires]
    with pytest.raises(RuntimeError, match=message):
        scoped_rpc.add_token(user_id=7, name="x", expires=moment,
                             scope_projects=projects, scope_operations=operations)
    assert scoped_rpc.list_tokens(user_id=7) == []


def test_the_longest_scoped_token_is_ninety_days(scoped_rpc, tokens):
    assert (tokens.SCOPED_TOKEN_MAX_TTL_DAYS, tokens.TOKEN_OPERATIONS) == (90, ("run", "build", "admin"))
    expires = datetime.datetime.now() + datetime.timedelta(days=90)

    token_id = scoped_rpc.add_token(user_id=7, name="max", expires=expires,
                                    scope_projects=[3], scope_operations=["run"])
    assert row_of(scoped_rpc, token_id)["expires"] == expires


def test_the_reserved_name_is_refused_with_a_scope_too(scoped_rpc, tokens):
    with pytest.raises(RuntimeError, match="reserved"):
        scoped_rpc.add_token(user_id=7, name=tokens.SYSTEM_TOKEN_NAME, expires=soon(),
                             scope_projects=[3], scope_operations=["run"])


def test_list_and_get_return_the_scope(scoped_rpc):
    scoped = scoped_rpc.add_token(user_id=7, name="ci", expires=soon(), scope_projects=[5], scope_operations=["run"])
    legacy = scoped_rpc.add_token(user_id=7, name="old")

    listed = {row["id"]: (row["scope_projects"], row["scope_operations"]) for row in scoped_rpc.list_tokens(user_id=7)}
    assert listed == {scoped: ([5], ["run"]), legacy: (None, None)}
    uuid = row_of(scoped_rpc, scoped)["uuid"]
    assert scoped_rpc.get_token(uuid=uuid)["scope_projects"] == [5]


def test_the_system_token_is_untouched(scoped_rpc, tokens):
    encoded = scoped_rpc.ensure_system_token(7)
    row = scoped_rpc.decode_token(encoded)

    assert (row["name"], row["expires"], row["scope_projects"], row["scope_operations"]) == (
        tokens.SYSTEM_TOKEN_NAME, None, None, None)
    assert scoped_rpc.list_tokens(user_id=7) == []   # still hidden from the user's list


def test_a_scoped_tokens_expiry_cannot_be_cleared_or_pushed_past_the_cap(scoped_rpc):
    token_id = scoped_rpc.add_token(user_id=7, name="ci", expires=soon(), scope_projects=[3], scope_operations=["run"])
    for refused in (None, datetime.datetime.now() + datetime.timedelta(days=91)):
        with pytest.raises(RuntimeError, match="expires within 90 days"):
            scoped_rpc.set_token_expiry(token_id, refused)
        assert row_of(scoped_rpc, token_id)["revocation_epoch"] == 0   # nothing changed, no epoch bump
    shorter = datetime.datetime.now() + datetime.timedelta(days=1)
    assert scoped_rpc.set_token_expiry(token_id, shorter) == 1          # shortening (rotation retiring it) stays
    assert scoped_rpc.set_token_expiry(token_id, datetime.datetime.now() - datetime.timedelta(minutes=1)) == 2


def test_a_legacy_tokens_expiry_is_set_as_before(scoped_rpc):
    token_id = scoped_rpc.add_token(user_id=7, name="old")
    assert scoped_rpc.set_token_expiry(token_id, datetime.datetime.now() + datetime.timedelta(days=400)) == 1
    assert scoped_rpc.set_token_expiry(token_id, None) == 2
