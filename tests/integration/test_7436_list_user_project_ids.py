"""#7436: list_user_project_ids returns the projects a user belongs to from one indexed query.

list_user_projects uses it to load only the user's projects instead of every project on the platform.
A user holding several roles in one project appears once; a user in no project gets an empty list.
"""
import pytest
import sqlalchemy as sa

from conftest import TABLE_PREFIX


@pytest.fixture
def subject(rpc, project_roles, engine):
    metadata = sa.MetaData()
    project_user_role = sa.Table(
        f"{TABLE_PREFIX}__project_user_role", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer), sa.Column("user_id", sa.Integer), sa.Column("role_id", sa.Integer),
    )
    metadata.create_all(engine)
    rows = [(3, 7, 1), (3, 7, 2), (5, 7, 1), (9, 7, 4), (4, 8, 1)]
    with engine.connect() as connection:
        for project_id, user_id, role_id in rows:
            connection.execute(project_user_role.insert().values(
                project_id=project_id, user_id=user_id, role_id=role_id))

    class Subject(type(rpc), project_roles.RPC):
        pass

    obj = Subject()
    obj.__dict__.update(rpc.__dict__)
    obj.db.tbl.project_user_role = project_user_role
    return obj


def test_7436_returns_each_project_once_even_with_several_roles(subject):
    assert sorted(subject.list_user_project_ids(7)) == [3, 5, 9]


def test_7436_other_users_projects_are_not_included(subject):
    assert subject.list_user_project_ids(8) == [4]


def test_7436_user_without_projects_gets_an_empty_list(subject):
    assert subject.list_user_project_ids(99) == []


# list_user_projects used to ask check_user_in_projects about every platform project; the new RPC must
# return exactly that membership, so any extra condition added to either query later shows up here
@pytest.mark.parametrize("user_id", [7, 8, 99])
def test_7436_matches_check_user_in_projects_over_all_projects(subject, user_id):
    all_project_ids = [3, 4, 5, 9, 11]
    expected = subject.check_user_in_projects(all_project_ids, user_id)
    assert sorted(subject.list_user_project_ids(user_id)) == sorted(expected)
