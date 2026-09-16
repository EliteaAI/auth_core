"""add_user() must create the user and its system token together (issue #5262).

The engine runs in AUTOCOMMIT, so the two inserts would otherwise commit
independently and a failure between them would leave a user the platform
believes has a permanent token but does not. add_user asks for a real
transaction on its own connection; these tests hold it to that.
"""
import sqlalchemy as sa

import pytest

SYSTEM_TOKEN_NAME = "elitea-system"


def user_rows(rpc):
    with rpc.db.engine.connect() as connection:
        return connection.execute(sa.select(rpc.db.tbl.user)).mappings().all()


def token_rows(rpc):
    with rpc.db.engine.connect() as connection:
        return connection.execute(sa.select(rpc.db.tbl.token)).mappings().all()


def test_add_user_creates_a_system_token(rpc):
    user_id = rpc.add_user(email="new@example.com")

    tokens = token_rows(rpc)
    assert len(tokens) == 1
    assert tokens[0]["user_id"] == user_id
    assert tokens[0]["name"] == SYSTEM_TOKEN_NAME
    assert tokens[0]["expires"] is None


def test_the_new_user_needs_no_further_provisioning(rpc):
    user_id = rpc.add_user(email="new@example.com", name="New")

    rpc.ensure_system_token(user_id=user_id)

    assert len(token_rows(rpc)) == 1


def test_a_failed_token_insert_rolls_the_user_back(rpc, users, monkeypatch):
    """Atomicity: no user may survive without the token that was promised."""
    def uuid4_that_fails():
        raise RuntimeError("boom")

    monkeypatch.setattr(users.uuid_, "uuid4", uuid4_that_fails)

    with pytest.raises(RuntimeError):
        rpc.add_user(email="new@example.com")

    assert user_rows(rpc) == []
    assert token_rows(rpc) == []
