"""A suspended user must not be able to authenticate (issue #5262 review).

auth_core has carried a `suspended` column since migration 202602241500, but
nothing on the token path ever read it. That mattered less while every token was
user-created and deletable; it matters now that the platform hands every user a
permanent token they can neither see nor delete, so suspension is enforced where
all token traffic passes: handle_bearer_token, which handle_basic_auth delegates
to. ensure_system_token refuses suspended users as well, so a suspended account
is never handed a fresh permanent credential either.
"""
import base64
import datetime

import pytest
import sqlalchemy as sa

SYSTEM_TOKEN_NAME = "elitea-system"

PAST = datetime.datetime(2020, 1, 1, 12, 0, 0)
FUTURE = datetime.datetime(2030, 1, 1, 12, 0, 0)


def add_user(rpc, user_id, suspended=False):
    with rpc.db.engine.connect() as connection:
        connection.execute(
            rpc.db.tbl.user.insert().values(
                id=user_id,
                email=f"user{user_id}@example.com",
                suspended=suspended,
            )
        )


def suspend(rpc, user_id, suspended=True):
    with rpc.db.engine.connect() as connection:
        connection.execute(
            rpc.db.tbl.user.update().where(
                rpc.db.tbl.user.c.id == user_id,
            ).values(suspended=suspended)
        )


def system_tokens(rpc, user_id):
    tbl = rpc.db.tbl.token
    with rpc.db.engine.connect() as connection:
        return connection.execute(
            sa.select(tbl).where(
                tbl.c.user_id == user_id,
                tbl.c.name == SYSTEM_TOKEN_NAME,
            )
        ).mappings().all()


def as_basic(encoded):
    return base64.b64encode(f"{encoded}:".encode()).decode()


# --- bearer auth -----------------------------------------------------------


def test_active_user_authenticates(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="mine")
    encoded = rpc.encode_token(token_id=token_id)

    assert rpc.handle_bearer_token("source", encoded) == ("token", token_id, "-")


def test_suspended_user_is_refused(rpc):
    add_user(rpc, 1)
    encoded = rpc.encode_token(token_id=rpc.add_token(user_id=1, name="mine"))

    suspend(rpc, 1)

    with pytest.raises(RuntimeError, match="suspended"):
        rpc.handle_bearer_token("source", encoded)


def test_suspended_user_is_refused_on_the_system_token(rpc):
    """The one they cannot list or delete, so the only way out is here."""
    add_user(rpc, 1)
    encoded = rpc.ensure_system_token(user_id=1)

    suspend(rpc, 1)

    with pytest.raises(RuntimeError, match="suspended"):
        rpc.handle_bearer_token("source", encoded)


def test_basic_auth_is_refused_too(rpc):
    add_user(rpc, 1)
    encoded = rpc.ensure_system_token(user_id=1)

    suspend(rpc, 1)

    with pytest.raises(RuntimeError, match="suspended"):
        rpc.handle_basic_auth("source", as_basic(encoded))


def test_basic_auth_still_works_for_an_active_user(rpc):
    add_user(rpc, 1)
    token_id = rpc.add_token(user_id=1, name="mine")
    encoded = rpc.encode_token(token_id=token_id)

    assert rpc.handle_basic_auth("source", as_basic(encoded)) == \
        ("token", token_id, "-")


def test_unsuspending_restores_access(rpc):
    add_user(rpc, 1)
    encoded = rpc.ensure_system_token(user_id=1)
    suspend(rpc, 1)

    suspend(rpc, 1, suspended=False)

    kind, _, _ = rpc.handle_bearer_token("source", encoded)
    assert kind == "token"


def test_expiry_is_still_checked(rpc):
    """The suspension lookup must not have displaced the existing guard."""
    add_user(rpc, 1)
    encoded = rpc.encode_token(
        token_id=rpc.add_token(user_id=1, name="mine", expires=PAST),
    )

    with pytest.raises(RuntimeError, match="expired"):
        rpc.handle_bearer_token("source", encoded)


def test_one_users_suspension_does_not_affect_another(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2, suspended=True)
    encoded = rpc.ensure_system_token(user_id=1)

    kind, _, _ = rpc.handle_bearer_token("source", encoded)
    assert kind == "token"


# --- provisioning ----------------------------------------------------------


def test_ensure_system_token_refuses_a_suspended_user(rpc):
    add_user(rpc, 1, suspended=True)

    with pytest.raises(RuntimeError, match="suspended"):
        rpc.ensure_system_token(user_id=1)

    assert system_tokens(rpc, 1) == []


def test_ensure_system_token_refuses_to_return_an_existing_one(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)

    suspend(rpc, 1)

    with pytest.raises(RuntimeError, match="suspended"):
        rpc.ensure_system_token(user_id=1)


def test_ensure_system_token_leaves_a_suspended_users_row_alone(rpc):
    """Refusing is not revoking: the row survives for the unsuspend."""
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    before = system_tokens(rpc, 1)

    suspend(rpc, 1)
    with pytest.raises(RuntimeError):
        rpc.ensure_system_token(user_id=1)

    assert system_tokens(rpc, 1) == before


# --- backfill --------------------------------------------------------------


def test_backfill_skips_suspended_users(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2, suspended=True)

    result = rpc.backfill_system_tokens()

    assert result["created"] == 1
    assert result["skipped_suspended"] == 1
    assert system_tokens(rpc, 2) == []


def test_backfill_dry_run_reports_the_skip(rpc):
    add_user(rpc, 1, suspended=True)

    result = rpc.backfill_system_tokens(dry_run=True)

    assert result["missing"] == 0
    assert result["skipped_suspended"] == 1


def test_backfill_counts_a_suspended_user_who_has_one_as_present(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    suspend(rpc, 1)

    result = rpc.backfill_system_tokens()

    assert result["already_present"] == 1
    assert result["skipped_suspended"] == 0
    assert result["created"] == 0
