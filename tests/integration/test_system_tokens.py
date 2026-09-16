"""Regression coverage for the system token invariants (issue #5262).

The invariants under test, each of which is security-relevant:

 * the reserved name cannot be minted through add_token, whatever the caller;
 * a token that already holds the reserved name is never promoted into a
   permanent hidden credential - it is evicted with its uuid and expiry intact;
 * exactly one system token exists per user, even when two callers provision
   concurrently;
 * the backfill inserts once and is safe to re-run;
 * system tokens stay out of the user-facing list and delete paths.
"""
import datetime

import jwt
import pytest
import sqlalchemy as sa

from conftest import SECRET_KEY

SYSTEM_TOKEN_NAME = "elitea-system"

FUTURE = datetime.datetime(2030, 1, 1, 12, 0, 0)


def add_user(rpc, user_id, email=None):
    with rpc.db.engine.connect() as connection:
        connection.execute(
            rpc.db.tbl.user.insert().values(
                id=user_id, email=email or f"user{user_id}@example.com",
            )
        )


def add_raw_token(rpc, user_id, name, uuid, expires=None):
    """Insert directly, bypassing add_token's reserved-name guard."""
    with rpc.db.engine.connect() as connection:
        return connection.execute(
            rpc.db.tbl.token.insert().values(
                uuid=uuid, user_id=user_id, name=name, expires=expires,
            )
        ).inserted_primary_key[0]


def rows(rpc, **where):
    tbl = rpc.db.tbl.token
    query = sa.select(tbl)
    for column, value in where.items():
        query = query.where(tbl.c[column] == value)
    with rpc.db.engine.connect() as connection:
        return connection.execute(query.order_by(tbl.c.id)).mappings().all()


def decoded_uuid(encoded):
    return jwt.decode(encoded, SECRET_KEY, algorithms=["HS512"])["uuid"]


# --- the reserved name is not mintable -------------------------------------


def test_add_token_rejects_the_reserved_name(rpc):
    add_user(rpc, 1)

    # wrap_exceptions(RuntimeError) converts the ValueError for RPC transport.
    with pytest.raises(RuntimeError, match="reserved"):
        rpc.add_token(user_id=1, name=SYSTEM_TOKEN_NAME)

    assert rows(rpc) == []


def test_add_token_rejects_the_reserved_name_with_an_expiry(rpc):
    add_user(rpc, 1)

    with pytest.raises(RuntimeError, match="reserved"):
        rpc.add_token(user_id=1, name=SYSTEM_TOKEN_NAME, expires=FUTURE)

    assert rows(rpc) == []


def test_add_token_still_allows_names_that_only_look_reserved(rpc):
    add_user(rpc, 1)

    rpc.add_token(user_id=1, name=f"{SYSTEM_TOKEN_NAME}-2")

    assert [row["name"] for row in rows(rpc)] == [f"{SYSTEM_TOKEN_NAME}-2"]


# --- provisioning ----------------------------------------------------------


def test_ensure_system_token_creates_one_non_expiring_token(rpc):
    add_user(rpc, 1)

    encoded = rpc.ensure_system_token(user_id=1)

    created = rows(rpc)
    assert len(created) == 1
    assert created[0]["name"] == SYSTEM_TOKEN_NAME
    assert created[0]["expires"] is None
    assert decoded_uuid(encoded) == created[0]["uuid"]


def test_ensure_system_token_is_idempotent(rpc):
    add_user(rpc, 1)

    first = rpc.ensure_system_token(user_id=1)
    second = rpc.ensure_system_token(user_id=1)

    assert decoded_uuid(first) == decoded_uuid(second)
    assert len(rows(rpc)) == 1


def test_ensure_system_token_is_per_user(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2)

    first = rpc.ensure_system_token(user_id=1)
    second = rpc.ensure_system_token(user_id=2)

    assert decoded_uuid(first) != decoded_uuid(second)
    assert len(rows(rpc)) == 2


# --- eviction, not promotion ----------------------------------------------


def test_expiring_conflict_is_evicted_not_promoted(rpc):
    """The core of finding 1: a pre-existing token must not become permanent."""
    add_user(rpc, 1)
    token_id = add_raw_token(
        rpc, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE,
    )

    rpc.ensure_system_token(user_id=1)

    evicted = rows(rpc, id=token_id)[0]
    assert evicted["name"] == f"{SYSTEM_TOKEN_NAME}-conflict-{token_id}"
    assert evicted["uuid"] == "squatter-uuid", "uuid must survive the rename"
    assert evicted["expires"] == FUTURE, "the token must not become permanent"


def test_evicted_conflict_stays_an_ordinary_user_token(rpc):
    """It is still listable and still deletable - it was not hidden away."""
    add_user(rpc, 1)
    token_id = add_raw_token(
        rpc, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE,
    )

    rpc.ensure_system_token(user_id=1)

    listed = rpc.list_tokens(user_id=1)
    assert [item["uuid"] for item in listed] == ["squatter-uuid"]

    assert rpc.delete_token(token_id=token_id) == 1


def test_eviction_mints_a_fresh_system_token(rpc):
    add_user(rpc, 1)
    add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE)

    encoded = rpc.ensure_system_token(user_id=1)

    system = rows(rpc, name=SYSTEM_TOKEN_NAME)
    assert len(system) == 1
    assert system[0]["expires"] is None
    assert system[0]["uuid"] != "squatter-uuid"
    assert decoded_uuid(encoded) == system[0]["uuid"]


# --- concurrency -----------------------------------------------------------


def test_unique_index_forbids_a_second_system_token(rpc):
    add_user(rpc, 1)
    add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "first")

    with pytest.raises(sa.exc.IntegrityError):
        add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "second")


def test_unique_index_leaves_ordinary_names_alone(rpc):
    add_user(rpc, 1)
    add_raw_token(rpc, 1, "mine", "first")
    add_raw_token(rpc, 1, "mine", "second")

    assert len(rows(rpc)) == 2


def test_losing_the_race_returns_the_winners_token(rpc, tokens, monkeypatch):
    """Finding 2: a concurrent caller must not create a second credential.

    The competing insert is injected at uuid4(), which ensure_system_token calls
    after its SELECT and immediately before its INSERT - exactly the window a
    real second caller would exploit. The insert then hits the unique index.
    """
    add_user(rpc, 1)

    real_uuid4 = tokens.uuid_.uuid4
    winner_uuid = "winner-uuid"

    def uuid4_that_loses_the_race():
        monkeypatch.setattr(tokens.uuid_, "uuid4", real_uuid4)
        add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, winner_uuid)
        return real_uuid4()

    monkeypatch.setattr(tokens.uuid_, "uuid4", uuid4_that_loses_the_race)

    encoded = rpc.ensure_system_token(user_id=1)

    assert decoded_uuid(encoded) == winner_uuid
    assert len(rows(rpc, name=SYSTEM_TOKEN_NAME)) == 1


# --- backfill --------------------------------------------------------------


def test_backfill_gives_every_user_a_token(rpc):
    for user_id in (1, 2, 3):
        add_user(rpc, user_id)

    result = rpc.backfill_system_tokens()

    assert result["users_total"] == 3
    assert result["created"] == 3
    assert result["already_present"] == 0
    assert result["reserved_name_conflicts"] == 0

    created = rows(rpc, name=SYSTEM_TOKEN_NAME)
    assert len(created) == 3
    assert all(row["expires"] is None for row in created)
    assert {row["user_id"] for row in created} == {1, 2, 3}


def test_backfill_is_safe_to_re_run(rpc):
    for user_id in (1, 2):
        add_user(rpc, user_id)

    rpc.backfill_system_tokens()
    before = rows(rpc)

    result = rpc.backfill_system_tokens()

    assert result["created"] == 0
    assert result["already_present"] == 2
    assert rows(rpc) == before


def test_backfill_skips_users_who_already_have_one(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2)
    add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "existing")

    result = rpc.backfill_system_tokens()

    assert result["created"] == 1
    assert result["already_present"] == 1
    assert len(rows(rpc, user_id=1)) == 1


def test_backfill_dry_run_writes_nothing(rpc):
    for user_id in (1, 2):
        add_user(rpc, user_id)

    result = rpc.backfill_system_tokens(dry_run=True)

    assert result["dry_run"] is True
    assert result["missing"] == 2
    assert result["created"] == 0, "a dry run creates nothing, so it reports none"
    assert rows(rpc) == []


def test_backfill_reports_conflicts_without_touching_them(rpc):
    """It counts them and leaves them to ensure_system_token."""
    add_user(rpc, 1)
    token_id = add_raw_token(
        rpc, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE,
    )

    result = rpc.backfill_system_tokens()

    assert result["reserved_name_conflicts"] == 1
    assert result["created"] == 0, "the name match alone counts as present"

    untouched = rows(rpc, id=token_id)[0]
    assert untouched["name"] == SYSTEM_TOKEN_NAME
    assert untouched["expires"] == FUTURE


def test_backfill_survives_a_login_provisioning_mid_run(rpc, tokens, monkeypatch):
    """The window between the backfill's scan and its insert is real.

    ensure_system_token() can land in it - any login does - and the unique index
    then rejects the backfill's row. That must be a counted loss, not a failed
    migration task.
    """
    add_user(rpc, 1)

    real_uuid4 = tokens.uuid_.uuid4

    def uuid4_that_loses_the_race():
        monkeypatch.setattr(tokens.uuid_, "uuid4", real_uuid4)
        rpc.ensure_system_token(user_id=1)
        return real_uuid4()

    monkeypatch.setattr(tokens.uuid_, "uuid4", uuid4_that_loses_the_race)

    result = rpc.backfill_system_tokens()

    assert result["created"] == 0, "the row was not written by this run"
    assert len(rows(rpc, name=SYSTEM_TOKEN_NAME)) == 1


def test_two_backfills_do_not_double_provision(rpc, tokens, monkeypatch):
    """Both scans see the same missing users; only one set of rows may exist."""
    add_user(rpc, 1)
    add_user(rpc, 2)

    real_uuid4 = tokens.uuid_.uuid4

    def uuid4_that_runs_a_second_backfill():
        monkeypatch.setattr(tokens.uuid_, "uuid4", real_uuid4)
        rpc.backfill_system_tokens()
        return real_uuid4()

    monkeypatch.setattr(tokens.uuid_, "uuid4", uuid4_that_runs_a_second_backfill)

    result = rpc.backfill_system_tokens()

    assert result["created"] == 0, "the other run wrote both rows"
    assert len(rows(rpc, name=SYSTEM_TOKEN_NAME)) == 2
    assert {row["user_id"] for row in rows(rpc, name=SYSTEM_TOKEN_NAME)} == {1, 2}


def test_backfill_reports_only_the_rows_it_wrote(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2)
    add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "existing")

    result = rpc.backfill_system_tokens()

    assert result["missing"] == 1
    assert result["created"] == 1
    assert result["already_present"] == 1


def test_backfill_never_violates_the_unique_index(rpc):
    """Its NOT EXISTS is on the name alone, which is what keeps this true."""
    add_user(rpc, 1)
    add_raw_token(rpc, 1, SYSTEM_TOKEN_NAME, "squatter-uuid", expires=FUTURE)

    rpc.backfill_system_tokens()

    assert len(rows(rpc, user_id=1)) == 1


# --- the token stays hidden -----------------------------------------------


def test_list_tokens_hides_system_tokens_by_default(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    rpc.add_token(user_id=1, name="mine")

    assert [item["name"] for item in rpc.list_tokens(user_id=1)] == ["mine"]


def test_list_tokens_can_opt_in(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)

    listed = rpc.list_tokens(user_id=1, include_system=True)

    assert [item["name"] for item in listed] == [SYSTEM_TOKEN_NAME]


def test_list_tokens_by_reserved_name_still_needs_the_flag(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)

    assert rpc.list_tokens(name=SYSTEM_TOKEN_NAME) == []


def test_delete_token_refuses_system_tokens(rpc):
    add_user(rpc, 1)
    rpc.ensure_system_token(user_id=1)
    token_id = rows(rpc)[0]["id"]

    assert rpc.delete_token(token_id=token_id) == 0
    assert len(rows(rpc)) == 1

    assert rpc.delete_token(token_id=token_id, allow_system=True) == 1
    assert rows(rpc) == []
