"""IdP subject keys on users (C-1009, issue #6941).

A user can carry the immutable identity an OIDC provider vouches for - issuer,
tenant id and object id - so a login can be matched on it instead of on an e-mail
address, which an identity provider lets an administrator change.
"""
import pytest
import sqlalchemy as sa

ISSUER = "https://login.example.com/11111111-1111-1111-1111-111111111111/v2.0"
TID = "11111111-1111-1111-1111-111111111111"
OID = "22222222-2222-2222-2222-222222222222"


def add_user(rpc, user_id, **values):
    values.setdefault("email", f"user{user_id}@example.com")
    with rpc.db.engine.connect() as connection:
        connection.execute(rpc.db.tbl.user.insert().values(id=user_id, **values))


def epoch(rpc, user_id):
    with rpc.db.engine.connect() as connection:
        return connection.execute(
            sa.select(rpc.db.tbl.user.c.revocation_epoch).where(
                rpc.db.tbl.user.c.id == user_id
            )
        ).scalar_one()


def stored(rpc, user_id):
    tbl = rpc.db.tbl.user
    with rpc.db.engine.connect() as connection:
        return tuple(connection.execute(
            sa.select(tbl.c.idp_issuer, tbl.c.idp_tid, tbl.c.idp_oid).where(
                tbl.c.id == user_id
            )
        ).one())


# --- lookup ---------------------------------------------------------------


def test_lookup_returns_none_when_no_user_carries_the_subject(rpc):
    add_user(rpc, 1)

    assert rpc.get_user_by_idp_subject(ISSUER, TID, OID) is None


def test_lookup_returns_the_user_that_carries_the_subject(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2, idp_issuer=ISSUER, idp_tid=TID, idp_oid=OID)

    user = rpc.get_user_by_idp_subject(ISSUER, TID, OID)

    assert user["id"] == 2


def test_lookup_needs_all_three_parts_to_match(rpc):
    add_user(rpc, 1, idp_issuer=ISSUER, idp_tid=TID, idp_oid=OID)

    assert rpc.get_user_by_idp_subject(ISSUER, TID, "other") is None
    assert rpc.get_user_by_idp_subject(ISSUER, "other", OID) is None
    assert rpc.get_user_by_idp_subject("other", TID, OID) is None


@pytest.mark.parametrize("args", [
    (None, TID, OID), (ISSUER, None, OID), (ISSUER, TID, None), ("", TID, OID),
])
def test_lookup_refuses_an_incomplete_subject(rpc, args):
    with pytest.raises(RuntimeError):
        rpc.get_user_by_idp_subject(*args)


def test_get_user_returns_the_subject_columns(rpc):
    add_user(rpc, 1, idp_issuer=ISSUER, idp_tid=TID, idp_oid=OID)
    add_user(rpc, 2)

    linked = rpc.get_user(user_id=1)
    plain = rpc.get_user(email="user2@example.com")

    assert (linked["idp_issuer"], linked["idp_tid"], linked["idp_oid"]) == (ISSUER, TID, OID)
    assert (plain["idp_issuer"], plain["idp_tid"], plain["idp_oid"]) == (None, None, None)


# --- set ------------------------------------------------------------------


def test_set_records_the_subject_and_bumps_the_epoch(rpc):
    add_user(rpc, 1)

    assert rpc.set_user_idp_subject(1, ISSUER, TID, OID) is True

    assert stored(rpc, 1) == (ISSUER, TID, OID)
    assert epoch(rpc, 1) == 1
    assert rpc.events.fired == [
        ("auth_invalidate", {"kind": "user", "id": 1, "epoch": 1}),
    ]


def test_set_is_idempotent_for_the_same_subject(rpc):
    add_user(rpc, 1)
    rpc.set_user_idp_subject(1, ISSUER, TID, OID)
    rpc.events.fired.clear()

    assert rpc.set_user_idp_subject(1, ISSUER, TID, OID) is False

    assert epoch(rpc, 1) == 1
    assert rpc.events.fired == []


def test_set_refuses_to_overwrite_a_different_subject(rpc):
    add_user(rpc, 1, idp_issuer=ISSUER, idp_tid=TID, idp_oid=OID)

    with pytest.raises(RuntimeError):
        rpc.set_user_idp_subject(1, ISSUER, TID, "another-object")

    assert stored(rpc, 1) == (ISSUER, TID, OID)
    assert epoch(rpc, 1) == 0
    assert rpc.events.fired == []


def test_set_refuses_a_subject_another_user_already_carries(rpc):
    add_user(rpc, 1, idp_issuer=ISSUER, idp_tid=TID, idp_oid=OID)
    add_user(rpc, 2)

    with pytest.raises(RuntimeError):
        rpc.set_user_idp_subject(2, ISSUER, TID, OID)

    assert stored(rpc, 2) == (None, None, None)
    assert epoch(rpc, 2) == 0


def test_set_refuses_an_unknown_user(rpc):
    with pytest.raises(RuntimeError):
        rpc.set_user_idp_subject(404, ISSUER, TID, OID)


@pytest.mark.parametrize("args", [
    (None, TID, OID), (ISSUER, "", OID), (ISSUER, TID, None),
])
def test_set_refuses_an_incomplete_subject(rpc, args):
    add_user(rpc, 1)

    with pytest.raises(RuntimeError):
        rpc.set_user_idp_subject(1, *args)

    assert stored(rpc, 1) == (None, None, None)


def test_users_without_a_subject_do_not_collide(rpc):
    add_user(rpc, 1)
    add_user(rpc, 2)
    add_user(rpc, 3, idp_issuer=ISSUER)
    add_user(rpc, 4, idp_issuer=ISSUER)

    assert stored(rpc, 3) == (ISSUER, None, None)
