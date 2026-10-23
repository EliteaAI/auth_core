"""Bulk user lookup by IdP subject (C-1009, issue #7122).

auth_get_users_by_idp_subjects is the batched form of auth_get_user_by_idp_subject:
the operator grant lists resolve a page of subjects with one call instead of one
per subject. It must return exactly what the single RPC returns, in one statement,
for a bounded number of subjects, and reveal nothing the single RPC does not.
"""
import pytest
import sqlalchemy as sa

ISSUER = "https://login.example.com/11111111-1111-1111-1111-111111111111/v2.0"
TID = "11111111-1111-1111-1111-111111111111"


def oid(n):
    return f"00000000-0000-0000-0000-{n:012d}"


def add_user(rpc, user_id, issuer=ISSUER, tid=TID, subject_oid=None, **values):
    values.setdefault("email", f"user{user_id}@example.com")
    if subject_oid is not None:
        values.update(idp_issuer=issuer, idp_tid=tid, idp_oid=subject_oid)
    with rpc.db.engine.connect() as connection:
        connection.execute(rpc.db.tbl.user.insert().values(id=user_id, **values))


def subject(n, tid=TID):
    return {"tid": tid, "oid": oid(n)}


def count_statements(engine, run):
    """The SELECT statements ``run`` sends to the database."""
    seen = []

    def before(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        seen.append(statement)

    sa.event.listen(engine, "before_cursor_execute", before)
    try:
        result = run()
    finally:
        sa.event.remove(engine, "before_cursor_execute", before)
    return result, seen


# --- shape ----------------------------------------------------------------


def test_returns_users_keyed_by_tid_and_oid(rpc):
    add_user(rpc, 1, subject_oid=oid(1))
    add_user(rpc, 2, subject_oid=oid(2))

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(1), subject(2)])

    assert set(found) == {f"{TID}:{oid(1)}", f"{TID}:{oid(2)}"}
    assert found[f"{TID}:{oid(1)}"]["id"] == 1
    assert found[f"{TID}:{oid(2)}"]["email"] == "user2@example.com"


def test_each_user_has_exactly_the_shape_of_the_single_lookup(rpc):
    add_user(rpc, 1, subject_oid=oid(1), name="Ann")

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(1)])

    assert found[f"{TID}:{oid(1)}"] == rpc.get_user_by_idp_subject(ISSUER, TID, oid(1))


def test_a_user_has_exactly_the_public_keys_and_no_credential_material(rpc):
    add_user(rpc, 1, subject_oid=oid(1), name="Ann")

    user = rpc.get_users_by_idp_subjects(ISSUER, [subject(1)])[f"{TID}:{oid(1)}"]

    assert set(user) == {
        "id", "email", "name", "suspended", "revocation_epoch", "idp_issuer", "idp_tid", "idp_oid",
    }


def test_subjects_of_different_tenants_are_told_apart(rpc):
    other_tid = "99999999-9999-9999-9999-999999999999"
    add_user(rpc, 1, subject_oid=oid(1))
    add_user(rpc, 2, tid=other_tid, subject_oid=oid(1))

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(1), subject(1, other_tid)])

    assert found[f"{TID}:{oid(1)}"]["id"] == 1
    assert found[f"{other_tid}:{oid(1)}"]["id"] == 2


def test_a_repeated_subject_is_returned_once(rpc):
    add_user(rpc, 1, subject_oid=oid(1))

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(1), subject(1)])

    assert list(found) == [f"{TID}:{oid(1)}"]


# --- absent / mismatched --------------------------------------------------


def test_missing_subjects_are_absent_not_none(rpc):
    add_user(rpc, 1, subject_oid=oid(1))

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(1), subject(2)])

    assert list(found) == [f"{TID}:{oid(1)}"]


def test_a_user_without_a_subject_is_never_returned(rpc):
    add_user(rpc, 1)

    assert rpc.get_users_by_idp_subjects(ISSUER, [subject(1)]) == {}


def test_another_issuer_finds_nothing(rpc):
    add_user(rpc, 1, subject_oid=oid(1))

    assert rpc.get_users_by_idp_subjects("https://other.example.com/v2.0", [subject(1)]) == {}


def test_no_subjects_is_an_empty_result_without_a_query(rpc):
    result, statements = count_statements(
        rpc.db.engine, lambda: rpc.get_users_by_idp_subjects(ISSUER, []),
    )

    assert result == {}
    assert statements == []


# --- bound and validation -------------------------------------------------


def test_one_statement_for_many_subjects(rpc):
    for n in range(1, 31):
        add_user(rpc, n, subject_oid=oid(n))
    asked = [subject(n) for n in range(1, 41)]

    found, statements = count_statements(
        rpc.db.engine, lambda: rpc.get_users_by_idp_subjects(ISSUER, asked),
    )

    assert len(found) == 30
    assert len(statements) == 1
    assert statements[0].lstrip().upper().startswith("SELECT")


def test_the_limit_is_accepted_and_one_more_is_refused(rpc, users):
    limit = users.MAX_IDP_SUBJECTS_PER_CALL
    assert limit == 200
    add_user(rpc, 1, subject_oid=oid(1))

    found = rpc.get_users_by_idp_subjects(ISSUER, [subject(n) for n in range(1, limit + 1)])
    assert list(found) == [f"{TID}:{oid(1)}"]

    with pytest.raises(RuntimeError, match="At most"):
        rpc.get_users_by_idp_subjects(ISSUER, [subject(n) for n in range(1, limit + 2)])


@pytest.mark.parametrize("issuer", [None, "", 5])
def test_the_issuer_is_required(rpc, issuer):
    with pytest.raises(RuntimeError):
        rpc.get_users_by_idp_subjects(issuer, [subject(1)])


@pytest.mark.parametrize("subjects", [
    None, "x", {"tid": TID, "oid": oid(1)},
    [None], ["a:b"], [{"tid": TID}], [{"oid": oid(1)}],
    [{"tid": "", "oid": oid(1)}], [{"tid": TID, "oid": None}],
    [{"tid": TID, "oid": oid(1), "extra": 1}],
])
def test_malformed_subjects_are_refused(rpc, subjects):
    with pytest.raises(RuntimeError):
        rpc.get_users_by_idp_subjects(ISSUER, subjects)
