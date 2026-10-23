#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0116

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Revocation epochs: bump inside the changing transaction, announce after it

RPC functions run with the Module as ``self`` and only decorated functions are
bound onto it, so the shared logic lives here as plain functions.
"""

import contextlib

from pylon.core.tools import log  # pylint: disable=E0401,E0611

KINDS = ("user", "token")

INVALIDATE_EVENT = "auth_invalidate"


@contextlib.contextmanager
def transaction(db):
    """ A real transaction on a connection of the AUTOCOMMIT engine

    Same isolation choice as add_user(): without it the change and its epoch bump
    would commit independently and a crash in between would leave the change
    unannounced.
    """
    isolation_level = "SERIALIZABLE" \
        if db.url.startswith("sqlite:") else "READ COMMITTED"
    #
    with db.engine.connect().execution_options(
            isolation_level=isolation_level,
    ) as connection:
        with connection.begin():
            yield connection


def bump_epoch(connection, db, kind, id_):
    """ Increment the epoch of one user/token on this connection; None if no such row

    Call it after the change it announces, in the same transaction: a reader that
    sees the new epoch then also sees the change.
    """
    if kind not in KINDS:
        raise ValueError(f"Unknown revocation kind {kind!r}, expected one of {KINDS}")
    #
    table = getattr(db.tbl, kind)
    #
    row = connection.execute(
        table.update().where(
            table.c.id == id_,
        ).values(
            revocation_epoch=table.c.revocation_epoch + 1,
        ).returning(table.c.revocation_epoch)
    ).first()
    #
    return None if row is None else int(row[0])


def fire_invalidate(context, kind, id_, epoch):
    """ Announce a bump to every pylon, after commit

    Best effort: the event only makes caches notice sooner. The guarantee is the
    epoch comparison, so a lost event must not fail the operation that is already
    committed.
    """
    try:
        context.event_manager.fire_event(
            INVALIDATE_EVENT, {"kind": kind, "id": id_, "epoch": epoch},
        )
    except Exception:  # pylint: disable=W0703
        log.exception("Failed to fire %s for %s %s", INVALIDATE_EVENT, kind, id_)
