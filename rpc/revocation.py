#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0115,C0116

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

""" RPC """

import datetime
from typing import Optional

import sqlalchemy as sa

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools, revocation


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_get_revocation_epochs", "get_revocation_epochs")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_revocation_epochs(
            self,
            user_id: Optional[int] = None,
            token_id: Optional[int] = None,
    ) -> dict:
        """ Current epochs, and whether the identity may still be admitted

        user_id is enough for a session; a token carries its owner, so a token_id
        alone also yields the owner's epoch (and an explicit user_id is ignored in
        favour of the token's owner). A missing row reads back as epoch None.

        "active" is the admission verdict at this moment - the user exists and is
        not suspended, and the token exists and has not expired - so a caller that
        refreshes this every few seconds also picks up an expiry that passes by
        itself, which no bump announces.
        """
        if user_id is None and token_id is None:
            raise ValueError("user_id or token_id is required")
        #
        user_tbl = self.db.tbl.user
        token_tbl = self.db.tbl.token
        #
        token_epoch = None
        token_expires = None
        token_found = False
        #
        with self.db.engine.connect() as connection:
            if token_id is not None:
                row = connection.execute(
                    sa.select(
                        token_tbl.c.revocation_epoch,
                        token_tbl.c.user_id,
                        token_tbl.c.expires,
                    ).where(token_tbl.c.id == token_id)
                ).first()
                #
                if row is not None:
                    token_found = True
                    token_epoch = int(row[0])
                    user_id = row[1]
                    token_expires = row[2]
                else:
                    user_id = None
            #
            user_row = None
            if user_id is not None:
                user_row = connection.execute(
                    sa.select(
                        user_tbl.c.revocation_epoch,
                        user_tbl.c.suspended,
                    ).where(user_tbl.c.id == user_id)
                ).first()
        #
        reason = None
        if token_id is not None and not token_found:
            reason = "token_missing"
        elif user_row is None:
            reason = "user_missing"
        elif user_row[1]:
            reason = "user_suspended"
        elif token_expires is not None and datetime.datetime.now() >= token_expires:
            reason = "token_expired"
        #
        return {
            "user": None if user_row is None else int(user_row[0]),
            "token": token_epoch,
            "user_id": user_id,
            "active": reason is None,
            "reason": reason,
        }

    @web.rpc("auth_bump_revocation_epoch", "bump_revocation_epoch")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def bump_revocation_epoch(self, kind: str, id: int) -> Optional[int]:  # pylint: disable=W0622
        """ Force-revoke cached state of a user or token; returns the new epoch

        For operations that change access outside auth_core's own RPCs (for
        example a role edit made elsewhere). None if there is no such row.
        """
        with revocation.transaction(self.db) as connection:
            epoch = revocation.bump_epoch(connection, self.db, kind, id)
        #
        if epoch is not None:
            revocation.fire_invalidate(self.context, kind, id, epoch)
        #
        return epoch
