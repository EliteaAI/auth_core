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

import uuid as uuid_
import datetime
from typing import Optional

import jwt  # pylint: disable=E0401
import sqlalchemy as sa

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools
from ..db import db_tools


# Reserved name of the platform-owned, non-expiring token that every user has.
# The name is the only marker: there is no dedicated column, so a token is a
# system token iff name == SYSTEM_TOKEN_NAME. The public POST /token endpoint
# rejects this name, which is what keeps the marker unforgeable.
SYSTEM_TOKEN_NAME = "elitea-system"


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_token", "add_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_token(self,
                   user_id: int,
                   name: str = "",
                   expires: Optional[datetime.datetime] = None,
                   token_id: Optional[int] = None):
        token_uuid = str(uuid_.uuid4())
        #
        values = {
            "uuid": token_uuid,
            "user_id": user_id,
            "expires": expires,
            "name": name,
        }

        if token_id:
            values["id"] = token_id

        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_token", "delete_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_token(self, token_id: int, allow_system: bool = False):
        """ Delete a token. System tokens are skipped unless allow_system is set.

        The guard is part of the WHERE clause rather than a pre-check, so it
        cannot be raced. Returns the number of deleted rows: 0 means the token
        did not exist or was a system token.
        """
        query = self.db.tbl.token.delete().where(
            self.db.tbl.token.c.id == token_id
        )
        #
        if not allow_system:
            query = query.where(
                self.db.tbl.token.c.name != SYSTEM_TOKEN_NAME
            )
        #
        with self.db.engine.connect() as connection:
            return connection.execute(query).rowcount

    @web.rpc("auth_get_token", "get_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_token(self, token_id: Optional[int] = None, uuid: Optional[str] = None):
        if token_id is not None:
            with self.db.engine.connect() as connection:
                token = connection.execute(
                    self.db.tbl.token.select().where(
                        self.db.tbl.token.c.id == token_id,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(token)
        #
        if uuid is not None:
            with self.db.engine.connect() as connection:
                token = connection.execute(
                    self.db.tbl.token.select().where(
                        self.db.tbl.token.c.uuid == uuid,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(token)
        #
        raise ValueError("ID or UUID or name is not provided")

    @web.rpc("auth_list_tokens", "list_tokens")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_tokens(
            self,
            user_id: Optional[int] = None,
            name: Optional[str] = None,
            include_system: bool = False,
    ):
        """ List tokens. System tokens are excluded unless include_system is set.

        The default excludes them so that existing callers - the user-facing
        token list above all - keep their current semantics untouched. Asking
        for name=SYSTEM_TOKEN_NAME still requires include_system=True.
        """
        where = []
        query = self.db.tbl.token.select()
        if name is not None:
            where.append(self.db.tbl.token.c.name == name)
        if user_id is not None:
            where.append(self.db.tbl.token.c.user_id == user_id)
        if not include_system:
            where.append(self.db.tbl.token.c.name != SYSTEM_TOKEN_NAME)

        if where:
            query = query.where(*where)

        with self.db.engine.connect() as connection:
            tokens = connection.execute(query).mappings().all()
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in tokens
        ]

    @web.rpc("auth_ensure_system_token", "ensure_system_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def ensure_system_token(self, user_id: int) -> str:
        """ Get-or-create this user's system token, returning it encoded """
        tbl = self.db.tbl.token
        #
        with self.db.engine.connect() as connection:
            row = connection.execute(
                sa.select(tbl.c.uuid).where(
                    tbl.c.user_id == user_id,
                    tbl.c.name == SYSTEM_TOKEN_NAME,
                ).limit(1)
            ).first()
            #
            if row is not None:
                token_uuid = row[0]
            else:
                token_uuid = str(uuid_.uuid4())
                connection.execute(
                    tbl.insert().values(
                        uuid=token_uuid,
                        user_id=user_id,
                        expires=None,
                        name=SYSTEM_TOKEN_NAME,
                    )
                )
        #
        return self.encode_token(uuid=token_uuid)

    @web.rpc("auth_backfill_system_tokens", "backfill_system_tokens")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def backfill_system_tokens(self, dry_run: bool = False) -> dict:
        """ Give every existing user a system token. Safe to re-run """
        user_tbl = self.db.tbl.user
        token_tbl = self.db.tbl.token
        #
        has_system_token = sa.exists().where(
            token_tbl.c.user_id == user_tbl.c.id,
            token_tbl.c.name == SYSTEM_TOKEN_NAME,
        )
        #
        with self.db.engine.connect() as connection:
            users_total = connection.execute(
                sa.select(sa.func.count()).select_from(user_tbl)
            ).scalar()
            #
            missing_user_ids = connection.execute(
                sa.select(user_tbl.c.id).where(~has_system_token)
            ).scalars().all()
            #
            # A row already named SYSTEM_TOKEN_NAME but carrying an expiry
            # satisfies "one per user" yet breaks the "never expires" half of
            # the invariant, so resolution would hand out an expired token.
            # Adopt it instead of adding a second row.
            is_expiring_squatter = (
                token_tbl.c.name == SYSTEM_TOKEN_NAME,
                token_tbl.c.expires.is_not(None),
            )
            squatters_adopted = connection.execute(
                sa.select(sa.func.count()).select_from(token_tbl).where(
                    *is_expiring_squatter
                )
            ).scalar()
            #
            if not dry_run:
                if missing_user_ids:
                    connection.execute(
                        token_tbl.insert(),
                        [
                            {
                                "uuid": str(uuid_.uuid4()),
                                "expires": None,
                                "user_id": user_id,
                                "name": SYSTEM_TOKEN_NAME,
                            }
                            for user_id in missing_user_ids
                        ],
                    )
                if squatters_adopted:
                    connection.execute(
                        token_tbl.update().where(
                            *is_expiring_squatter
                        ).values(expires=None)
                    )
        #
        return {
            "dry_run": dry_run,
            "users_total": users_total,
            "already_present": users_total - len(missing_user_ids),
            "created": len(missing_user_ids),
            "squatters_adopted": squatters_adopted,
        }

    @web.rpc("auth_list_tokens_expiring_soon", "list_tokens_expiring_soon")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_tokens_expiring_soon(self):
        """ Return tokens whose expires is within [now+23h, now+25h] """
        now = datetime.datetime.now()
        window_start = now + datetime.timedelta(hours=23)
        window_end = now + datetime.timedelta(hours=24)
        #
        tbl = self.db.tbl.token
        query = sa.select(
            tbl.c.user_id,
            tbl.c.uuid,
            tbl.c.name,
        ).where(
            tbl.c.expires != None,  # pylint: disable=C0121
            tbl.c.expires >= window_start,
            tbl.c.expires <= window_end,
        )
        with self.db.engine.connect() as connection:
            tokens = connection.execute(query).mappings().all()
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in tokens
        ]

    @web.rpc("auth_encode_token", "encode_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def encode_token(self, token_id: Optional[int] = None, uuid: Optional[str] = None):
        if token_id is not None:
            token = self.get_token(token_id=token_id)
        elif uuid is not None:
            token = self.get_token(uuid=uuid)
        else:
            raise ValueError("ID or UUID is not provided")
        #
        expires: Optional[datetime.datetime] = token["expires"]
        #
        if expires:
            expires: str = expires.isoformat(timespec="minutes")
        #
        token_data = {
            "uuid": token["uuid"],
            "expires": expires
        }
        #
        return jwt.encode(
            token_data,
            self.context.app.secret_key,
            algorithm="HS512",
        )

    @web.rpc("auth_decode_token", "decode_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def decode_token(self, token):
        try:
            token_data = jwt.decode(
                token, self.context.app.secret_key, algorithms=["HS512"]
            )
        except:
            raise ValueError("Invalid token")  # pylint: disable=W0707
        #
        return self.get_token(uuid=token_data["uuid"])
