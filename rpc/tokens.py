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
# system token iff name == SYSTEM_TOKEN_NAME and it never expires. add_token()
# below rejects the name, which is what keeps the marker unforgeable.
SYSTEM_TOKEN_NAME = "elitea-system"

# A row that carries the reserved name but breaks the rest of the invariant is
# renamed to this prefix plus its own id, which takes it out of the reserved
# namespace while leaving it a listable, deletable token of its owner.
EVICTED_NAME_PREFIX = f"{SYSTEM_TOKEN_NAME}-conflict-"


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_token", "add_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_token(self,
                   user_id: int,
                   name: str = "",
                   expires: Optional[datetime.datetime] = None,
                   token_id: Optional[int] = None):
        if name == SYSTEM_TOKEN_NAME:
            # System tokens are inserted by ensure_system_token() and add_user()
            # directly. Refusing the name here means no other caller - including
            # one that bypasses the HTTP layer - can mint a row that resolution
            # would later mistake for the platform's own token.
            raise ValueError(f"Token name is reserved: {name}")
        #
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
        """ Get-or-create this user's system token, returning it encoded

        Only a row that satisfies the whole invariant - reserved name *and* no
        expiry - counts. A row that carries the name with an expiry is not
        repaired in place: clearing its expiry would silently promote a token
        its owner created, and may have exposed, into a permanent credential the
        API then refuses to list or delete. It is evicted from the reserved
        namespace instead and a fresh system token is minted.
        """
        tbl = self.db.tbl.token
        user_tbl = self.db.tbl.user
        #
        is_system_token = (
            tbl.c.user_id == user_id,
            tbl.c.name == SYSTEM_TOKEN_NAME,
            tbl.c.expires.is_(None),
        )
        #
        with self.db.engine.connect() as connection:
            # A suspended user gets neither a new system token nor the one they
            # already have. handle_bearer_token() refuses it anyway; refusing to
            # hand it out means a suspended account cannot be left holding a
            # freshly minted permanent credential either.
            if connection.execute(
                sa.select(user_tbl.c.suspended).where(
                    user_tbl.c.id == user_id,
                )
            ).scalar():
                raise ValueError(f"User is suspended: {user_id}")
            #
            row = connection.execute(
                sa.select(tbl.c.uuid).where(*is_system_token).limit(1)
            ).first()
            #
            if row is not None:
                return self.encode_token(uuid=row[0])
            #
            # Nothing valid exists, so any row left under the reserved name for
            # this user necessarily carries an expiry.
            evicted = connection.execute(
                tbl.update().where(
                    tbl.c.user_id == user_id,
                    tbl.c.name == SYSTEM_TOKEN_NAME,
                ).values(
                    name=sa.literal(EVICTED_NAME_PREFIX, sa.Text).concat(
                        sa.cast(tbl.c.id, sa.Text)
                    ),
                )
            ).rowcount
            #
            if evicted:
                log.warning(
                    "Evicted %s expiring token(s) from the reserved name "
                    "for user %s", evicted, user_id,
                )
            #
            token_uuid = str(uuid_.uuid4())
            #
            try:
                connection.execute(
                    tbl.insert().values(
                        uuid=token_uuid,
                        user_id=user_id,
                        expires=None,
                        name=SYSTEM_TOKEN_NAME,
                    )
                )
            except sa.exc.IntegrityError:
                # The one-per-user index rejected the insert, so a concurrent
                # caller got there first. Its row is the system token now.
                connection.rollback()
                #
                row = connection.execute(
                    sa.select(tbl.c.uuid).where(*is_system_token).limit(1)
                ).first()
                #
                if row is None:
                    raise
                #
                token_uuid = row[0]
        #
        return self.encode_token(uuid=token_uuid)

    @web.rpc("auth_backfill_system_tokens", "backfill_system_tokens")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def backfill_system_tokens(self, dry_run: bool = False) -> dict:
        """ Give every existing user a system token. Safe to re-run

        Concurrency-safe against itself and against ensure_system_token(): the
        scan only decides who to try, and each insert is its own statement whose
        loss to the one-per-user index is counted, not raised. So "created" is
        the number of rows this run actually wrote, and a second backfill running
        alongside the first reports 0 rather than double-counting.

        Suspended users are skipped. handle_bearer_token() and
        ensure_system_token() both refuse them, so minting the row here would
        only stockpile permanent credentials for accounts that must not use one.
        """
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
                sa.select(user_tbl.c.id).where(
                    ~has_system_token,
                    sa.not_(user_tbl.c.suspended),
                )
            ).scalars().all()
            #
            skipped_suspended = connection.execute(
                sa.select(sa.func.count()).select_from(user_tbl).where(
                    ~has_system_token,
                    user_tbl.c.suspended,
                )
            ).scalar()
            #
            # The 202609161200 migration cleared the reserved namespace, and
            # add_token() refuses the name, so this should be 0. It is reported
            # rather than fixed: such a user counts as "already present" here
            # and is left to ensure_system_token(), which evicts the row at the
            # point of use instead of mutating credentials from a bulk job.
            reserved_name_conflicts = connection.execute(
                sa.select(sa.func.count()).select_from(token_tbl).where(
                    token_tbl.c.name == SYSTEM_TOKEN_NAME,
                    token_tbl.c.expires.is_not(None),
                )
            ).scalar()
            #
            if reserved_name_conflicts:
                log.warning(
                    "%s token(s) hold the reserved name with an expiry",
                    reserved_name_conflicts,
                )
            #
            created = 0
            lost_races = 0
            #
            if not dry_run:
                for user_id in missing_user_ids:
                    try:
                        connection.execute(
                            token_tbl.insert().values(
                                uuid=str(uuid_.uuid4()),
                                expires=None,
                                user_id=user_id,
                                name=SYSTEM_TOKEN_NAME,
                            )
                        )
                        created += 1
                    except sa.exc.IntegrityError:
                        # Someone provisioned this user between the scan and now
                        # - a login calling ensure_system_token(), or a second
                        # backfill. Their row is the system token; ours was never
                        # needed.
                        connection.rollback()
                        lost_races += 1
            #
            if lost_races:
                log.info(
                    "%s user(s) were provisioned concurrently during the "
                    "backfill", lost_races,
                )
        #
        return {
            "dry_run": dry_run,
            "users_total": users_total,
            "already_present": users_total - len(missing_user_ids) - skipped_suspended,
            "missing": len(missing_user_ids),
            "created": created,
            "skipped_suspended": skipped_suspended,
            "reserved_name_conflicts": reserved_name_conflicts,
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
