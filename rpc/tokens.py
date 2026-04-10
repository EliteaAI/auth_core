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

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools
from ..db import db_tools


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
    def delete_token(self, token_id: int):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token.delete().where(
                    self.db.tbl.token.c.id == token_id
                )
            ).rowcount

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
    def list_tokens(self, user_id: Optional[int] = None, name: Optional[str] = None):
        where = []
        query = self.db.tbl.token.select()
        if name is not None:
            where.append(self.db.tbl.token.c.name == name)
        if user_id is not None:
            where.append(self.db.tbl.token.c.user_id == user_id)

        if where:
            query = query.where(*where)

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
