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

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools
from ..db import db_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_user_provider", "add_user_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_user_provider(self, user_id: int, provider_ref: str) -> int:
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_provider.insert().values(
                    user_id=user_id,
                    provider_ref=provider_ref,
                )
            ).inserted_primary_key[0]

    @web.rpc("auth_remove_user_provider", "remove_user_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def remove_user_provider(self, user_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_provider.delete().where(
                    self.db.tbl.user_provider.c.user_id == user_id,
                    self.db.tbl.user_provider.c.provider_ref == provider_ref,
                )
            ).rowcount

    @web.rpc("auth_get_user_from_provider", "get_user_from_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user_from_provider(self, provider_ref):
        with self.db.engine.connect() as connection:
            user_provider = connection.execute(
                self.db.tbl.user_provider.select().where(
                    self.db.tbl.user_provider.c.provider_ref == provider_ref,
                )
            ).mappings().one()
        #
        return self.get_user(user_provider["user_id"])

    @web.rpc("auth_list_user_providers", "list_user_providers")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_user_providers(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                providers = connection.execute(
                    self.db.tbl.user_provider.select().where(
                        self.db.tbl.user_provider.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                providers = connection.execute(
                    self.db.tbl.user_provider.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in providers
        ]
