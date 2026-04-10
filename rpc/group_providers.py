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

    @web.rpc("auth_add_group_provider", "add_group_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_group_provider(self, group_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_provider.insert().values(
                    group_id=group_id,
                    provider_ref=provider_ref,
                )
            ).inserted_primary_key[0]

    @web.rpc("auth_remove_group_provider", "remove_group_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def remove_group_provider(self, group_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_provider.delete().where(
                    self.db.tbl.group_provider.c.group_id == group_id,
                    self.db.tbl.group_provider.c.provider_ref == provider_ref,
                )
            ).rowcount

    @web.rpc("auth_get_group_from_provider", "get_group_from_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_group_from_provider(self, provider_ref):
        with self.db.engine.connect() as connection:
            group_provider = connection.execute(
                self.db.tbl.group_provider.select().where(
                    self.db.tbl.group_provider.c.provider_ref == provider_ref,
                )
            ).mappings().one()
        #
        return self.get_group(id=group_provider["group_id"])

    @web.rpc("auth_list_group_providers", "list_group_providers")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_group_providers(self, group_id=None):
        with self.db.engine.connect() as connection:
            if group_id is not None:
                providers = connection.execute(
                    self.db.tbl.group_provider.select().where(
                        self.db.tbl.group_provider.c.group_id == group_id,
                    )
                ).mappings().all()
            else:
                providers = connection.execute(
                    self.db.tbl.group_provider.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in providers
        ]
