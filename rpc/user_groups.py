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

    @web.rpc("auth_add_user_group", "add_user_group")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_user_group(self, user_id, group_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_group.insert().values(
                    user_id=user_id,
                    group_id=group_id,
                )
            ).inserted_primary_key[0]

    @web.rpc("auth_remove_user_group", "remove_user_group")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def remove_user_group(self, user_id, group_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_group.delete().where(
                    self.db.tbl.user_group.c.user_id == user_id,
                    self.db.tbl.user_group.c.group_id == group_id,
                )
            ).rowcount

    @web.rpc("auth_get_user_group_ids", "get_user_group_ids")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user_group_ids(self, user_id):
        with self.db.engine.connect() as connection:
            user_groups = connection.execute(
                self.db.tbl.user_group.select().where(
                    self.db.tbl.user_group.c.user_id == user_id,
                )
            ).mappings().all()
        #
        return [
            item["group_id"] for item in user_groups
        ]

    @web.rpc("auth_get_user_groups", "get_user_groups")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user_groups(self, user_id):
        return [
            self.get_group(group_id)
            for group_id in self.get_user_group_ids(user_id)
        ]

    @web.rpc("auth_list_user_groups", "list_user_groups")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_user_groups(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                user_groups = connection.execute(
                    self.db.tbl.user_group.select().where(
                        self.db.tbl.user_group.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                user_groups = connection.execute(
                    self.db.tbl.user_group.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in user_groups
        ]
