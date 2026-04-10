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

    @web.rpc("auth_add_group", "add_group")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_group(self, name="", parent_id=None, id_=...) -> int:
        values = {
            "name": name,
            "parent_id": parent_id,
        }
        #
        if id_ is not ...:
            values["id"] = id_
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_group", "delete_group")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_group(self, id_) -> int:
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group.delete().where(
                    self.db.tbl.group.c.id == id_
                )
            ).rowcount

    @web.rpc("auth_get_group", "get_group")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_group(self, id_) -> dict:
        with self.db.engine.connect() as connection:
            group = connection.execute(
                self.db.tbl.group.select().where(
                    self.db.tbl.group.c.id == id_,
                )
            ).mappings().one()
        return db_tools.sqlalchemy_mapping_to_dict(group)

    @web.rpc("auth_list_groups", "list_groups")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_groups(self):
        with self.db.engine.connect() as connection:
            groups = connection.execute(
                self.db.tbl.group.select()
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in groups]

    @web.rpc("auth_walk_group_tree", "walk_group_tree")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def walk_group_tree(self, group_id: int):
        groups = self.list_groups()
        group_map = {item["id"]: item for item in groups}
        #
        result = []
        #
        current_id = group_id
        while True:
            if current_id not in group_map:
                break
            #
            item = group_map[current_id]
            result.append(item)
            #
            if item["parent_id"] is None:
                break
            #
            current_id = item["parent_id"]
        #
        return result
