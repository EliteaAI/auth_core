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

    @web.rpc("auth_add_scope", "add_scope")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_scope(self, name="", parent_id=None, scope_id=...):
        values = {
            "name": name,
            "parent_id": parent_id,
        }
        #
        if scope_id is not ...:
            values["id"] = scope_id
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.scope.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_scope", "delete_scope")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_scope(self, scope_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.scope.delete().where(
                    self.db.tbl.scope.c.id == scope_id
                )
            ).rowcount

    @web.rpc("auth_get_scope", "get_scope")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_scope(self, scope_id):
        with self.db.engine.connect() as connection:
            scope = connection.execute(
                self.db.tbl.scope.select().where(
                    self.db.tbl.scope.c.id == scope_id,
                )
            ).mappings().one()
        return db_tools.sqlalchemy_mapping_to_dict(scope)

    @web.rpc("auth_list_scopes", "list_scopes")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_scopes(self):
        with self.db.engine.connect() as connection:
            scopes = connection.execute(
                self.db.tbl.scope.select()
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in scopes]

    @web.rpc("auth_walk_scope_tree", "walk_scope_tree")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def walk_scope_tree(self, scope_id):
        scopes = self.list_scopes()
        scope_map = {item["id"]: item for item in scopes}
        #
        result = []
        #
        current_id = scope_id
        while True:
            if current_id not in scope_map:
                break
            #
            item = scope_map[current_id]
            result.append(item)
            #
            if item["parent_id"] is None:
                break
            #
            current_id = item["parent_id"]
        #
        return result
