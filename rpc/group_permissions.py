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

    @web.rpc("auth_add_group_permission", "add_group_permission")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_group_permission(self, group_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_permission.insert().values(
                    group_id=group_id,
                    scope_id=scope_id,
                    permission=permission,
                )
            ).inserted_primary_key[0]

    @web.rpc("auth_remove_group_permission", "remove_group_permission")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def remove_group_permission(self, group_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_permission.delete().where(
                    self.db.tbl.group_permission.c.group_id == group_id,
                    self.db.tbl.group_permission.c.scope_id == scope_id,
                    self.db.tbl.group_permission.c.permission == permission,
                )
            ).rowcount

    @web.rpc("auth_get_group_permissions", "get_group_permissions")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_group_permissions(self, group_id, scope_id):
        group_scopes = [
            scope["id"] for scope in self.walk_scope_tree(scope_id)
        ]
        #
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.group_permission.select().where(
                    self.db.tbl.group_permission.c.group_id == group_id,
                    self.db.tbl.group_permission.c.scope_id.in_(group_scopes),
                )
            ).mappings().all()
        #
        result = list(set([item["permission"] for item in data]))  # pylint: disable=R1718
        result.sort()
        #
        return result

    @web.rpc("auth_list_group_permissions", "list_group_permissions")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_group_permissions(self, group_id=None):
        with self.db.engine.connect() as connection:
            if group_id is not None:
                permissions = connection.execute(
                    self.db.tbl.group_permission.select().where(
                        self.db.tbl.group_permission.c.group_id == group_id,
                    )
                ).mappings().all()
            else:
                permissions = connection.execute(
                    self.db.tbl.group_permission.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in permissions
        ]
