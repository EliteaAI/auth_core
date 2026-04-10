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

import sqlalchemy

from ..tools import rpc_tools
from ..db import db_tools


class RPC:  # pylint: disable=R0903,E1101

    #
    # project_role
    #

    @web.rpc("auth_add_project_role", "add_project_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_project_role(self, project_id, name, id_=...):
        values = {
            "project_id": project_id,
            "name": name,
        }
        #
        if id_ is not ...:
            values["id"] = id_
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_role.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_update_project_role", "update_project_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def update_project_role(self, project_id, id_, name):
        values = {
            "name": name,
        }
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_role.update().where(
                    self.db.tbl.project_role.c.project_id == project_id,
                    self.db.tbl.project_role.c.id == id_,
                ).values(**values).returning(
                    self.db.tbl.project_role.c.project_id,
                    self.db.tbl.project_role.c.id,
                    self.db.tbl.project_role.c.name,
                )
            ).first()

    @web.rpc("auth_delete_project_role", "delete_project_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_project_role(self, project_id, name=..., id_=...):
        with self.db.engine.connect() as connection:
            if name is not ...:
                return connection.execute(
                    self.db.tbl.project_role.delete().where(
                        self.db.tbl.project_role.c.project_id == project_id,
                        self.db.tbl.project_role.c.name == name,
                    )
                ).rowcount
            #
            if id_ is not ...:
                return connection.execute(
                    self.db.tbl.project_role.delete().where(
                        self.db.tbl.project_role.c.project_id == project_id,
                        self.db.tbl.project_role.c.id == id_,
                    )
                ).rowcount
            #
            return 0

    @web.rpc("auth_get_project_role", "get_project_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_project_role(self, project_id, name=..., id_=...):
        project_role = None
        #
        with self.db.engine.connect() as connection:
            if name is not ...:
                project_role = connection.execute(
                    self.db.tbl.project_role.select().where(
                        self.db.tbl.project_role.c.project_id == project_id,
                        self.db.tbl.project_role.c.name == name,
                    )
                ).mappings().one_or_none()
            elif id_ is not ...:
                project_role = connection.execute(
                    self.db.tbl.project_role.select().where(
                        self.db.tbl.project_role.c.project_id == project_id,
                        self.db.tbl.project_role.c.id == id_,
                    )
                ).mappings().one_or_none()
        #
        if project_role is None:
            return None
        #
        return db_tools.sqlalchemy_mapping_to_dict(project_role)

    @web.rpc("auth_list_project_roles", "list_project_roles")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_project_roles(self, project_id):
        with self.db.engine.connect() as connection:
            project_role = connection.execute(
                self.db.tbl.project_role.select().where(
                    self.db.tbl.project_role.c.project_id == project_id,
                )
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in project_role]

    #
    # project_role_permission
    #

    @web.rpc("auth_add_project_role_permission", "add_project_role_permission")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_project_role_permission(self, project_id, role_id, permission):
        values = {
            "project_id": project_id,
            "role_id": role_id,
            "permission": permission,
        }
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_role_permission.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_project_role_permission", "delete_project_role_permission")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_project_role_permission(self, project_id, role_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_role_permission.delete().where(
                    self.db.tbl.project_role_permission.c.project_id == project_id,
                    self.db.tbl.project_role_permission.c.role_id == role_id,
                    self.db.tbl.project_role_permission.c.permission == permission,
                )
            ).rowcount

    @web.rpc("auth_list_project_role_permissions", "list_project_role_permissions")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_project_role_permissions(self, project_id, role_id=...):
        with self.db.engine.connect() as connection:
            query = self.db.tbl.project_role_permission.select().where(
                self.db.tbl.project_role_permission.c.project_id == project_id,
            )
            #
            if role_id is not ...:
                query = query.where(self.db.tbl.project_role_permission.c.role_id == role_id)
            #
            project_role_permissions = connection.execute(query).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in project_role_permissions]

    #
    # project_user_role
    #

    @web.rpc("auth_add_project_user_role", "add_project_user_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_project_user_role(self, project_id, user_id, role_id):
        values = {
            "project_id": project_id,
            "user_id": user_id,
            "role_id": role_id,
        }
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_user_role.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_project_user_role", "delete_project_user_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_project_user_role(self, project_id, user_id, role_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.project_user_role.delete().where(
                    self.db.tbl.project_user_role.c.project_id == project_id,
                    self.db.tbl.project_user_role.c.user_id == user_id,
                    self.db.tbl.project_user_role.c.role_id == role_id,
                )
            ).rowcount

    @web.rpc("auth_update_project_user_roles", "update_project_user_roles")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def update_project_user_roles(self, project_id, user_id, role_ids):
        # Remove all roles and add new ones
        with self.db.engine.connect() as connection:
            with connection.begin():
                connection.execute(
                    self.db.tbl.project_user_role.delete().where(
                        self.db.tbl.project_user_role.c.project_id == project_id,
                        self.db.tbl.project_user_role.c.user_id == user_id,
                    )
                )
                for role_id in role_ids:
                    connection.execute(
                        self.db.tbl.project_user_role.insert().values(
                            project_id=project_id,
                            user_id=user_id,
                            role_id=role_id
                        )
                    )
        return True

    @web.rpc("auth_list_project_user_roles", "list_project_user_roles")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_project_user_roles(self, project_id, user_id=...):
        with self.db.engine.connect() as connection:
            query = self.db.tbl.project_user_role.select().where(
                self.db.tbl.project_user_role.c.project_id == project_id,
            )
            #
            if user_id is not ...:
                query = query.where(self.db.tbl.project_user_role.c.user_id == user_id)
            #
            project_user_roles = connection.execute(query).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in project_user_roles]

    @web.rpc("auth_get_project_user_permissions", "get_project_user_permissions")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_project_user_permissions(self, project_id, user_id):
        """Resolve permissions for a user in a project.

        Checks project_role_permission first (per-project overrides).
        Falls back to central role_permission (mode='default') if no overrides exist.
        """
        with self.db.engine.connect() as connection:
            # Step A: Get role IDs + names for this user in this project
            role_q = sqlalchemy.select(
                self.db.tbl.project_role.c.id,
                self.db.tbl.project_role.c.name,
            ).select_from(
                self.db.tbl.project_user_role.join(
                    self.db.tbl.project_role,
                    self.db.tbl.project_user_role.c.role_id == self.db.tbl.project_role.c.id
                )
            ).where(
                self.db.tbl.project_user_role.c.project_id == project_id,
                self.db.tbl.project_user_role.c.user_id == user_id,
            )
            rows = connection.execute(role_q).all()
            #
            if not rows:
                return set()
            #
            role_ids = {r[0] for r in rows}
            role_names = {r[1] for r in rows}
            #
            # Step B: Check project-specific permission overrides
            project_perms_q = sqlalchemy.select(
                self.db.tbl.project_role_permission.c.permission
            ).where(
                self.db.tbl.project_role_permission.c.project_id == project_id,
                self.db.tbl.project_role_permission.c.role_id.in_(role_ids),
            )
            project_perms = {row[0] for row in connection.execute(project_perms_q).all()}
            #
            if project_perms:
                return project_perms
            #
            # Step C: Fall back to central role_permission (mode='default')
            perms_q = sqlalchemy.select(
                self.db.tbl.role_permission.c.permission
            ).select_from(
                self.db.tbl.role.join(
                    self.db.tbl.role_permission,
                    self.db.tbl.role.c.id == self.db.tbl.role_permission.c.role_id
                )
            ).where(
                self.db.tbl.role.c.mode == 'default',
                self.db.tbl.role.c.name.in_(role_names),
            )
            return {row[0] for row in connection.execute(perms_q).all()}

    @web.rpc("auth_check_user_in_project", "check_user_in_project")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def check_user_in_project(self, project_id, user_id):
        query = sqlalchemy.select(
            self.db.tbl.project_user_role.c.id
        ).where(
            self.db.tbl.project_user_role.c.project_id == project_id,
            self.db.tbl.project_user_role.c.user_id == user_id,
        ).limit(1)
        #
        with self.db.engine.connect() as connection:
            result = connection.execute(query).first()
        #
        return result is not None

    @web.rpc("auth_check_user_in_projects", "check_user_in_projects")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def check_user_in_projects(self, project_ids, user_id):
        query = sqlalchemy.select(
            self.db.tbl.project_user_role.c.project_id
        ).where(
             self.db.tbl.project_user_role.c.project_id.in_(project_ids),
             self.db.tbl.project_user_role.c.user_id == user_id,
        ).distinct()
        #
        with self.db.engine.connect() as connection:
            results = connection.execute(query).all()
        #
        return [row[0] for row in results]

    @web.rpc("auth_list_project_users", "list_project_users")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_project_users(self, project_id):
        query = sqlalchemy.select(
            self.db.tbl.project_user_role.c.user_id
        ).where(
            self.db.tbl.project_user_role.c.project_id == project_id,
        ).distinct()
        #
        with self.db.engine.connect() as connection:
            results = connection.execute(query).all()
        #
        return [row[0] for row in results]

    @web.rpc("auth_apply_project_roles_snapshot", "apply_project_roles_snapshot")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def apply_project_roles_snapshot(self, snapshot):
        # snapshot: list of dicts: {
        #   "project_id": 1,
        #   "roles": [{"name": "...", "permissions": ["..."]}],
        #   "assignments": [{"user_id": 1, "role": "..."}]
        # }
        mapping_roles = {} # (project_id, role_name) -> role_id

        # 1. Ensure all roles exist
        with self.db.engine.connect() as connection:
            # Load existing roles for all targeted projects
            project_ids = [s["project_id"] for s in snapshot]
            existing_roles = connection.execute(
                self.db.tbl.project_role.select().where(
                    self.db.tbl.project_role.c.project_id.in_(project_ids)
                )
            ).mappings().all()
            for row in existing_roles:
                mapping_roles[(row["project_id"], row["name"])] = row["id"]

            # Identify missing roles
            roles_to_insert = []
            for project in snapshot:
                p_id = project["project_id"]
                for role_data in project.get("roles", []):
                    r_name = role_data["name"]
                    if (p_id, r_name) not in mapping_roles:
                        roles_to_insert.append({"project_id": p_id, "name": r_name})

            # Insert missing roles
            if roles_to_insert:
                # Insert and get IDs back. Since executemany with returning might not be supported/easy for mapping back
                # simply insert and re-query or insert one by one?
                # For simplicity and support, we can just insert one by one or insert distinct then re-query
                # Let's insert one by one to easily update mapping map, or use ON CONFLICT if DB supports it.
                # Assuming standard SQL or supported wrapper.
                # Optimized approach:
                connection.execute(
                    self.db.tbl.project_role.insert(), roles_to_insert
                )
                # Re-query to get IDs
                refreshed_roles = connection.execute(
                     self.db.tbl.project_role.select().where(
                        self.db.tbl.project_role.c.project_id.in_(project_ids)
                    )
                ).mappings().all()
                for row in refreshed_roles:
                    mapping_roles[(row["project_id"], row["name"])] = row["id"]

            # 2. Permissions
            # We want to add missing permissions.
            # Get existing permissions
            existing_permissions = set()
            db_perms = connection.execute(
                 self.db.tbl.project_role_permission.select().where(
                    self.db.tbl.project_role_permission.c.project_id.in_(project_ids)
                )
            ).mappings().all()
            for row in db_perms:
                 existing_permissions.add((row["role_id"], row["permission"]))

            perms_to_insert = []
            for project in snapshot:
                p_id = project["project_id"]
                for role_data in project.get("roles", []):
                    r_name = role_data["name"]
                    if (p_id, r_name) in mapping_roles:
                        r_id = mapping_roles[(p_id, r_name)]
                        for perm in role_data.get("permissions", []):
                            if (r_id, perm) not in existing_permissions:
                                perms_to_insert.append({
                                    "project_id": p_id,
                                    "role_id": r_id,
                                    "permission": perm
                                })
                                existing_permissions.add((r_id, perm))

            if perms_to_insert:
                connection.execute(
                    self.db.tbl.project_role_permission.insert(), perms_to_insert
                )

            # 3. Assignments
            # Get existing assignments
            existing_assignments = set()
            db_assigns = connection.execute(
                 self.db.tbl.project_user_role.select().where(
                    self.db.tbl.project_user_role.c.project_id.in_(project_ids)
                )
            ).mappings().all()
            for row in db_assigns:
                existing_assignments.add((row["project_id"], row["user_id"], row["role_id"]))

            assigns_to_insert_candidates = []
            all_involved_users = set()

            for project in snapshot:
                p_id = project["project_id"]
                for assign in project.get("assignments", []):
                    u_id = assign["user_id"]
                    r_name = assign["role"]
                    if (p_id, r_name) in mapping_roles:
                        r_id = mapping_roles[(p_id, r_name)]
                        if (p_id, u_id, r_id) not in existing_assignments:
                            assigns_to_insert_candidates.append({
                                "project_id": p_id,
                                "user_id": u_id,
                                "role_id": r_id
                            })
                            all_involved_users.add(u_id)

            # Validate users exist
            valid_users = set()
            if all_involved_users:
                # Chunk user query if too many
                all_users_list = list(all_involved_users)
                chunk_size = 1000
                for i in range(0, len(all_users_list), chunk_size):
                    chunk = all_users_list[i:i+chunk_size]
                    u_rows = connection.execute(
                        self.db.tbl.user.select().with_only_columns(
                            self.db.tbl.user.c.id
                        ).where(self.db.tbl.user.c.id.in_(chunk))
                    ).all()
                    for r in u_rows:
                        valid_users.add(r[0])

            assignments_to_insert = [
                a for a in assigns_to_insert_candidates
                if a["user_id"] in valid_users
            ]

            if assignments_to_insert:
                connection.execute(
                    self.db.tbl.project_user_role.insert(), assignments_to_insert
                )
        return True
