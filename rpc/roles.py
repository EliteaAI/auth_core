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

import datetime
from typing import Optional

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from sqlalchemy import select, bindparam, and_  # pylint: disable=E0401

from ..tools import rpc_tools
from ..db import db_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_get_token_permissions", "get_token_permissions")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_token_permissions(self, token_id: int,  # pylint: disable=W1113,W0613
                               mode: str = 'administration',
                               project_id: Optional[int] = None,
                               *args, **kwargs) -> set:
        token = self.get_token(token_id=token_id)
        token_user = token["user_id"]
        # Update last_login only once per day to reduce DB writes
        now = datetime.datetime.now(datetime.timezone.utc)
        user = self.get_user(user_id=token_user)
        last_login = user.get("last_login")
        if last_login is None or last_login.date() < now.date():
            self.update_user(token_user, last_login=now)
        # log.info("Token : %s", token)
        # log.info("Token mode: %s", mode)
        # log.info("Token project_id: %s", project_id)
        user_permissions = self.get_user_permissions(
            user_id=token_user,
            mode=mode,
            project_id=project_id
        )
        # log.info("Token user_permissions: %s", user_permissions)
        return user_permissions

    @web.rpc("auth_get_roles", "get_roles")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_roles(self, mode: str = "administration") -> list[str]:
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.role.select().where(
                    self.db.tbl.role.c.mode == mode,
                ).order_by(
                    self.db.tbl.role.c.id
                )
            ).mappings().all()
            # log.info(f"{data=}")
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in data
        ]

    @web.rpc("auth_add_role", "add_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_role(self, name: str, mode: str = "administration") -> int:
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.role.insert().values(
                    name=name,
                    mode=mode,
                )
            ).inserted_primary_key[0]

    @web.rpc("auth_delete_role", "delete_role")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_role(self, name: str, mode: str = "administration") -> None:
        with self.db.engine.connect() as connection:
            role_id = connection.execute(
                self.db.tbl.role.select().where(
                    self.db.tbl.role.c.name == name,
                    self.db.tbl.role.c.mode == mode,
                )
            ).mappings().first()["id"]
            connection.execute(
                self.db.tbl.user_role.delete().where(
                    self.db.tbl.user_role.c.role_id == role_id,
                )
            )
            connection.execute(
                self.db.tbl.role_permission.delete().where(
                    self.db.tbl.role_permission.c.role_id == role_id,
                )
            )
            connection.execute(
                self.db.tbl.role.delete().where(
                    self.db.tbl.role.c.id == role_id,
                )
            )

    @web.rpc("auth_update_role_name", "update_role_name")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def update_role_name(self, old_name: str, new_name: str, mode: str = "administration") -> int:
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.role.update().where(
                    self.db.tbl.role.c.name == old_name,
                    self.db.tbl.role.c.mode == mode,
                ).values(
                    name=new_name,
                )
            ).rowcount
        return data

    @web.rpc("auth_assign_user_to_role", "assign_user_to_role")
    def assign_user_to_role(self,
                            user_id: int,
                            role_name: str,
                            mode: str = 'administration',
                            project_id: Optional[int] = None) -> None:
        #
        rpc_timeout = self.descriptor.config.get("rpc_timeout", 120)
        #
        match mode:
            case 'default':
                assert project_id, 'projects_id is required for default mode assignment'
                self.context.rpc_manager.timeout(rpc_timeout).admin_add_user_to_project(
                    project_id=project_id,
                    user_id=user_id,
                    role_names=[role_name]
                )
            case _:
                with self.db.engine.connect() as connection:
                    # Remove existing roles in this mode first (enforce single role)
                    existing_role_ids = [
                        row['id'] for row in connection.execute(
                            self.db.tbl.role.select().where(
                                self.db.tbl.role.c.mode == mode,
                            )
                        ).mappings().all()
                    ]
                    if existing_role_ids:
                        connection.execute(
                            self.db.tbl.user_role.delete().where(
                                self.db.tbl.user_role.c.user_id == user_id,
                                self.db.tbl.user_role.c.role_id.in_(existing_role_ids),
                            )
                        )
                    #
                    role_id = connection.execute(
                        self.db.tbl.role.select().where(
                            self.db.tbl.role.c.name == role_name,
                            self.db.tbl.role.c.mode == mode,
                        )
                    ).mappings().first()['id']
                    connection.execute(
                        self.db.tbl.user_role.insert().values(
                            user_id=user_id,
                            role_id=role_id,
                        )
                    )

    @web.rpc("auth_remove_user_from_role", "remove_user_from_role")
    def remove_user_from_role(self,
                              user_id: int,
                              role_name: str,
                              mode: str = 'administration') -> None:
        with self.db.engine.connect() as connection:
            role = connection.execute(
                self.db.tbl.role.select().where(
                    self.db.tbl.role.c.name == role_name,
                    self.db.tbl.role.c.mode == mode,
                )
            ).mappings().first()
            #
            if role is None:
                return
            #
            connection.execute(
                self.db.tbl.user_role.delete().where(
                    self.db.tbl.user_role.c.user_id == user_id,
                    self.db.tbl.user_role.c.role_id == role['id'],
                )
            )

    @web.rpc("auth_get_permissions", "get_permissions")
    def get_permissions(self, mode="administration"):
        with self.db.engine.connect() as connection:
            data_1 = connection.execute(
                self.db.tbl.role.join(
                    self.db.tbl.role_permission, isouter=True
                ).select().where(
                    self.db.tbl.role.c.mode == mode,
                ).order_by(self.db.tbl.role.c.name)
            ).mappings().all()
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in data_1
        ]

    @web.rpc("auth_get_permissions_by_role", "get_permissions_by_role")
    def get_permissions_by_role(self, role_name, mode="administration"):
        with self.db.engine.connect() as connection:
            data_1 = connection.execute(
                self.db.tbl.role.join(
                    self.db.tbl.role_permission, isouter=True
                ).select()
                .where(
                    self.db.tbl.role.c.name == role_name,
                    self.db.tbl.role.c.mode == mode
                )
                .order_by(self.db.tbl.role.c.name)
            ).mappings().all()
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in data_1
        ]

    @web.rpc("auth_set_permission_for_role", "set_permission_for_role")
    def set_permission_for_role(self, role_name: str, permission_name: str,  # pylint: disable=W0613
                                mode: str = "administration", **kwargs) -> None:
        with self.db.engine.connect() as connection:
            # role_id = connection.execute(
            #     self.db.tbl.role.select().where(
            #         self.db.tbl.role.c.name == role_name,
            #         self.db.tbl.role.c.mode == mode
            #     )
            # ).inserted_primary_key[0]
            tmp = connection.execute(
                self.db.tbl.role.select().where(
                    self.db.tbl.role.c.name == role_name,
                    self.db.tbl.role.c.mode == mode
                )
            )
            q1 = tmp.mappings().one()
            try:
                q2 = tmp.inserted_primary_key[0]
            except:  # pylint: disable=W0702
                q2 = q1["id"]
            log.info(f"{q1=}   {q2=}")
            role_id = q2
            # role_id = data["id"]
            connection.execute(
                self.db.tbl.role_permission.insert().values(
                    role_id=role_id,
                    permission=permission_name,
                )
            )

    @web.rpc("auth_remove_permission_from_role", "remove_permission_from_role")
    def remove_permission_from_role(self, role_name, permission_name, mode="administration"):
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.role.select().where(
                    self.db.tbl.role.c.name == role_name,
                    self.db.tbl.role.c.mode == mode
                )
            ).mappings().one()
            # log.info(f"To delete in role {data=}")
            role_id = data["id"]
            data = connection.execute(
                self.db.tbl.role_permission.delete().where(
                    self.db.tbl.role_permission.c.role_id == role_id,
                    self.db.tbl.role_permission.c.permission == permission_name,
                )
            ).rowcount
        return data

    @web.rpc("auth_insert_permissions", "insert_permissions")
    def insert_permissions(self, permissions: tuple[str, str, str]):  # pylint: disable=R1711
        if self.db.url.startswith("sqlite:"):
            from sqlalchemy.dialects.sqlite import insert  # pylint: disable=E0401,C0415
        else:  # postgresql:
            from sqlalchemy.dialects.postgresql import insert  # pylint: disable=E0401,C0415
        #
        with self.db.engine.connect() as connection:
            insert_permission = insert(self.db.tbl.role_permission).values(
                role_id=select(self.db.tbl.role.c.id).where(
                    and_(
                        self.db.tbl.role.c.name == bindparam("name"),
                        self.db.tbl.role.c.mode == bindparam("mode")
                    )
                ).scalar_subquery(),
                permission=bindparam("permission")
            ).on_conflict_do_nothing(
                index_elements=[
                    self.db.tbl.role_permission.c.role_id,
                    self.db.tbl.role_permission.c.permission
                ]
            )
            connection.execute(
                insert_permission,
                [{"name": name, "mode": mode, "permission": permission} for
                 name, mode, permission in permissions]
            )
        return None

    @web.rpc("auth_get_user_roles", "get_user_roles")
    def get_user_roles(self, user_id, mode='administration'):
        # log.info(f"{user_id=}")
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.user_role.join(
                    self.db.tbl.role, isouter=True
                ).select().where(
                    self.db.tbl.user_role.c.user_id == user_id,
                    self.db.tbl.role.c.mode == str(mode),
                ).order_by(self.db.tbl.role.c.name)
            ).mappings().all()
            #
            result = [
                db_tools.sqlalchemy_mapping_to_dict(item) for item in data
            ]
            # log.info(f"user roles {result=}")
            return {item['name'] for item in result}

    @web.rpc("auth_get_user_permissions", "get_user_permissions")
    def get_user_permissions(self, user_id: int, mode: str = 'administration',  # pylint: disable=W0613
                             project_id: Optional[str] = None,
                             **kwargs) -> set:
        #
        rpc_timeout = self.descriptor.config.get("rpc_timeout", 120)
        #
        if mode in ['default', 'prompt_lib']:
            if project_id:
                try:
                    return self.context.rpc_manager.timeout(
                        rpc_timeout
                    ).admin_get_permissions_in_project(
                        project_id=project_id,
                        user_id=user_id
                    )
                except:  # pylint: disable=W0702
                    log.exception("Main pylon RPC call error")
                    return set()
            else:
                return set()
        #
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.user_role.join(
                    self.db.tbl.role, isouter=True
                ).join(
                    self.db.tbl.role_permission, isouter=True
                ).select().where(
                    self.db.tbl.user_role.c.user_id == user_id,
                    self.db.tbl.role.c.mode == str(mode),
                ).order_by(self.db.tbl.role.c.name)
            ).mappings().all()
            #
            result = [
                db_tools.sqlalchemy_mapping_to_dict(item) for item in data
            ]
            # log.info(f"user permissions {result=}")
            return {item['permission'] for item in result}
