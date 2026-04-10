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

import sqlalchemy
from sqlalchemy import func, or_, case, asc, desc
from sqlalchemy.exc import NoResultFound
from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools
from ..db import db_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_user", "add_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_user(self, email: str, name: Optional[str] = '', id_: Optional[int] = None):
        values = {
            "email": email,
        }
        if name:
            values['name'] = name
        if id_:
            values["id"] = id_

        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_update_user", "update_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def update_user(
            self,
            id_: int,
            name: Optional[str] = '',
            last_login: Optional[datetime.datetime] = None,
            suspended: Optional[bool] = None,
    ):
        values = {}
        if name:
            values['name'] = name
        if last_login:
            values["last_login"] = last_login
        if suspended is not None:
            values["suspended"] = suspended
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.update().where(
                    self.db.tbl.user.c.id == id_
                ).values(**values
                         ).returning(
                    self.db.tbl.user.c.id,
                    self.db.tbl.user.c.name
                )
            ).first()

    @web.rpc("auth_delete_user", "delete_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_user(self, user_id: int):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.delete().where(
                    self.db.tbl.user.c.id == user_id
                )
            ).rowcount

    @web.rpc("auth_get_user", "get_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user(self, user_id: Optional[int] = None,
                  email: Optional[str] = None,
                  name: Optional[str] = None):
        try:
            if user_id is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.id == user_id,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
            if email is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.email == email,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
            if name is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.name == name,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
        except NoResultFound:
            if user_id is not None:
                raise RuntimeError(f"No such user found: id={user_id}") from None
            if email is not None:
                raise RuntimeError(f"No such user found: email={email}") from None
            if name is not None:
                raise RuntimeError(f"No such user found: name={name}") from None
            raise RuntimeError("No such user found") from None
        #
        raise ValueError("ID or name is not provided")

    @web.rpc("auth_list_users", "list_users")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_users(self, user_ids: Optional[list] = None) -> list[dict]:
        query = self.db.tbl.user.select()
        if user_ids:
            query = query.where(
                self.db.tbl.user.c.id.in_(user_ids),
            )
        with self.db.engine.connect() as connection:
            users = connection.execute(query).mappings().all()
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in users]

    @web.rpc("auth_search_users", "search_users")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def search_users(self, search: str) -> list[dict]:
        tbl = self.db.tbl.user
        search_pattern = f"%{search}%"
        query = tbl.select().where(
            or_(
                tbl.c.name.ilike(search_pattern),
                tbl.c.email.ilike(search_pattern),
            )
        )
        with self.db.engine.connect() as connection:
            users = connection.execute(query).mappings().all()
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in users]

    @web.rpc("auth_list_users_paginated", "list_users_paginated")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_users_paginated(
            self,
            limit: int = 20,
            offset: int = 0,
            search: Optional[str] = None,
            user_type: Optional[str] = None,
            sort_by: str = "name",
            sort_order: str = "asc",
    ) -> dict:
        tbl = self.db.tbl.user
        #
        allowed_sort = {"name", "email", "last_login", "id", "suspended"}
        if sort_by not in allowed_sort:
            sort_by = "name"
        if sort_order not in ("asc", "desc"):
            sort_order = "asc"
        #
        is_system = or_(
            tbl.c.email.like("system_user_%@centry.user"),
            tbl.c.email == "system@centry.user",
        )
        #
        with self.db.engine.connect() as connection:
            # Tab counts (without search filter)
            counts_q = sqlalchemy.select(
                func.count().label("total_count"),
                func.sum(case((is_system, 1), else_=0)).label("system_count"),
            ).select_from(tbl)
            counts_row = connection.execute(counts_q).one()
            system_count = int(counts_row.system_count or 0)
            platform_count = int(counts_row.total_count) - system_count
            #
            # Filtered query
            query = tbl.select()
            #
            if user_type == "system":
                query = query.where(is_system)
            elif user_type == "platform":
                query = query.where(~is_system)
            #
            if search:
                search_pattern = f"%{search}%"
                query = query.where(
                    or_(
                        tbl.c.name.ilike(search_pattern),
                        tbl.c.email.ilike(search_pattern),
                    )
                )
            #
            # Total after filters, before pagination
            count_q = sqlalchemy.select(
                func.count()
            ).select_from(query.alias())
            total = connection.execute(count_q).scalar()
            #
            # Sort
            sort_col = getattr(tbl.c, sort_by)
            sort_fn = desc if sort_order == "desc" else asc
            query = query.order_by(sort_fn(sort_col).nullslast())
            #
            # Paginate
            query = query.limit(limit).offset(offset)
            #
            rows = connection.execute(query).mappings().all()
            #
            # Batch-check admin status (administration mode)
            admin_user_ids = set()
            user_ids = [row['id'] for row in rows]
            if user_ids:
                admin_role_q = sqlalchemy.select(
                    self.db.tbl.role.c.id
                ).where(
                    self.db.tbl.role.c.name == 'admin',
                    self.db.tbl.role.c.mode == 'administration',
                )
                admin_role_row = connection.execute(admin_role_q).first()
                if admin_role_row:
                    admin_users_q = sqlalchemy.select(
                        self.db.tbl.user_role.c.user_id
                    ).where(
                        self.db.tbl.user_role.c.role_id == admin_role_row[0],
                        self.db.tbl.user_role.c.user_id.in_(user_ids),
                    )
                    admin_user_ids = {r[0] for r in connection.execute(admin_users_q).all()}
        #
        return {
            "rows": [
                {**db_tools.sqlalchemy_mapping_to_dict(item), "is_admin": item['id'] in admin_user_ids}
                for item in rows
            ],
            "total": total,
            "counts": {
                "platform": platform_count,
                "system": system_count,
            },
        }
