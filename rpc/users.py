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

import sqlalchemy
from sqlalchemy import func, or_, case, asc, desc
from sqlalchemy.exc import NoResultFound
from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools, revocation
from ..db import db_tools
from .tokens import SYSTEM_TOKEN_NAME


def _check_idp_subject(issuer, tid, oid):
    """ A subject is all three parts, each a non-empty string """
    for name, value in (("issuer", issuer), ("tid", tid), ("oid", oid)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"IdP subject needs a non-empty {name}")


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_user", "add_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_user(self, email: str, name: Optional[str] = '', id_: Optional[int] = None):
        """ Create a user together with its system token, atomically """
        values = {
            "email": email,
        }
        if name:
            values['name'] = name
        if id_:
            values["id"] = id_

        # The engine is configured with isolation_level=AUTOCOMMIT, so the two
        # inserts below would commit independently and a crash in between would
        # leave a user with no system token. Request a real transaction for this
        # connection only.
        isolation_level = "SERIALIZABLE" \
            if self.db.url.startswith("sqlite:") else "READ COMMITTED"

        with self.db.engine.connect().execution_options(
                isolation_level=isolation_level,
        ) as connection:
            with connection.begin():
                user_id = connection.execute(
                    self.db.tbl.user.insert().values(**values)
                ).inserted_primary_key[0]
                #
                connection.execute(
                    self.db.tbl.token.insert().values(
                        uuid=str(uuid_.uuid4()),
                        user_id=user_id,
                        expires=None,
                        name=SYSTEM_TOKEN_NAME,
                    )
                )
        #
        return user_id

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
        #
        epoch = None
        with revocation.transaction(self.db) as connection:
            result = connection.execute(
                self.db.tbl.user.update().where(
                    self.db.tbl.user.c.id == id_
                ).values(**values
                         ).returning(
                    self.db.tbl.user.c.id,
                    self.db.tbl.user.c.name
                )
            ).first()
            # A suspension change must reach every cache; it is bumped in the same
            # transaction so nobody sees the new state under the old epoch.
            if suspended is not None and result is not None:
                epoch = revocation.bump_epoch(connection, self.db, "user", id_)
        #
        if epoch is not None:
            revocation.fire_invalidate(self.context, "user", id_, epoch)
        #
        return result

    @web.rpc("auth_delete_user", "delete_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_user(self, user_id: int):
        with self.db.engine.connect() as connection:
            deleted = connection.execute(
                self.db.tbl.user.delete().where(
                    self.db.tbl.user.c.id == user_id
                )
            ).rowcount
        # The row (and its tokens, by cascade) is gone, so there is no epoch left
        # to bump: absence reads back as "no such user" and denies. The event only
        # makes caches drop the user now.
        if deleted:
            revocation.fire_invalidate(self.context, "user", user_id, None)
        #
        return deleted

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

    @web.rpc("auth_get_user_by_idp_subject", "get_user_by_idp_subject")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user_by_idp_subject(self, issuer: str, tid: str, oid: str) -> Optional[dict]:
        """ The user that carries this IdP subject, None if nobody does """
        _check_idp_subject(issuer, tid, oid)
        #
        tbl = self.db.tbl.user
        with self.db.engine.connect() as connection:
            user = connection.execute(
                tbl.select().where(
                    tbl.c.idp_issuer == issuer,
                    tbl.c.idp_tid == tid,
                    tbl.c.idp_oid == oid,
                )
            ).mappings().first()
        #
        return None if user is None else db_tools.sqlalchemy_mapping_to_dict(user)

    @web.rpc("auth_set_user_idp_subject", "set_user_idp_subject")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def set_user_idp_subject(self, user_id: int, issuer: str, tid: str, oid: str) -> bool:
        """ Link a user to an IdP subject, once

        True if the subject was written, False if the user already carried exactly
        this subject. Raises if the user carries a different one (a subject is
        immutable: re-pointing an account is a decision for an operator, not for a
        sign-in), if the user does not exist, or if another user already carries it.

        The write is conditional on the user having no subject, so two concurrent
        sign-ins cannot both link. It bumps the user's revocation epoch: cached
        entries built before the link are dropped.
        """
        _check_idp_subject(issuer, tid, oid)
        #
        tbl = self.db.tbl.user
        no_subject = sqlalchemy.and_(
            tbl.c.idp_issuer.is_(None),
            tbl.c.idp_tid.is_(None),
            tbl.c.idp_oid.is_(None),
        )
        #
        epoch = None
        with revocation.transaction(self.db) as connection:
            linked = connection.execute(
                tbl.update().where(
                    tbl.c.id == user_id, no_subject,
                ).values(idp_issuer=issuer, idp_tid=tid, idp_oid=oid)
            ).rowcount
            #
            if linked:
                epoch = revocation.bump_epoch(connection, self.db, "user", user_id)
            else:
                current = connection.execute(
                    sqlalchemy.select(
                        tbl.c.idp_issuer, tbl.c.idp_tid, tbl.c.idp_oid,
                    ).where(tbl.c.id == user_id)
                ).first()
                if current is None:
                    raise ValueError(f"No such user found: id={user_id}")
                if tuple(current) != (issuer, tid, oid):
                    raise ValueError(
                        f"User {user_id} is already linked to a different IdP subject"
                    )
        #
        if epoch is not None:
            revocation.fire_invalidate(self.context, "user", user_id, epoch)
        #
        return bool(linked)

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
            # Batch-fetch administration roles for users
            # Role priority: super_admin > admin > editor > viewer
            user_admin_roles = {}
            user_ids = [row['id'] for row in rows]
            if user_ids:
                # Get all administration mode roles
                admin_roles_q = sqlalchemy.select(
                    self.db.tbl.role.c.id,
                    self.db.tbl.role.c.name,
                ).where(
                    self.db.tbl.role.c.mode == 'administration',
                )
                admin_roles = {r[0]: r[1] for r in connection.execute(admin_roles_q).all()}
                #
                if admin_roles:
                    # Get user-role assignments for these users
                    user_roles_q = sqlalchemy.select(
                        self.db.tbl.user_role.c.user_id,
                        self.db.tbl.user_role.c.role_id,
                    ).where(
                        self.db.tbl.user_role.c.role_id.in_(admin_roles.keys()),
                        self.db.tbl.user_role.c.user_id.in_(user_ids),
                    )
                    #
                    # Role priority order (highest first)
                    role_priority = ['super_admin', 'admin', 'editor', 'viewer']
                    #
                    for user_id, role_id in connection.execute(user_roles_q).all():
                        role_name = admin_roles.get(role_id)
                        if role_name:
                            # Keep the highest priority role
                            current_role = user_admin_roles.get(user_id)
                            if current_role is None:
                                user_admin_roles[user_id] = role_name
                            else:
                                # Compare priorities
                                current_priority = role_priority.index(current_role) if current_role in role_priority else 999
                                new_priority = role_priority.index(role_name) if role_name in role_priority else 999
                                if new_priority < current_priority:
                                    user_admin_roles[user_id] = role_name
        #
        return {
            "rows": [
                {
                    **db_tools.sqlalchemy_mapping_to_dict(item),
                    "is_admin": item['id'] in user_admin_roles,  # Backward compatibility
                    "admin_role": user_admin_roles.get(item['id']),  # New field: role name or None
                }
                for item in rows
            ],
            "total": total,
            "counts": {
                "platform": platform_count,
                "system": system_count,
            },
        }
