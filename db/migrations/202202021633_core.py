#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0103,C0116

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

""" DB migration """

revision = "202202021633"
down_revision = None
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.create_table(
        f"{module_name}__user",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("email", sa.Text, index=True, unique=True),
        sa.Column("name", sa.Text, index=True, nullable=True),
        sa.Column("last_login", sa.DateTime, nullable=True)
    )
    #
    op.create_table(
        f"{module_name}__user_provider",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "provider_ref", sa.Text,
            primary_key=True, index=True, unique=True,
        ),
    )
    #
    op.create_table(
        f"{module_name}__group",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "parent_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="SET NULL"
            ),
        ),
        sa.Column("name", sa.Text, index=True),
    )
    #
    op.create_table(
        f"{module_name}__group_provider",
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "provider_ref", sa.Text,
            primary_key=True, index=True, unique=True,
        ),
    )
    #
    op.create_table(
        f"{module_name}__user_group",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
    )
    #
    scope_table = op.create_table(
        f"{module_name}__scope",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "parent_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="SET NULL"
            ),
        ),
        sa.Column("name", sa.Text, index=True),
    )
    #
    op.bulk_insert(
        scope_table,
        [
            {"name": "Global", "parent_id": None},
        ]
    )
    #
    op.create_table(
        f"{module_name}__user_permission",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "scope_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column("permission", sa.Text, primary_key=True),
    )
    #
    op.create_table(
        f"{module_name}__group_permission",
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "scope_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column("permission", sa.Text, primary_key=True),
    )
    #
    op.create_table(
        f"{module_name}__token",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "uuid", sa.String(36),
            index=True, unique=True,
        ),
        sa.Column("expires", sa.DateTime),
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            index=True,
        ),
        sa.Column("name", sa.Text),
    )
    #
    roles_table = op.create_table(
        f"{module_name}__role",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True, index=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("mode", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "mode"),
    )
    #
    op.bulk_insert(
        roles_table,
        [
            {"name": "system", "mode": "administration"},
            {"name": "admin", "mode": "administration"},
            {"name": "editor", "mode": "administration"},
            {"name": "viewer", "mode": "administration"},
            {"name": "system", "mode": "developer"},
            {"name": "admin", "mode": "developer"},
            {"name": "editor", "mode": "developer"},
            {"name": "viewer", "mode": "developer"},
            {"name": "system", "mode": "default"},
            {"name": "admin", "mode": "default"},
            {"name": "editor", "mode": "default"},
            {"name": "viewer", "mode": "default"},
        ]
    )
    #
    op.create_table(
        f"{module_name}__role_permission",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("permission", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("role_id", "permission"),
        sa.ForeignKeyConstraint(["role_id"], [f"{module_name}__role.id"], ondelete='CASCADE')
    )
    #
    op.create_table(
        f"{module_name}__user_role",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "role_id"),
        sa.ForeignKeyConstraint(["user_id"], [f"{module_name}__user.id"], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(["role_id"], [f"{module_name}__role.id"], ondelete='CASCADE')
    )


def downgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.drop_table(f"{module_name}__token")
    op.drop_table(f"{module_name}__group_permission")
    op.drop_table(f"{module_name}__user_permission")
    op.drop_table(f"{module_name}__scope")
    op.drop_table(f"{module_name}__user_group")
    op.drop_table(f"{module_name}__group_provider")
    op.drop_table(f"{module_name}__group")
    op.drop_table(f"{module_name}__user_provider")
    op.drop_table(f"{module_name}__user")
    op.drop_table(f"{module_name}__role")
    op.drop_table(f"{module_name}__role_permission")
    op.drop_table(f"{module_name}__user_role")
