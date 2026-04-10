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

revision = "202511111607"
down_revision = "202412021300"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.create_table(
        f"{module_name}__project_role",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("project_id", sa.Integer, index=True, nullable=False),
        sa.Column("name", sa.Text, index=True, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name"),
    )
    #
    op.create_table(
        f"{module_name}__project_role_permission",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("project_id", sa.Integer, index=True, nullable=False),
        sa.Column(
            "role_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__project_role.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            index=True,
        ),
        sa.Column("permission", sa.Text, index=True, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "role_id", "permission"),
    )
    #
    op.create_table(
        f"{module_name}__project_user_role",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("project_id", sa.Integer, index=True, nullable=False),
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            index=True,
        ),
        sa.Column(
            "role_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__project_role.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            index=True,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "user_id", "role_id"),
    )


def downgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.drop_table(f"{module_name}__project_user_role")
    op.drop_table(f"{module_name}__project_role_permission")
    op.drop_table(f"{module_name}__project_role")
