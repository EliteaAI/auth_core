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

"""Add monitor role

Revision ID: 202412021300
Revises:
Create Date: 2024-12-02 13:39:37.784522

"""

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


# revision identifiers, used by Alembic.
revision = '202412021300'
down_revision = "202202021633"
branch_labels = None
depends_on = None

role_name = "monitor"
role_mode = "default"


def upgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__role (name, mode)
            VALUES (:name, :mode)
            """
        ).bindparams(**{"name": role_name, "mode": role_mode})
    )


def downgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__role
            WHERE name = :name AND mode = :mode
            """
        ).bindparams(**{"name": role_name, "mode": role_mode})
    )
