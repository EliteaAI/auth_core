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

""" DB migration: Add suspended column to user table """

revision = "202602241500"
down_revision = "202602231400"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    op.add_column(
        f"{module_name}__user",
        sa.Column("suspended", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    op.drop_column(f"{module_name}__user", "suspended")
