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

""" DB migration: lifecycle audit inbox (#7504)

auth_core writes lifecycle audit events here in the transaction that makes the change;
the admin plugin (pylon_main) drains them into its partitioned audit table.
"""

revision = "202611161200"
down_revision = "202611131300"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    op.create_table(
        f"{module_name}__lifecycle_audit_inbox",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"),
                  primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(36), nullable=False, unique=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    op.drop_table(f"{module_name}__lifecycle_audit_inbox")
