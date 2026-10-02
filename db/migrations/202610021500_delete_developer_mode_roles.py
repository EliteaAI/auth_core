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

"""Delete the unused developer-mode roles and their grants (issue #6880)."""

revision = "202610021500"
down_revision = "202610021200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    prefix = module.descriptor.name
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(f"{prefix}__role"):
        return
    role_ids = f"SELECT id FROM {prefix}__role WHERE mode = 'developer'"
    # Children first: SQLite test DBs do not enforce the ON DELETE CASCADE FKs.
    for child in ("role_permission", "user_role"):
        if inspector.has_table(f"{prefix}__{child}"):
            op.execute(sa.text(f"DELETE FROM {prefix}__{child} WHERE role_id IN ({role_ids})"))
    op.execute(sa.text(f"DELETE FROM {prefix}__role WHERE mode = 'developer'"))


def downgrade(module, payload):
    # The developer roles were never assigned or checked, so there is nothing to restore.
    _ = module, payload
