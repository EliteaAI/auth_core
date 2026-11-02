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

"""Add a scope to API tokens (C-1009, issue #7336).

A token acts with every permission of its owner in every project. A scoped token
names what it is for instead:

 * token.scope_projects: JSON array of project ids the token may act in;
 * token.scope_operations: JSON array of operations among run, build, admin.

Both nullable. A token is scoped only when both are set and it expires (add_token
refuses a scope without an expiry); every token that exists before the upgrade has
neither and stays what it is (a legacy token). The statements are guarded so that
re-running them, or running them against a database that already has the columns,
is a no-op.

Downgrade: dropping the columns turns every scoped token into an unscoped one that
still expires (it then acts in all its owner's projects, with all their rights, until
it expires). The downgrade logs how many scoped tokens it unscopes; delete them first
(or let them expire) when that is not wanted.
"""

revision = "202611021200"
down_revision = "202610191200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413


COLUMNS = ("scope_projects", "scope_operations")


def _columns(table):
    inspector = sa.inspect(op.get_bind())
    return {item["name"] for item in inspector.get_columns(table)}


def upgrade(module, payload):
    _ = payload
    table = f"{module.descriptor.name}__token"
    existing = _columns(table)
    for name in COLUMNS:
        if name not in existing:
            op.add_column(table, sa.Column(name, sa.JSON, nullable=True))


def downgrade(module, payload):
    _ = payload
    table = f"{module.descriptor.name}__token"
    existing = _columns(table)
    if "scope_projects" in existing:
        scoped = op.get_bind().execute(sa.text(
            f'SELECT count(*) FROM "{table}" WHERE scope_projects IS NOT NULL'
        )).scalar()
        if scoped:
            log.warning("Downgrade unscopes %s scoped API token(s): they keep their expiry", scoped)
    for name in COLUMNS:
        if name in existing:
            op.drop_column(table, name)
