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

"""Add IdP subject keys to users (C-1009, issue #6941).

Sign-in matched users by e-mail address alone. An OIDC provider lets its
administrators change the address on an account, and an address can be reissued to
a different person, so "same e-mail" is not "same person": whoever holds the address
at the identity provider inherits the platform account.

An identity provider vouches for a stable identity instead: the issuer, the tenant
id (tid) and the object id (oid) of the account. Those never change for a person
and are never handed to anyone else. This revision gives a user a place to keep
them:

 * user.idp_issuer, user.idp_tid, user.idp_oid: nullable TEXT, all NULL until the
   user signs in through a provider that supplies them (auth_init links them, see
   its identity_key policy). Existing rows are left untouched.
 * a partial unique index over the three columns, applying only when all three are
   set, so a subject belongs to at most one user while users that have none (every
   user today, and users from providers without tid/oid) never collide.

The statements are guarded so that re-running them, or running them against a
database that already has the columns or the index, is a no-op.
"""

revision = "202610160900"
down_revision = "202610151200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


COLUMNS = ("idp_issuer", "idp_tid", "idp_oid")
INDEX_SUFFIX = "user_idp_subject"
WHERE = " AND ".join(f"{name} IS NOT NULL" for name in COLUMNS)


def _columns(table):
    inspector = sa.inspect(op.get_bind())
    return {item["name"] for item in inspector.get_columns(table)}


def _indexes(table):
    inspector = sa.inspect(op.get_bind())
    return {item["name"] for item in inspector.get_indexes(table)}


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    table = f"{module_name}__user"
    index = f"uq_{module_name}__{INDEX_SUFFIX}"
    #
    existing = _columns(table)
    for name in COLUMNS:
        if name not in existing:
            op.add_column(table, sa.Column(name, sa.Text, nullable=True))
    #
    if index not in _indexes(table):
        op.create_index(
            index, table, list(COLUMNS), unique=True,
            postgresql_where=sa.text(WHERE),
            sqlite_where=sa.text(WHERE),
        )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    table = f"{module_name}__user"
    index = f"uq_{module_name}__{INDEX_SUFFIX}"
    #
    if index in _indexes(table):
        op.drop_index(index, table_name=table)
    #
    existing = _columns(table)
    for name in COLUMNS:
        if name in existing:
            op.drop_column(table, name)
