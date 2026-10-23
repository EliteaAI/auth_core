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

"""Add revocation epochs to users and tokens (C-1009, issue #6944).

pylon_main caches who a caller is and what they may do - in per-process TTL
caches and in a Redis auth-result cache - for up to 60 seconds. Nothing told those
caches that a user was suspended, a role was removed or a token was deleted, so a
revoked credential kept working until every cache had aged out, on every replica.

A revocation epoch is a monotonically increasing counter per user and per token.
Every operation that revokes or narrows access bumps it in the same transaction
as the change itself, and pylon_main compares the epoch a cached entry was built
with against the current one (itself cached for a few seconds): a newer epoch is a
cache miss. So the staleness bound becomes "the epoch read TTL" instead of "the
longest cache TTL", and it holds even when the invalidation event is lost.

Two columns, both BIGINT NOT NULL DEFAULT 0:

 * user.revocation_epoch: bumped by suspension changes and by every role
   assignment or removal for that user. Project-role changes bump the user's
   epoch rather than a per-(project, user) one. That is coarser - a role change in
   project A also makes the user's cached entries for project B miss once - but it
   needs one column instead of a side table, and an extra miss costs one RPC.
 * token.revocation_epoch: bumped when a token's expiry changes (rotation
   retirement). A deleted token has no row left to carry an epoch; its absence is
   the signal and reads back as "no such token".

The default makes the change backward compatible: rows that exist before the
upgrade start at epoch 0, which is what every cache entry built from them will
carry. The statements are guarded so that re-running them, or running them against
a database that already has the columns, is a no-op.
"""

revision = "202610151200"
down_revision = "202610051500"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


COLUMN = "revocation_epoch"
TABLES = ("user", "token")


def _has_column(table):
    inspector = sa.inspect(op.get_bind())
    return COLUMN in {item["name"] for item in inspector.get_columns(table)}


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    for name in TABLES:
        table = f"{module_name}__{name}"
        if _has_column(table):
            continue
        op.add_column(
            table,
            sa.Column(
                COLUMN, sa.BigInteger, nullable=False,
                server_default=sa.text("0"),
            ),
        )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    #
    for name in TABLES:
        table = f"{module_name}__{name}"
        if not _has_column(table):
            continue
        op.drop_column(table, COLUMN)
