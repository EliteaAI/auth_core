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

"""Reserve the 'elitea-system' token name for the platform (issue #5262).

Two things happen here, in this order, and both have to be done before any
provisioning code can run - which is why they are a migration and not part of
the backfill task:

 * Eviction. The reserved name only became unforgeable in this release, when the
   token API started rejecting it, so a user could have created a token with that
   name earlier. Such a row is renamed out of the reserved namespace, keeping its
   uuid and its expiry, so it stays an ordinary token its owner can still see and
   delete. Adopting it instead - clearing its expiry - would silently turn a
   credential the user chose, and may have exposed, into a permanent one that the
   API refuses to list or delete.

 * A partial unique index, so that "one system token per user" is enforced by the
   database rather than by the select-then-insert in ensure_system_token(). The
   index cannot be built while duplicates exist, hence the eviction first.

Migrations run before the table reflections in Module.init(), so on a supported
upgrade path no platform-created system token can exist yet: every row carrying
the reserved name is by definition a squatter, which is what makes the rename
unconditional. The exception is an environment that ran a pre-release build of
this branch, where provisioning happened before this revision existed - there the
platform's own rows are evicted too and the backfill task has to be re-run. Such
rows are recognisable by expires IS NULL and can simply be deleted.
"""

revision = "202609161200"
down_revision = "202609011200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413

from pylon.core.tools import log  # pylint: disable=E0401,C0413


# Kept in sync with rpc/tokens.py by hand: a migration has to stay readable at
# the revision it was written, so it does not import runtime constants.
SYSTEM_TOKEN_NAME = "elitea-system"
EVICTED_NAME_PREFIX = f"{SYSTEM_TOKEN_NAME}-conflict-"


def _index_name(table):
    return f"uq_{table}_system_per_user"


def upgrade(module, payload):
    _ = payload
    table = f"{module.descriptor.name}__token"

    evicted = op.get_bind().execute(
        sa.text(
            f"""
            UPDATE {table}
            SET name = :prefix || CAST(id AS TEXT)
            WHERE name = :reserved
            RETURNING id, user_id
            """
        ).bindparams(prefix=EVICTED_NAME_PREFIX, reserved=SYSTEM_TOKEN_NAME)
    ).fetchall()

    # The runbook's pre-flight query finds these rows by their new name, which
    # stops identifying them as soon as their owners add or remove tokens of
    # their own. This is the only durable record of whose token the release
    # renamed, and a rollback cannot reconstruct it.
    if evicted:
        log.warning(
            "Renamed %s token(s) out of the reserved name %r; report to owners",
            len(evicted), SYSTEM_TOKEN_NAME,
        )
    for token_id, user_id in evicted:
        log.warning(
            "Renamed token %s of user %s to %s%s",
            token_id, user_id, EVICTED_NAME_PREFIX, token_id,
        )

    where = sa.text(f"name = '{SYSTEM_TOKEN_NAME}'")
    op.create_index(
        _index_name(table),
        table,
        ["user_id"],
        unique=True,
        postgresql_where=where,
        sqlite_where=where,
    )


def downgrade(module, payload):
    _ = payload
    table = f"{module.descriptor.name}__token"

    # The eviction is not reversed: renaming those rows back would recreate the
    # duplicates this index exists to forbid.
    op.drop_index(_index_name(table), table_name=table)
