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

"""Grant the shared-chat manage permission to admin and editor roles that carry a per-project override snapshot.

Projects with override rows never fall back to the role template, so without this
grant no invited Admin or Editor in an existing project could manage a chat shared
with them (issue #7757). Only project roles named admin or editor gain it, the roles
the template grants it to; custom roles are left to the project admin. A project role
has no mode, so the grant never reads the system role table.

The ids of the rows inserted here are kept in a ledger table so downgrade removes
exactly those rows and keeps grants a project admin made later.
"""

revision = "202611271200"
down_revision = "202611161200"
branch_labels = None

import sqlalchemy as sa  # pylint: disable=E0401,C0413
from alembic import op  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413

MANAGE_SHARED = "models.chat.conversations.manage_shared"
ROLE_NAMES = ["admin", "editor"]

LEDGER_SUFFIX = "__mig_202611271200_granted"


def upgrade(module, payload):
    _ = payload

    module_name = module.descriptor.name
    bind = op.get_bind()
    table = f"{module_name}__project_role_permission"

    op.create_table(
        f"{module_name}{LEDGER_SUFFIX}",
        sa.Column("id", sa.Integer, primary_key=True),
    )

    inserted_ids = bind.execute(
        sa.text(
            f"""
            INSERT INTO {table} (project_id, role_id, permission)
            SELECT s.project_id, s.role_id, :permission
            FROM (
                SELECT DISTINCT p.project_id, p.role_id
                FROM {table} p
                JOIN {module_name}__project_role pr
                    ON pr.id = p.role_id
                WHERE pr.name IN :role_names
            ) s
            WHERE NOT EXISTS (
                SELECT 1
                FROM {table} ex
                WHERE ex.project_id = s.project_id
                  AND ex.role_id = s.role_id
                  AND ex.permission = :permission
            )
            RETURNING id
            """
        ).bindparams(sa.bindparam("role_names", expanding=True)),
        {"permission": MANAGE_SHARED, "role_names": ROLE_NAMES},
    ).scalars().all()

    if inserted_ids:
        bind.execute(
            sa.text(f"INSERT INTO {module_name}{LEDGER_SUFFIX} (id) VALUES (:id)"),
            [{"id": row_id} for row_id in inserted_ids],
        )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    ledger = f"{module_name}{LEDGER_SUFFIX}"

    if not sa.inspect(op.get_bind()).has_table(ledger):
        log.warning("%s missing; leaving project role permissions untouched", ledger)
        return

    # Only rows this revision inserted; independent grants of the same permission stay.
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_role_permission
            WHERE permission = :permission
              AND id IN (SELECT id FROM {ledger})
            """
        ).bindparams(permission=MANAGE_SHARED)
    )
    op.drop_table(ledger)
