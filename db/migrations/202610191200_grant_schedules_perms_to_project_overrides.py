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

"""Grant the schedule permissions to roles that already carry a per-project override snapshot.

Projects with override rows never fall back to the role template, so without this
grant nobody in an existing project could use Schedules (issue #7011).
Roles that may create or edit agents get the six user permissions, custom roles
included. Only roles named admin get admin, export and import (Change owner).

The ids of the rows inserted here are kept in a ledger table so downgrade removes
exactly those rows and keeps grants a project admin made later.
"""

revision = "202610191200"
down_revision = "202610160900"
branch_labels = None

import sqlalchemy as sa  # pylint: disable=E0401,C0413
from alembic import op  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413

SCHEDULE_USER_PERMISSIONS = [
    "models.applications.schedules.list",
    "models.applications.schedules.details",
    "models.applications.schedules.create",
    "models.applications.schedules.update",
    "models.applications.schedules.delete",
    "models.applications.schedules.run",
]

SCHEDULE_ADMIN_PERMISSIONS = [
    "models.applications.schedules.admin",
    "models.applications.schedules.export",
    "models.applications.schedules.import",
]

AGENT_EDIT_PERMISSIONS = [
    "models.applications.applications.create",
    "models.applications.application.update",
]

LEDGER_SUFFIX = "__mig_202610191200_granted"


def _grant(bind, module_name, source, permissions, **params):
    """Insert each permission for every (project_id, role_id) of `source`; return the new ids."""
    table = f"{module_name}__project_role_permission"
    statement = sa.text(
        f"""
        INSERT INTO {table} (project_id, role_id, permission)
        SELECT s.project_id, s.role_id, :permission
        FROM ({source}) s
        WHERE NOT EXISTS (
            SELECT 1
            FROM {table} ex
            WHERE ex.project_id = s.project_id
              AND ex.role_id = s.role_id
              AND ex.permission = :permission
        )
        RETURNING id
        """
    ).bindparams(*[sa.bindparam(name, expanding=True) for name in params])
    inserted_ids = []
    for permission in permissions:
        inserted_ids += bind.execute(
            statement, {"permission": permission, **params}
        ).scalars().all()
    return inserted_ids


def upgrade(module, payload):
    _ = payload

    module_name = module.descriptor.name
    bind = op.get_bind()

    op.create_table(
        f"{module_name}{LEDGER_SUFFIX}",
        sa.Column("id", sa.Integer, primary_key=True),
    )

    inserted_ids = _grant(
        bind, module_name,
        f"""
        SELECT DISTINCT project_id, role_id
        FROM {module_name}__project_role_permission
        WHERE permission IN :agent_permissions
        """,
        SCHEDULE_USER_PERMISSIONS,
        agent_permissions=AGENT_EDIT_PERMISSIONS,
    )
    inserted_ids += _grant(
        bind, module_name,
        f"""
        SELECT DISTINCT p.project_id, p.role_id
        FROM {module_name}__project_role_permission p
        JOIN {module_name}__project_role pr
            ON pr.id = p.role_id
        WHERE pr.name = 'admin'
        """,
        SCHEDULE_ADMIN_PERMISSIONS,
    )

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

    # Only rows this revision inserted; independent grants of the same permissions stay.
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_role_permission
            WHERE permission IN :perms
              AND id IN (SELECT id FROM {ledger})
            """
        ).bindparams(sa.bindparam(
            "perms",
            value=SCHEDULE_USER_PERMISSIONS + SCHEDULE_ADMIN_PERMISSIONS,
            expanding=True,
        ))
    )
    op.drop_table(ledger)
