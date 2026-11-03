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

"""Grant the project governance permissions to roles that already carry a per-project override snapshot.

Projects with override rows never fall back to the role template, so without this grant no project admin of an
existing project could operate governance in the project, and no member could request it (issue #7269). Project
roles named admin get the operator permissions (agent identity bindings, autonomous mandates, credential references
and grants: view, manage, approve; credentials also probe) and the request permission; project roles named editor get
the request permission only. Viewers, the system role and custom roles gain nothing here. A project role has no mode,
so the grant never reads the system role table.

The ids of the rows inserted here are kept in a ledger table so downgrade removes exactly those rows and keeps grants a
project admin made later.
"""

revision = "202611031200"
down_revision = "202611021200"
branch_labels = None

import sqlalchemy as sa  # pylint: disable=E0401,C0413
from alembic import op  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413

OPERATOR_PERMISSIONS = [
    "governance.bindings.view",
    "governance.bindings.manage",
    "governance.bindings.approve",
    "governance.mandates.view",
    "governance.mandates.manage",
    "governance.mandates.approve",
    "credentials.view",
    "credentials.manage",
    "credentials.probe",
    "credentials.approve",
]

REQUEST_PERMISSIONS = ["governance.request"]

ROLE_PERMISSIONS = {
    "admin": OPERATOR_PERMISSIONS + REQUEST_PERMISSIONS,
    "editor": REQUEST_PERMISSIONS,
}

LEDGER_SUFFIX = "__mig_202611031200_granted"


def _grant(bind, module_name, role_name, permissions):
    """Insert each permission for every (project_id, role_id) of an override project's role ``role_name``; return the
    new ids."""
    table = f"{module_name}__project_role_permission"
    statement = sa.text(
        f"""
        INSERT INTO {table} (project_id, role_id, permission)
        SELECT s.project_id, s.role_id, :permission
        FROM (
            SELECT DISTINCT p.project_id, p.role_id
            FROM {table} p
            JOIN {module_name}__project_role pr
                ON pr.id = p.role_id
            WHERE pr.name = :role_name
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
    )
    inserted_ids = []
    for permission in permissions:
        inserted_ids += bind.execute(
            statement, {"permission": permission, "role_name": role_name}
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

    inserted_ids = []
    for role_name, permissions in ROLE_PERMISSIONS.items():
        inserted_ids += _grant(bind, module_name, role_name, permissions)

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
            value=OPERATOR_PERMISSIONS + REQUEST_PERMISSIONS,
            expanding=True,
        ))
    )
    op.drop_table(ledger)
