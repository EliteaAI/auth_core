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

"""Scope project backup/restore: project admins in project settings, super_admin in the admin panel.

Permission seeding is additive (falsy recommended_roles are skipped and the
insert is ON CONFLICT DO NOTHING), so neither of these two changes can be made
by editing recommended_roles alone:

 * a role that already holds a permission keeps it — the administration-scope
   backup grant has to be deleted here;
 * a project whose roles already carry a per-project override snapshot never
   falls back to the central template, so the project-scope backup permissions
   have to be inserted into those snapshots here.
"""

revision = "202609011200"
down_revision = "202607161200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


# Project scope (project settings page). Mirrors the recommended_roles the admin
# plugin registers: restore is admin and up, download also reaches editors.
PROJECT_PERMISSIONS = ("models.project_backup", "models.project_backup.download")
PROJECT_RESTORE_PERMISSION = "models.project_backup.restore"

_ADMIN_ROLES = ("admin", "super_admin", "system")

ROLE_PERMISSION_PAIRS = [
    (role, perm)
    for role in _ADMIN_ROLES
    for perm in PROJECT_PERMISSIONS + (PROJECT_RESTORE_PERMISSION,)
] + [("editor", perm) for perm in PROJECT_PERMISSIONS]

GRANTED_PROJECT_PERMISSIONS = list(PROJECT_PERMISSIONS) + [PROJECT_RESTORE_PERMISSION]

# Administration scope (admin panel). Every project on the platform is in reach
# there, so backup follows restore and stays with super_admin.
REVOKED_ADMIN_PERMISSIONS = [
    "projects.projects.backup",
    "projects.projects.backup.download",
]


def _mapping_subquery(db_dialect):
    """Render the (role_name, permission) mapping as an inline relation `v`.

    PostgreSQL supports a VALUES table; SQLite needs UNION ALL of SELECTs.
    Values are fixed in-source constants (no user input), so inlining is safe.
    """
    def _q(value):
        return "'" + value.replace("'", "''") + "'"

    if db_dialect == "sqlite":
        selects = [
            f"SELECT {_q(role)} AS role_name, {_q(perm)} AS permission"
            for role, perm in ROLE_PERMISSION_PAIRS
        ]
        return "(" + " UNION ALL ".join(selects) + ") AS v"
    #
    rows = ",\n            ".join(
        f"({_q(role)}, {_q(perm)})" for role, perm in ROLE_PERMISSION_PAIRS
    )
    return f"(VALUES\n            {rows}\n        ) AS v(role_name, permission)"


def upgrade(module, payload):
    _ = payload

    module_name = module.descriptor.name
    db_dialect = op.get_bind().dialect.name
    mapping = _mapping_subquery(db_dialect)

    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_role_permission (project_id, role_id, permission)
            SELECT s.project_id, s.role_id, v.permission
            FROM (
                SELECT DISTINCT project_id, role_id
                FROM {module_name}__project_role_permission
            ) s
            JOIN {module_name}__project_role pr
                ON pr.id = s.role_id
            JOIN {mapping}
                ON v.role_name = pr.name
            WHERE NOT EXISTS (
                SELECT 1
                FROM {module_name}__project_role_permission ex
                WHERE ex.project_id = s.project_id
                  AND ex.role_id = s.role_id
                  AND ex.permission = v.permission
            )
            """
        )
    )

    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__role_permission
            WHERE permission IN :perms
              AND role_id IN (
                SELECT id FROM {module_name}__role WHERE name = 'admin'
              )
            """
        ).bindparams(
            sa.bindparam("perms", value=REVOKED_ADMIN_PERMISSIONS, expanding=True)
        )
    )


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name

    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_role_permission
            WHERE permission IN :perms
            """
        ).bindparams(
            sa.bindparam("perms", value=GRANTED_PROJECT_PERMISSIONS, expanding=True)
        )
    )

    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__role_permission (role_id, permission)
            SELECT r.id, p.perm
            FROM {module_name}__role r
            CROSS JOIN (
                SELECT :backup AS perm
                UNION ALL SELECT :backup_download AS perm
            ) AS p
            WHERE r.name = 'admin'
              AND NOT EXISTS (
                SELECT 1 FROM {module_name}__role_permission rp
                WHERE rp.role_id = r.id AND rp.permission = p.perm
              )
            """
        ).bindparams(
            backup=REVOKED_ADMIN_PERMISSIONS[0],
            backup_download=REVOKED_ADMIN_PERMISSIONS[1],
        )
    )
