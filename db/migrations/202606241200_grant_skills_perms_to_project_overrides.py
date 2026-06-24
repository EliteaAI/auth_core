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

"""Grant Skills permissions to roles that already carry a per-project override snapshot."""

revision = "202606241200"
down_revision = "202604161400"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


SKILL_PERMISSION_PREFIX = "models.applications.skills.%"

_FULL = [
    "models.applications.skills.list",
    "models.applications.skills.details",
    "models.applications.skills.create",
    "models.applications.skills.update",
    "models.applications.skills.delete",
    "models.applications.skills.export",
]
_VIEWER = [
    "models.applications.skills.list",
    "models.applications.skills.details",
    "models.applications.skills.export",
]

ROLE_SKILL_PAIRS = (
    [("admin", p) for p in _FULL]
    + [("editor", p) for p in _FULL]
    + [("super_admin", p) for p in _FULL]
    + [("system", p) for p in _FULL]
    + [("viewer", p) for p in _VIEWER]
)


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
            for role, perm in ROLE_SKILL_PAIRS
        ]
        return "(" + " UNION ALL ".join(selects) + ") AS v"
    #
    rows = ",\n            ".join(
        f"({_q(role)}, {_q(perm)})" for role, perm in ROLE_SKILL_PAIRS
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


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    
    # NOTE: lossy, NOT a true inverse. The upgrade cannot tag the rows it inserted, so this
    # removes ALL skills.* per-project override rows -- including any a project admin added
    # legitimately after the feature shipped. Projects on the central fallback are unaffected
    # (they have no override rows).
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_role_permission
            WHERE permission LIKE :skill_pattern
            """
        ).bindparams(skill_pattern=SKILL_PERMISSION_PREFIX)
    )
