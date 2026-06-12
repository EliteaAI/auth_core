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

"""Add project_context permissions: view for all roles, edit depends on project type"""

revision = "202606110900"
down_revision = "202604161400"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name

    # -------------------------------------------------------------------------
    # Part 1: Central role_permission table (fallback for projects with no overrides)
    #
    # These permissions apply when a project has NO rows in project_role_permission.
    # - view: granted to admin, editor, viewer
    # - edit: granted to admin only
    #
    # Note: Uses ON CONFLICT with UniqueConstraint(role_id, permission) defined in 202202021633_core.py
    # -------------------------------------------------------------------------

    # Single INSERT for all central permissions (8 permission/role/mode combinations)
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__role_permission (role_id, permission)
            SELECT r.id, perms.permission
            FROM {module_name}__role r
            CROSS JOIN (
                SELECT 'models.project_context.view' AS permission, 'admin' AS role_name, 'default' AS mode
                UNION ALL SELECT 'models.project_context.view', 'editor', 'default'
                UNION ALL SELECT 'models.project_context.view', 'viewer', 'default'
                UNION ALL SELECT 'models.project_context.view', 'admin', 'administration'
                UNION ALL SELECT 'models.project_context.view', 'editor', 'administration'
                UNION ALL SELECT 'models.project_context.view', 'viewer', 'administration'
                UNION ALL SELECT 'models.project_context.edit', 'admin', 'default'
                UNION ALL SELECT 'models.project_context.edit', 'admin', 'administration'
            ) perms
            WHERE r.name = perms.role_name AND r.mode = perms.mode
            ON CONFLICT (role_id, permission) DO NOTHING;
            """
        )
    )

    # -------------------------------------------------------------------------
    # Part 2a: Patch project_role_permission for projects WITH existing overrides
    #
    # Projects that already have rows in project_role_permission bypass the central
    # fallback entirely, so we must add the new permissions explicitly.
    #
    # Note: Uses ON CONFLICT with UniqueConstraint(project_id, role_id, permission)
    #       defined in 202511111607_project_roles.py
    # -------------------------------------------------------------------------

    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_role_permission (project_id, role_id, permission)
            SELECT DISTINCT pr.project_id, pr.id, perms.permission
            FROM {module_name}__project_role pr
            CROSS JOIN (
                -- view: all roles
                SELECT 'models.project_context.view' AS permission, 'admin' AS role_name
                UNION ALL SELECT 'models.project_context.view', 'editor'
                UNION ALL SELECT 'models.project_context.view', 'viewer'
                -- edit: admin only
                UNION ALL SELECT 'models.project_context.edit', 'admin'
            ) perms
            WHERE pr.name = perms.role_name
            -- Project must have existing overrides
            AND EXISTS (
                SELECT 1 FROM {module_name}__project_role_permission existing
                WHERE existing.project_id = pr.project_id
            )
            ON CONFLICT (project_id, role_id, permission) DO NOTHING;
            """
        )
    )



def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name

    for permission in ('models.project_context.view', 'models.project_context.edit'):
        op.execute(
            sa.text(
                f"DELETE FROM {module_name}__role_permission WHERE permission = :perm"
            ).bindparams(perm=permission)
        )
        op.execute(
            sa.text(
                f"DELETE FROM {module_name}__project_role_permission WHERE permission = :perm"
            ).bindparams(perm=permission)
        )
