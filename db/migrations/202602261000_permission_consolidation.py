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

""" DB migration: Permission consolidation """

revision = "202602261000"
down_revision = "202602241500"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    
    # Get database dialect
    connection = op.get_bind()
    db_dialect = connection.dialect.name

    # D1. Add public project permissions + monitoring to viewer role
    if db_dialect == 'sqlite':
        # SQLite doesn't support VALUES clause, use UNION instead
        permissions_d1 = [
            'models.promptlib_shared.author.detail',
            'models.promptlib_shared.collection.details',
            'models.promptlib_shared.collections.list',
            'models.promptlib_shared.predict.post',
            'models.promptlib_shared.public_collection.details',
            'models.promptlib_shared.tags.list',
            'models.promptlib_shared.trending_authors.list',
            'models.prompt_lib.feedbacks.create',
            'models.applications.public_applications.list',
            'models.applications.public_application.details',
            'models.applications.task.delete',
            'models.applications.toolkits.details',
            'models.applications.trending_authors.list',
            'models.applications.export_import.export',
            'models.applications.fork.post',
            'models.chat.participants.create',
            'models.chat.folders.get',
            'models.chat.folders.update',
            'models.chat.folders.create',
            'monitoring.monitorable'
        ]
        
        # Build UNION query for SQLite
        union_parts = [f"SELECT '{perm}' as perm" for perm in permissions_d1]
        union_query = ' UNION ALL '.join(union_parts)
        
        op.execute(
            sa.text(
                f"""
                INSERT INTO {module_name}__role_permission (role_id, permission)
                SELECT r.id, p.perm
                FROM {module_name}__role r
                CROSS JOIN ({union_query}) AS p
                WHERE r.name = 'viewer' AND r.mode = 'default'
                AND NOT EXISTS (
                    SELECT 1 FROM {module_name}__role_permission rp
                    WHERE rp.role_id = r.id AND rp.permission = p.perm
                );
                """
            )
        )
    else:
        # PostgreSQL and other databases supporting VALUES
        op.execute(
            sa.text(
                f"""
                INSERT INTO {module_name}__role_permission (role_id, permission)
                SELECT r.id, p.perm
                FROM {module_name}__role r
                CROSS JOIN (VALUES
                    ('models.promptlib_shared.author.detail'),
                    ('models.promptlib_shared.collection.details'),
                    ('models.promptlib_shared.collections.list'),
                    ('models.promptlib_shared.predict.post'),
                    ('models.promptlib_shared.public_collection.details'),
                    ('models.promptlib_shared.tags.list'),
                    ('models.promptlib_shared.trending_authors.list'),
                    ('models.prompt_lib.feedbacks.create'),
                    ('models.applications.public_applications.list'),
                    ('models.applications.public_application.details'),
                    ('models.applications.task.delete'),
                    ('models.applications.toolkits.details'),
                    ('models.applications.trending_authors.list'),
                    ('models.applications.export_import.export'),
                    ('models.applications.fork.post'),
                    ('models.chat.participants.create'),
                    ('models.chat.folders.get'),
                    ('models.chat.folders.update'),
                    ('models.chat.folders.create'),
                    ('monitoring.monitorable')
                ) AS p(perm)
                WHERE r.name = 'viewer' AND r.mode = 'default'
                AND NOT EXISTS (
                    SELECT 1 FROM {module_name}__role_permission rp
                    WHERE rp.role_id = r.id AND rp.permission = p.perm
                );
                """
            )
        )

    # D2. Add moderator permissions to editor role
    if db_dialect == 'sqlite':
        permissions_d2 = [
            'models.promptlib_shared.approve_collection.post',
            'models.promptlib_shared.reject_collection.delete'
        ]
        
        union_parts = [f"SELECT '{perm}' as perm" for perm in permissions_d2]
        union_query = ' UNION ALL '.join(union_parts)
        
        op.execute(
            sa.text(
                f"""
                INSERT INTO {module_name}__role_permission (role_id, permission)
                SELECT r.id, p.perm
                FROM {module_name}__role r
                CROSS JOIN ({union_query}) AS p
                WHERE r.name = 'editor' AND r.mode = 'default'
                AND NOT EXISTS (
                    SELECT 1 FROM {module_name}__role_permission rp
                    WHERE rp.role_id = r.id AND rp.permission = p.perm
                );
                """
            )
        )
    else:
        op.execute(
            sa.text(
                f"""
                INSERT INTO {module_name}__role_permission (role_id, permission)
                SELECT r.id, p.perm
                FROM {module_name}__role r
                CROSS JOIN (VALUES
                    ('models.promptlib_shared.approve_collection.post'),
                    ('models.promptlib_shared.reject_collection.delete')
                ) AS p(perm)
                WHERE r.name = 'editor' AND r.mode = 'default'
                AND NOT EXISTS (
                    SELECT 1 FROM {module_name}__role_permission rp
                    WHERE rp.role_id = r.id AND rp.permission = p.perm
                );
                """
            )
        )

    # D3a. Migrate prompt_lib_public users -> viewer
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_user_role (project_id, user_id, role_id)
            SELECT pur.project_id, pur.user_id, viewer_role.id
            FROM {module_name}__project_user_role pur
            JOIN {module_name}__project_role custom_role ON pur.role_id = custom_role.id AND pur.project_id = custom_role.project_id
            JOIN {module_name}__project_role viewer_role ON viewer_role.project_id = pur.project_id AND viewer_role.name = 'viewer'
            WHERE custom_role.name = 'prompt_lib_public'
            AND NOT EXISTS (SELECT 1 FROM {module_name}__project_user_role existing WHERE existing.project_id = pur.project_id AND existing.user_id = pur.user_id AND existing.role_id = viewer_role.id);
            """
        )
    )

    # D3b. Migrate public_admin users -> admin
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_user_role (project_id, user_id, role_id)
            SELECT pur.project_id, pur.user_id, admin_role.id
            FROM {module_name}__project_user_role pur
            JOIN {module_name}__project_role custom_role ON pur.role_id = custom_role.id AND pur.project_id = custom_role.project_id
            JOIN {module_name}__project_role admin_role ON admin_role.project_id = pur.project_id AND admin_role.name = 'admin'
            WHERE custom_role.name = 'public_admin'
            AND NOT EXISTS (SELECT 1 FROM {module_name}__project_user_role existing WHERE existing.project_id = pur.project_id AND existing.user_id = pur.user_id AND existing.role_id = admin_role.id);
            """
        )
    )

    # D3c. Migrate prompt_lib_moderators users -> editor
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_user_role (project_id, user_id, role_id)
            SELECT pur.project_id, pur.user_id, editor_role.id
            FROM {module_name}__project_user_role pur
            JOIN {module_name}__project_role custom_role ON pur.role_id = custom_role.id AND pur.project_id = custom_role.project_id
            JOIN {module_name}__project_role editor_role ON editor_role.project_id = pur.project_id AND editor_role.name = 'editor'
            WHERE custom_role.name = 'prompt_lib_moderators'
            AND NOT EXISTS (SELECT 1 FROM {module_name}__project_user_role existing WHERE existing.project_id = pur.project_id AND existing.user_id = pur.user_id AND existing.role_id = editor_role.id);
            """
        )
    )

    # D3d. Migrate monitor users -> viewer
    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__project_user_role (project_id, user_id, role_id)
            SELECT pur.project_id, pur.user_id, viewer_role.id
            FROM {module_name}__project_user_role pur
            JOIN {module_name}__project_role custom_role ON pur.role_id = custom_role.id AND pur.project_id = custom_role.project_id
            JOIN {module_name}__project_role viewer_role ON viewer_role.project_id = pur.project_id AND viewer_role.name = 'viewer'
            WHERE custom_role.name = 'monitor'
            AND NOT EXISTS (SELECT 1 FROM {module_name}__project_user_role existing WHERE existing.project_id = pur.project_id AND existing.user_id = pur.user_id AND existing.role_id = viewer_role.id);
            """
        )
    )

    # D3e. Remove all custom role user assignments
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_user_role
            WHERE role_id IN (SELECT id FROM {module_name}__project_role WHERE name IN ('prompt_lib_public', 'prompt_lib_moderators', 'public_admin', 'monitor'));
            """
        )
    )

    # D4. Delete custom/corrupted project_role entries
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__project_role
            WHERE name NOT IN ('admin', 'editor', 'viewer', 'system', 'Executor');
            """
        )
    )

    # D5. Remove monitor from central table (may be no-op after A1)
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__role_permission
            WHERE role_id IN (SELECT id FROM {module_name}__role WHERE name = 'monitor' AND mode = 'default');
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__role WHERE name = 'monitor' AND mode = 'default';
            """
        )
    )

    # D6. Clear dead project_role_permission table
    # Use DELETE for SQLite compatibility, TRUNCATE for PostgreSQL
    if db_dialect == 'sqlite':
        op.execute(
            sa.text(
                f"""
                DELETE FROM {module_name}__project_role_permission;
                """
            )
        )
    else:
        op.execute(
            sa.text(
                f"""
                TRUNCATE TABLE {module_name}__project_role_permission;
                """
            )
        )

    # D7. Reclaim disk space
    if db_dialect == 'sqlite':
        pass  # No VACCUM
    else:
        op.execute(sa.text("COMMIT"))
        op.execute(sa.text(f"VACUUM FULL {module_name}__project_role_permission"))


def downgrade(module, payload):
    pass
