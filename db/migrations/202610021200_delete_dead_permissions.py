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

"""Delete permission strings no code registers or checks (issue #6874)."""

revision = "202610021200"
down_revision = "202609251200"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


# Must match admin tasks/permission_tasks.py DEAD_PERMISSIONS (the task cleans already-migrated DBs).
DEAD_PERMISSIONS = [
    "admin",
    "configuration",
    "configuration.evaluation",
    "configuration.evaluation.platform_dimensions",
    "configurations",
    "invites",
    "invites.platform",
    "migration",
    "models.chat.conversations.list_custom",
    "modes",
    "projects",
    "projects.projects.backup",
    "projects.projects.restore",
    "runtime",
    "models.prompt_lib.approve_collection.post",
    "models.prompt_lib.collection.delete",
    "models.prompt_lib.collection.details",
    "models.prompt_lib.collection.update",
    "models.prompt_lib.collections.create",
    "models.prompt_lib.collections.list",
    "models.prompt_lib.public_collection.details",
    "models.prompt_lib.reject_collection.delete",
    "models.promptlib_shared.approve_collection.post",
    "models.promptlib_shared.collection.delete",
    "models.promptlib_shared.collection.details",
    "models.promptlib_shared.collection.update",
    "models.promptlib_shared.collections.create",
    "models.promptlib_shared.collections.list",
    "models.promptlib_shared.public_collection.details",
    "models.promptlib_shared.reject_collection.delete",
]

TABLES = ("role_permission", "project_role_permission", "group_permission", "user_permission")


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    inspector = sa.inspect(op.get_bind())
    for table in TABLES:
        if not inspector.has_table(f"{module_name}__{table}"):
            continue
        op.execute(
            sa.text(f"DELETE FROM {module_name}__{table} WHERE permission IN :perms")
            .bindparams(sa.bindparam("perms", value=DEAD_PERMISSIONS, expanding=True))
        )


def downgrade(module, payload):
    # The deleted strings grant nothing, so there is nothing to restore.
    _ = module, payload
