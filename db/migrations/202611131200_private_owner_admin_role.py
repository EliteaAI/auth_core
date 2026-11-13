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

"""Grant the project admin role to the owner of each private project (#7507).

Private projects were created with their owner as editor / viewer only. The owner is verified when the project is
named ``project_user_<uid>``, its owner_id is ``uid`` and ``uid`` is a member of it; only that user gains admin, on
top of the roles they hold. Unverified private projects, projects without an admin role and non-owners already
holding admin are logged for review and left as they are. Each granted owner's revocation epoch is bumped so cached
permissions refresh.

The ids of the rows inserted here are kept in a ledger table so downgrade removes exactly those rows.
"""

revision = "202611131200"
down_revision = "202611121200"
branch_labels = None

import os  # pylint: disable=C0413

import sqlalchemy as sa  # pylint: disable=E0401,C0413
from alembic import op  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413

PERSONAL_PREFIX = "project_user_"
LEDGER_SUFFIX = "__mig_202611131200_granted"


def _project_table(bind):
    """ The projects plugin keeps project in POSTGRES_SCHEMA, not in auth_core's search_path """
    inspector = sa.inspect(bind)
    if bind.dialect.name == "postgresql":
        schema = os.environ.get("POSTGRES_SCHEMA", "centry")
        if inspector.has_table("project", schema=schema):
            return f'"{schema}".project'
    return "project" if inspector.has_table("project") else None


def _private_projects(bind, project_table):
    return bind.execute(sa.text(
        f"SELECT id, name, owner_id FROM {project_table} WHERE name LIKE :prefix ORDER BY id"
    ), {"prefix": f"{PERSONAL_PREFIX}%"}).all()


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    bind = op.get_bind()
    ledger = f"{module_name}{LEDGER_SUFFIX}"
    user_role = f"{module_name}__project_user_role"
    project_role = f"{module_name}__project_role"
    #
    if not sa.inspect(bind).has_table(ledger):
        op.create_table(ledger, sa.Column("id", sa.Integer, primary_key=True))
    #
    project_table = _project_table(bind)
    if project_table is None:
        log.warning("project table missing; no private project owner was granted admin")
        return
    #
    inserted_ids = []
    granted_users = []
    for project_id, name, owner_id in _private_projects(bind, project_table):
        uid = name[len(PERSONAL_PREFIX):]
        is_member = uid.isdigit() and bind.execute(sa.text(
            f"SELECT 1 FROM {user_role} WHERE project_id = :project_id AND user_id = :user_id LIMIT 1"
        ), {"project_id": project_id, "user_id": int(uid)}).first() is not None
        #
        if not (uid.isdigit() and int(uid) == owner_id and is_member):
            log.warning("Private project %s (%s, owner_id %s) has an unverified owner; left unchanged",
                        project_id, name, owner_id)
            continue
        #
        admin_role_id = bind.execute(sa.text(
            f"SELECT id FROM {project_role} WHERE project_id = :project_id AND name = 'admin'"
        ), {"project_id": project_id}).scalar()
        if admin_role_id is None:
            log.warning("Private project %s has no admin role; owner %s left unchanged", project_id, owner_id)
            continue
        #
        for (other_id,) in bind.execute(sa.text(
                f"SELECT user_id FROM {user_role} WHERE project_id = :project_id AND role_id = :role_id"
                " AND user_id <> :owner_id"
        ), {"project_id": project_id, "role_id": admin_role_id, "owner_id": owner_id}).all():
            log.warning("Private project %s: non-owner user %s holds admin; review it", project_id, other_id)
        #
        new_id = bind.execute(sa.text(
            f"""
            INSERT INTO {user_role} (project_id, user_id, role_id)
            SELECT :project_id, :user_id, :role_id
            WHERE NOT EXISTS (
                SELECT 1 FROM {user_role}
                WHERE project_id = :project_id AND user_id = :user_id AND role_id = :role_id
            )
            RETURNING id
            """
        ), {"project_id": project_id, "user_id": owner_id, "role_id": admin_role_id}).scalar()
        if new_id is not None:
            inserted_ids.append(new_id)
            granted_users.append(owner_id)
    #
    if inserted_ids:
        bind.execute(
            sa.text(f"INSERT INTO {ledger} (id) VALUES (:id)"),
            [{"id": row_id} for row_id in inserted_ids],
        )
    for user_id in sorted(set(granted_users)):
        bind.execute(sa.text(
            f"UPDATE {module_name}__user SET revocation_epoch = revocation_epoch + 1 WHERE id = :user_id"
        ), {"user_id": user_id})
    log.info("Granted admin to %s private project owner(s)", len(inserted_ids))


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    ledger = f"{module_name}{LEDGER_SUFFIX}"
    #
    if not sa.inspect(op.get_bind()).has_table(ledger):
        log.warning("%s missing; leaving project user roles untouched", ledger)
        return
    #
    # Only rows this revision inserted; admin granted to an owner in any other way stays
    op.execute(sa.text(
        f"DELETE FROM {module_name}__project_user_role WHERE id IN (SELECT id FROM {ledger})"
    ))
    op.drop_table(ledger)
