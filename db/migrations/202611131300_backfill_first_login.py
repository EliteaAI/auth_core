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

"""Backfill first_login from the creation time of the user's private project (#7490).

The private project is created on the user's first successful login, so its creation time stands in for the
first login of users who logged in before first_login was recorded. Only users who logged in, have no first_login
and have a verified private project (named ``project_user_<uid>`` and owned by ``uid``) are filled; users who never
logged in keep NULL so their real first login is still recorded. The project creation time is the earliest
statistic start_time, as returned by ``project_get_created_at``.

The ids of the users filled here are kept in a ledger table so downgrade clears exactly those values.
"""

revision = "202611131300"
down_revision = "202611131200"
branch_labels = None

import os  # pylint: disable=C0413

import sqlalchemy as sa  # pylint: disable=E0401,C0413
from alembic import op  # pylint: disable=E0401,C0413
from pylon.core.tools import log  # pylint: disable=E0401,C0413

PERSONAL_PREFIX = "project_user_"
LEDGER_SUFFIX = "__mig_202611131300_first_login"


def _projects_tables(bind):
    """ The projects plugin keeps project and statistic in POSTGRES_SCHEMA, not in auth_core's search_path """
    inspector = sa.inspect(bind)
    if bind.dialect.name == "postgresql":
        schema = os.environ.get("POSTGRES_SCHEMA", "centry")
        if inspector.has_table("project", schema=schema) and inspector.has_table("statistic", schema=schema):
            return f'"{schema}".project', f'"{schema}".statistic'
    if inspector.has_table("project") and inspector.has_table("statistic"):
        return "project", "statistic"
    return None, None


def upgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    bind = op.get_bind()
    user_table = f"{module_name}__user"
    ledger = f"{module_name}{LEDGER_SUFFIX}"
    #
    if not sa.inspect(bind).has_table(ledger):
        op.create_table(ledger, sa.Column("id", sa.Integer, primary_key=True))
    #
    project_table, statistic_table = _projects_tables(bind)
    if project_table is None:
        log.warning("project / statistic table missing; first_login was not backfilled")
        return
    #
    rows = bind.execute(sa.text(
        f"""
        SELECT p.owner_id, MIN(s.start_time)
        FROM {project_table} p
        JOIN {statistic_table} s ON s.project_id = p.id
        JOIN {user_table} u ON u.id = p.owner_id
        WHERE p.name = :prefix || CAST(p.owner_id AS VARCHAR(32))
          AND u.first_login IS NULL
          AND u.last_login IS NOT NULL
          AND s.start_time IS NOT NULL
        GROUP BY p.owner_id
        """
    ), {"prefix": PERSONAL_PREFIX}).all()
    #
    filled = []
    for user_id, created_at in rows:
        updated = bind.execute(sa.text(
            f"UPDATE {user_table} SET first_login = :created_at WHERE id = :user_id AND first_login IS NULL"
        ), {"user_id": user_id, "created_at": created_at}).rowcount
        if updated:
            filled.append(user_id)
    #
    if filled:
        bind.execute(
            sa.text(f"INSERT INTO {ledger} (id) VALUES (:id)"),
            [{"id": user_id} for user_id in filled],
        )
    log.info("Backfilled first_login for %s user(s)", len(filled))


def downgrade(module, payload):
    _ = payload
    module_name = module.descriptor.name
    ledger = f"{module_name}{LEDGER_SUFFIX}"
    #
    if not sa.inspect(op.get_bind()).has_table(ledger):
        log.warning("%s missing; leaving first_login untouched", ledger)
        return
    #
    # Only values this revision filled; first logins recorded at login stay
    op.execute(sa.text(
        f"UPDATE {module_name}__user SET first_login = NULL WHERE id IN (SELECT id FROM {ledger})"
    ))
    op.drop_table(ledger)
