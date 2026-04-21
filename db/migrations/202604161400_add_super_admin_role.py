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

"""Add super_admin role to administration, developer, and default modes"""

revision = "202604161400"
down_revision = "202602261000"
branch_labels = None

from alembic import op  # pylint: disable=E0401,C0413
import sqlalchemy as sa  # pylint: disable=E0401,C0413


MODES = ["administration", "developer", "default"]


def upgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    for mode in MODES:
        op.execute(
            sa.text(
                f"""
                INSERT INTO {module_name}__role (name, mode)
                VALUES (:name, :mode)
                ON CONFLICT (name, mode) DO NOTHING
                """
            ).bindparams(name="super_admin", mode=mode)
        )


def downgrade(module, payload):
    _ = payload
    #
    module_name = module.descriptor.name
    #
    for mode in MODES:
        op.execute(
            sa.text(
                f"""
                DELETE FROM {module_name}__role
                WHERE name = :name AND mode = :mode
                """
            ).bindparams(name="super_admin", mode=mode)
        )

