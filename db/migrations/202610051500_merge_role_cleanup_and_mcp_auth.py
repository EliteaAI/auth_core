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

"""Merge the role cleanup (202610021500) and MCP auth grant (202610051200) heads.

release/2.0.7 ships 202610051200 on top of 202609251200 without #16/#17, so both
branches hang off 202609251200 here. run_db_migrations upgrades to a single "head",
so this merge keeps main at one head, and a DB upgraded on 2.0.7 still runs
202610021200/202610021500 on its way here.
"""

revision = "202610051500"
down_revision = ("202610021500", "202610051200")
branch_labels = None


def upgrade(module, payload):
    _ = module, payload


def downgrade(module, payload):
    _ = module, payload
