#!/usr/bin/python3
# coding=utf-8

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

""" Module """

import time

import sqlalchemy  # pylint: disable=E0401
from sqlalchemy.orm import sessionmaker  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401

from .db import db_migrations


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # DB
        self.db = Holder()
        self.db.tbl = Holder()
        self.db.url = self.descriptor.config.get("db_url", None)
        self.db.options = self.descriptor.config.get("db_options", {})

    #
    # Module
    #

    def preload(self):
        """ Preload handler """
        self.descriptor.register_tool("auth_core", self)

    def init(self):
        """ Init module """
        log.info("Initializing module")
        #
        self.db.engine = sqlalchemy.create_engine(
            self.db.url, **self.db.options
        )
        #
        # Managed identity
        if self.descriptor.config.get("engine_use_managed_identity", False):
            from sqlalchemy import event  # pylint: disable=E0401,C0415
            from azure.identity import DefaultAzureCredential  # pylint: disable=E0401,C0415
            #
            @event.listens_for(self.db.engine, "do_connect")
            def _get_managed_token(dialect, conn_rec, cargs, cparams):  # pylint: disable=W0613
                credential = DefaultAzureCredential()
                token = credential.get_token("https://ossrdbms-aad.database.windows.net/.default").token
                cparams["password"] = token
        #
        self.wait_for_db()
        #
        db_migrations.run_db_migrations(self, self.db.url)
        #
        self.db.session = sessionmaker(bind=self.db.engine)()
        self.db.metadata = sqlalchemy.MetaData()
        #
        module_name = self.descriptor.name
        #
        self.db.tbl.user = sqlalchemy.Table(
            f"{module_name}__user", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_provider = sqlalchemy.Table(
            f"{module_name}__user_provider", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group = sqlalchemy.Table(
            f"{module_name}__group", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group_provider = sqlalchemy.Table(
            f"{module_name}__group_provider", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_group = sqlalchemy.Table(
            f"{module_name}__user_group", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.scope = sqlalchemy.Table(
            f"{module_name}__scope", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_permission = sqlalchemy.Table(
            f"{module_name}__user_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group_permission = sqlalchemy.Table(
            f"{module_name}__group_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.token = sqlalchemy.Table(
            f"{module_name}__token", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.role = sqlalchemy.Table(
            f"{module_name}__role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.role_permission = sqlalchemy.Table(
            f"{module_name}__role_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_role = sqlalchemy.Table(
            f"{module_name}__user_role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.project_role = sqlalchemy.Table(
            f"{module_name}__project_role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.project_role_permission = sqlalchemy.Table(
            f"{module_name}__project_role_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.project_user_role = sqlalchemy.Table(
            f"{module_name}__project_user_role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        # Init
        self.descriptor.init_rpcs()
        self.descriptor.init_methods()
        self.descriptor.init_inits()
        self.descriptor.init_blueprint(
            url_prefix=self.descriptor.config.get("url_prefix", "/"),
            static_url_prefix=self.descriptor.config.get("static_url_prefix", "/"),
        )
        # Register tool
        self.descriptor.register_tool("auth_core", self)

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister tool
        self.descriptor.unregister_tool("auth_core")
        # De-init
        self.descriptor.deinit_blueprint()
        self.descriptor.deinit_deinits()
        self.descriptor.deinit_rpcs()
        # Dispose DB
        self.db.engine.dispose()

    def wait_for_db(
            self,
            mute_first_failed_connections=1,
            connection_retry_interval=3.0,
            max_failed_connections=60,
            log_errors=True,
    ):
        """ Wait for DB to be operational """
        #
        failed_connections = 0
        #
        while True:
            try:
                connection = self.db.engine.connect()
                connection.close()
                #
                return
            except Exception as exc:  # pylint: disable=W0702,W0718
                if log_errors and \
                        failed_connections >= mute_first_failed_connections:
                    #
                    log.exception(
                        "Failed to create DB connection. Retrying in %s seconds",
                        connection_retry_interval,
                    )
                #
                failed_connections += 1
                #
                if max_failed_connections and failed_connections > max_failed_connections:
                    raise RuntimeError("Failed to connect to DB") from exc
                #
                time.sleep(connection_retry_interval)
