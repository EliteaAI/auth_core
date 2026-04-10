#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0116,W0201

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

""" Method """

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def credential_handlers_init(self):
        self.credential_handlers = {}  # type -> rpc_endpoint
        # Register bearer token handler
        self.context.rpc_manager.call.auth_register_credential_handler(
            "bearer", "auth_handle_bearer_token"
        )
        # Register basic auth handler
        self.context.rpc_manager.call.auth_register_credential_handler(
            "basic", "auth_handle_basic_auth"
        )

    @web.deinit()
    def credential_handlers_deinit(self):
        # Unregister basic token handler
        self.context.rpc_manager.call.auth_unregister_credential_handler(
            "basic"
        )
        # Unregister bearer token handler
        self.context.rpc_manager.call.auth_unregister_credential_handler(
            "bearer"
        )
