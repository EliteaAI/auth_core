#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0115,C0116

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

""" RPC """

import base64
import datetime

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_register_credential_handler", "register_credential_handler")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def register_credential_handler(self, credential_type, rpc_endpoint):
        if credential_type in self.credential_handlers:
            raise ValueError(f"Credential type is already registered: {credential_type}")
        #
        self.credential_handlers[credential_type] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @web.rpc("auth_unregister_credential_handler", "unregister_credential_handler")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def unregister_credential_handler(self, credential_type):
        if credential_type not in self.credential_handlers:
            raise ValueError(f"Credential type is not registered: {credential_type}")
        #
        self.credential_handlers.pop(credential_type)

    @web.rpc("auth_handle_bearer_token", "handle_bearer_token")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def handle_bearer_token(self, source, token_data):
        _ = source
        #
        try:
            token = self.decode_token(token_data)
        except:
            raise ValueError("Bad token")  # pylint: disable=W0707
        #
        if token["expires"] is not None and \
                datetime.datetime.now() >= token["expires"]:
            raise ValueError("Token expired")
        #
        return "token", token["id"], "-"

    @web.rpc("auth_handle_basic_auth", "handle_basic_auth")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def handle_basic_auth(self, source, auth_data):
        try:
            token_data, _ = base64.b64decode(auth_data).decode().split(":", 1)
        except:
            raise ValueError("Bad auth data")  # pylint: disable=W0707
        #
        return self.handle_bearer_token(source, token_data)
