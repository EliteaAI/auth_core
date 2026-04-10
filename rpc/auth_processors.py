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

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_register_auth_processor", "register_auth_processor")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def register_auth_processor(self, rpc_endpoint_name):
        if rpc_endpoint_name in self.auth_processors:
            raise ValueError(f"Processor is already registered: {rpc_endpoint_name}")
        #
        self.auth_processors.append(rpc_endpoint_name)

    @web.rpc("auth_unregister_auth_processor", "unregister_auth_processor")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def unregister_auth_processor(self, rpc_endpoint_name):
        if rpc_endpoint_name not in self.auth_processors:
            raise ValueError(f"Processor is not registered: {rpc_endpoint_name}")
        #
        self.auth_processors.remove(rpc_endpoint_name)
