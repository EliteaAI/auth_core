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

    @web.rpc("auth_register_success_mapper", "register_success_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def register_success_mapper(self, target, rpc_endpoint):
        if target in self.success_mappers:
            raise ValueError(f"Target is already registered: {target}")
        #
        self.success_mappers[target] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @web.rpc("auth_unregister_success_mapper", "unregister_success_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def unregister_success_mapper(self, target):
        if target not in self.success_mappers:
            raise ValueError(f"Target is not registered: {target}")
        #
        self.success_mappers.pop(target)

    @web.rpc("auth_noop_success_mapper", "noop_success_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def noop_success_mapper(self, source, auth_type, auth_id, auth_reference):
        _ = source, auth_type, auth_id, auth_reference
        #
        return True, {}

    @web.rpc("auth_rpc_success_mapper", "rpc_success_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def rpc_success_mapper(self, source, auth_type, auth_id, auth_reference):
        _ = source
        #
        headers = {}
        #
        headers["X-Auth-Type"] = str(auth_type)
        headers["X-Auth-ID"] = str(auth_id)
        headers["X-Auth-Reference"] = str(auth_reference)
        #
        return True, headers
