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

    @web.rpc("auth_register_info_mapper", "register_info_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def register_info_mapper(self, target, rpc_endpoint):
        if target in self.info_mappers:
            raise ValueError(f"Target is already registered: {target}")
        #
        self.info_mappers[target] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @web.rpc("auth_unregister_info_mapper", "unregister_info_mapper")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def unregister_info_mapper(self, target):
        if target not in self.info_mappers:
            raise ValueError(f"Target is not registered: {target}")
        #
        self.info_mappers.pop(target)
