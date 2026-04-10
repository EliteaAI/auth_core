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
from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401

from ..tools import rpc_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_get_referenced_auth_context", "get_referenced_auth_context")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_referenced_auth_context(self, auth_reference):
        request = Holder()
        request.cookies = {
            self.context.app.session_cookie_name: auth_reference
        }
        #
        with self.context.app.app_context():
            session = self.context.app.session_interface.open_session(
                self.context.app, request,
            )
        #
        return self.get_auth_context(session)

    @web.rpc("auth_set_referenced_auth_context", "set_referenced_auth_context")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def set_referenced_auth_context(self, auth_reference, auth_context):
        request = Holder()
        request.cookies = {
            self.context.app.session_cookie_name: auth_reference
        }
        #
        response = Holder()
        response.set_cookie = lambda *args, **kvargs: None
        #
        with self.context.app.app_context():
            session = self.context.app.session_interface.open_session(
                self.context.app, request,
            )
            #
            self.set_auth_context(auth_context, session)
            #
            self.context.app.session_interface.save_session(
                self.context.app, session, response,
            )

    @web.rpc("auth_get_session_cookie_name", "get_session_cookie_name")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_session_cookie_name(self):
        return self.context.app.session_cookie_name
