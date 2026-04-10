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

""" Method """

import flask  # pylint: disable=E0401

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611
from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.method()
    def get_auth_context(self, session=None):
        """ Get current auth context from session """
        if session is None:
            session = flask.session
        #
        return {
            "done": session.get("auth_done", False),
            "error": session.get("auth_error", ""),
            "expiration": session.get("auth_expiration", None),
            "provider": session.get("auth_provider", None),
            "provider_attr": session.get("auth_provider_attr", {}),
            "user_id": session.get("auth_user_id", None),
        }

    @web.method()
    def set_auth_context(self, auth_context, session=None):
        """ Save current auth context in session """
        if session is None:
            session = flask.session
        #
        session["auth_done"] = auth_context.get("done", False)
        session["auth_error"] = auth_context.get("error", "")
        session["auth_expiration"] = auth_context.get("expiration", None)
        session["auth_provider"] = auth_context.get("provider", None)
        session["auth_provider_attr"] = auth_context.get("provider_attr", {})
        session["auth_user_id"] = auth_context.get("user_id", None)

    @web.method()
    def get_auth_reference(self):
        """ Get auth reference (session cookie value) """
        cookie_name = self.context.app.session_cookie_name
        cookie = flask.request.cookies.get(cookie_name, None)
        #
        if cookie:
            return cookie
        #
        response = Holder()
        response.cookie = {"data": None}
        response.set_cookie = lambda *args, **kvargs: response.cookie.update({"data": kvargs.get("value", None)})  # pylint: disable=C0301
        #
        flask.session.modified = True
        self.context.app.session_interface.save_session(
            self.context.app, flask.session, response,
        )
        #
        flask.session.modified = True
        return response.cookie.get("data", None)
