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


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.method()
    def access_denied_reply(self, source=None, to_json=False):
        """ Traefik/client: bad auth reply/redirect """
        # Check public rules
        if source is not None:
            for rule in self.public_rules:
                if self.public_rule_matches(rule, source):
                    # Public request
                    return self.access_success_reply(source, "public", to_json=to_json)
        #
        if "auth_denied_url" in self.descriptor.config:
            if to_json:
                return {
                    "auth_ok": False,
                    "reply": "access_denied",
                    "action": "redirect",
                    "target": self.descriptor.config.get("auth_denied_url"),
                }
            return flask.redirect(self.descriptor.config.get("auth_denied_url"))
        #
        if to_json:
            return {
                "auth_ok": False,
                "reply": "access_denied",
                "action": "make_response",
                "data": "Access Denied",
                "status_code": 403,
            }
        return flask.make_response("Access Denied", 403)

    @web.method()
    def access_success_reply(  # pylint: disable=R0913,R0917
            self, source,
            auth_type, auth_id="-", auth_reference="-",
            to_json=False,
    ):
        """ Traefik: auth OK reply """
        auth_target = source["target"]
        if auth_target not in self.success_mappers:
            return self.access_denied_reply(to_json=to_json)
        #
        try:
            auth_allow, auth_headers = self.success_mappers[auth_target](
                source, auth_type, auth_id, auth_reference
            )
        except:  # pylint: disable=W0702
            auth_allow = False
        #
        if not auth_allow:
            return self.access_denied_reply(to_json=to_json)
        #
        if to_json:
            response = {
                "auth_ok": True,
                "reply": "access_success",
                "headers": {},
            }
            for key, value in auth_headers.items():
                response["headers"][key] = str(value)
            return response
        #
        response = flask.make_response("OK")
        for key, value in auth_headers.items():
            response.headers[key] = str(value)
        return response
