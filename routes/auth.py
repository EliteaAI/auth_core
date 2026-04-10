#!/usr/bin/python3
# coding=utf-8

#   Copyright 2025 EPAM Systems
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

""" Route """

import datetime

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401,W0611


class Route:  # pylint: disable=E1101,R0903
    """ Route """

    @web.route("/auth")
    def auth(self):  # pylint: disable=R0911,R0912
        """ Traefik ForwardAuth endpoint """
        # Check if we got request from Traefik
        traefik_headers = [
            "X-Forwarded-Method",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Uri",
            "X-Forwarded-For",
        ]
        for header in traefik_headers:
            if header not in flask.request.headers:
                # Not a traefik request
                return self.access_denied_reply()
        # Get source request data
        source = {
            "method": flask.request.headers.get("X-Forwarded-Method"),
            "proto": flask.request.headers.get("X-Forwarded-Proto"),
            "host": flask.request.headers.get("X-Forwarded-Host"),
            "uri": flask.request.headers.get("X-Forwarded-Uri"),
            "ip": flask.request.headers.get("X-Forwarded-For"),
            #
            "target": flask.request.args.get("target", None),
            "scope": flask.request.args.get("scope", None),
        }
        # Check auth header
        if "Authorization" in flask.request.headers:
            auth_header = flask.request.headers.get("Authorization")
            if " " not in auth_header:
                # Invalid auth header
                return self.access_denied_reply(source)
            #
            credential_type, credential_data = auth_header.split(" ", 1)
            credential_type = credential_type.lower()
            #
            if credential_type not in self.credential_handlers:
                # No credential handler
                return self.access_denied_reply(source)
            #
            try:
                auth_type, auth_id, auth_reference = \
                    self.credential_handlers[credential_type](
                        source, credential_data
                    )
            except:  # pylint: disable=W0702
                # Bad credential
                return self.access_denied_reply(source)
            #
            return self.access_success_reply(
                source, auth_type, auth_id, auth_reference
            )
        # Check other auth headers
        other_auth_headers = self.descriptor.config.get("other_auth_headers", {})
        for header_name, credential_type in  other_auth_headers.items():
            if header_name in flask.request.headers:
                credential_data = flask.request.headers.get(header_name)
                #
                if credential_type not in self.credential_handlers:
                    # No credential handler
                    return self.access_denied_reply(source)
                #
                try:
                    auth_type, auth_id, auth_reference = \
                        self.credential_handlers[credential_type](
                            source, credential_data
                        )
                except:  # pylint: disable=W0702
                    # Bad credential
                    return self.access_denied_reply(source)
                #
                return self.access_success_reply(
                    source, auth_type, auth_id, auth_reference
                )
        # Browser auth
        auth_ctx = self.get_auth_context()
        if auth_ctx["done"] and \
                (
                        auth_ctx["expiration"] is None or
                        datetime.datetime.now() < auth_ctx["expiration"]
                ):
            # Auth done
            return self.access_success_reply(
                source,
                auth_type="user",
                auth_id=str(auth_ctx["user_id"]) \
                    if auth_ctx["user_id"] is not None else "-",
                auth_reference=flask.request.cookies.get(
                    self.context.app.session_cookie_name, "-"
                ),
            )
        # Check public rules
        for rule in self.public_rules:
            if self.public_rule_matches(rule, source):
                # Public request
                return self.access_success_reply(source, "public")
        # Auth needed or expired
        self.set_auth_context({})
        target_token = self.sign_target_url(self.make_source_url(source))
        return self.access_needed_redirect(target_token)

    @web.route("/login")
    def login(self):
        """ Login endpoint """
        self.set_auth_context({})
        target_token = flask.request.args.get(
            "target_to",
            self.sign_target_url(
                self.descriptor.config.get("default_login_url", "/")
            )
        )
        return self.access_needed_redirect(target_token)

    @web.route("/logout")
    def logout(self):
        """ Logout endpoint """
        target_token = flask.request.args.get(
            "target_to",
            self.sign_target_url(
                self.descriptor.config.get("default_logout_url", "/")
            )
        )
        return self.logout_needed_redirect(target_token)

    @web.route("/info")
    def info(self):
        """ Info endpoint """
        target = flask.request.args.get("target", None)
        scope = flask.request.args.get("scope", None)
        #
        if target not in self.info_mappers:
            return self.access_denied_reply()
        #
        auth_ctx = self.get_auth_context()
        #
        try:
            mimetype, data = self.info_mappers[target](auth_ctx, scope)
        except:  # pylint: disable=W0702
            return self.access_denied_reply()
        #
        response = flask.make_response(data)
        response.mimetype = mimetype
        return response
