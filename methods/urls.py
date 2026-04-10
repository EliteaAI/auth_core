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

import jwt  # pylint: disable=E0401

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.method()
    def make_source_url(self, source):
        """ Make original URL from source """
        _ = self
        #
        proto = source.get("proto")
        host = source.get("host")
        uri = source.get("uri")
        #
        return f"{proto}://{host}{uri}"

    @web.method()
    def sign_target_url(self, url):
        """ Sign and encode URL in JWT token """
        return jwt.encode(
            {"url": url},
            self.context.app.secret_key,
            algorithm="HS256",
        )

    @web.method()
    def verify_target_url(self, url_token):
        """ Verify and decode URL from JWT token """
        try:
            url_data = jwt.decode(
                url_token, self.context.app.secret_key, algorithms=["HS256"]
            )
        except:
            raise ValueError("Invalid URL token")  # pylint: disable=W0707
        #
        return url_data["url"]

    @web.method()
    def get_relative_url_prefix(self, target_descriptor, target_url_prefix=None):
        """ Get relative URL prefix """
        if target_url_prefix is None:
            target_url_prefix = f"/{target_descriptor.name}"
        #
        core_prefix = self.descriptor.config.get("url_prefix", "/")
        #
        return f'{core_prefix.rstrip("/")}/{target_url_prefix.lstrip("/")}'
