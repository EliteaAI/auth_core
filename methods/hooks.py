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

import traceback

import flask  # pylint: disable=E0401
import werkzeug.exceptions  # pylint: disable=E0401

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def hooks_init(self):
        if self.descriptor.config.get("register_error_handler", True):
            self.context.app.errorhandler(Exception)(self.error_handler)
        #
        if "auth" in self.context.module_manager.modules:
            return
        #
        self.context.app.before_request(self.before_request_hook)
        self.context.app.after_request(self.after_request_hook)

    @web.method()
    def error_handler(self, error):
        if isinstance(error, werkzeug.exceptions.NotFound):
            return "Not Found", 404
        #
        if self.descriptor.config.get("traceback_error_handler", True):
            try:
                error = "".join(traceback.format_exception(error))
            except:  # pylint: disable=W0702
                pass
        #
        log.error("Error: %s", error)
        #
        return self.access_denied_reply(), 400

    @web.method()
    def before_request_hook(self):
        if self.descriptor.config.get("force_https_redirect", False) and \
                flask.request.host not in self.descriptor.config.get(
                    "https_redirect_excludes", []
                ):
            if flask.request.scheme == "http":
                log.info("HTTP -> HTTPS redirect for host: %s", flask.request.host)
                return flask.redirect(flask.request.url.replace("http://", "https://", 1))
        #
        return None

    @web.method()
    def after_request_hook(self, response):
        additional_headers = self.descriptor.config.get(
            "additional_headers", {}
        )
        for key, value in additional_headers.items():
            response.headers[key] = value
        #
        if self.descriptor.config.get('ALLOW_CORS') and \
                flask.request.headers.get('X-Forwarded-Uri', '').startswith('/api/') and \
                flask.request.headers.get('X-Forwarded-Method') == 'OPTIONS':
            response = flask.make_response()
            response.headers.add('Access-Control-Allow-Headers', '*')
            response.headers.add('Access-Control-Allow-Methods', '*')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Allow-Origin', '*')
            #
            log.debug(f'after cors_after_request\n\tresponse: {response}\nh: {response.headers}')
        #
        additional_default_headers = self.descriptor.config.get(
            "additional_default_headers", {}
        )
        for key, value in additional_default_headers.items():
            if key not in response.headers:
                response.headers[key] = value
        #
        return response
