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

import urllib

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
    def access_needed_redirect(self, target_token, to_json=False):  # pylint: disable=R0911
        """ Client: auth redirect """
        target_provider = self.descriptor.config.get("auth_provider", None)
        if target_provider not in self.auth_providers:
            return self.access_denied_reply(to_json=to_json)
        target_info = self.auth_providers[target_provider]
        #
        if target_info["login_route"] is not None:
            try:
                if to_json:
                    return {
                        "auth_ok": False,
                        "reply": "access_needed",
                        "action": "redirect",
                        "target": flask.url_for(
                            target_info["login_route"],
                            target_to=target_token,
                            _external=True
                        ),
                    }
                #
                return flask.redirect(
                    flask.url_for(
                        target_info["login_route"],
                        target_to=target_token,
                        _external=True
                    )
                )
            except:  # pylint: disable=W0702
                log.exception("Failed to make login route URL")
                return self.access_denied_reply(to_json=to_json)
        #
        if target_info["login_url"] is not None:
            try:
                url_params = urllib.parse.urlencode({"target_to": target_token})
                #
                if to_json:
                    return {
                        "auth_ok": False,
                        "reply": "access_needed",
                        "action": "redirect",
                        "target": f'{target_info["login_url"]}?{url_params}',
                    }
                return flask.redirect(
                    f'{target_info["login_url"]}?{url_params}'
                )
            except:  # pylint: disable=W0702
                return self.access_denied_reply(to_json=to_json)
        #
        return self.access_denied_reply(to_json=to_json)

    @web.method()
    def access_success_redirect(self, target_token):
        """ Client: auth OK redirect """
        auth_ctx = self.get_auth_context()
        #
        for processor_endpoint in self.auth_processors:
            processor_rpc = getattr(
                self.context.rpc_manager.call, processor_endpoint
            )
            #
            try:
                auth_ctx = processor_rpc(auth_ctx)
            except:  # pylint: disable=W0702
                log.exception("Processor failed")
                return self.access_denied_reply()
        #
        flask.session.regenerate()
        self.set_auth_context(auth_ctx)
        #
        try:
            target_url = self.verify_target_url(target_token)
        except:  # pylint: disable=W0702
            target_url = self.descriptor.config.get("default_login_url", "/")
        #
        return flask.redirect(target_url)

    @web.method()
    def logout_needed_redirect(self, target_token):
        """ Client: logout redirect """
        auth_ctx = self.get_auth_context()
        #
        target_provider = auth_ctx.get("provider", None)
        if target_provider is None or target_provider not in self.auth_providers:
            target_provider = self.descriptor.config.get("auth_provider", None)
        #
        if target_provider not in self.auth_providers:
            return self.access_denied_reply()
        target_info = self.auth_providers[target_provider]
        #
        if target_info["logout_route"] is not None:
            try:
                return flask.redirect(
                    flask.url_for(
                        target_info["logout_route"],
                        target_to=target_token,
                    )
                )
            except:  # pylint: disable=W0702
                return self.access_denied_reply()
        #
        if target_info["logout_url"] is not None:
            try:
                url_params = urllib.parse.urlencode({"target_to": target_token})
                return flask.redirect(
                    f'{target_info["logout_url"]}?{url_params}'
                )
            except:  # pylint: disable=W0702
                return self.access_denied_reply()
        #
        return self.access_denied_reply()

    @web.method()
    def logout_success_redirect(self, target_token):
        """ Client: logout OK redirect """
        flask.session.destroy()
        flask.session.regenerate()
        self.set_auth_context({})
        try:
            target_url = self.verify_target_url(target_token)
        except:  # pylint: disable=W0702
            target_url = self.descriptor.config.get("default_logout_url", "/")
        #
        return flask.redirect(target_url)
