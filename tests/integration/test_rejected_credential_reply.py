"""A rejected credential gets a 401 from ForwardAuth, not a redirect a client follows with the same credential."""
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures.helpers import install_pylon_stubs, load_module_from_path  # noqa: E402

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
DENIED_URL = "https://host/access_denied"
TRAEFIK_HEADERS = {
    "X-Forwarded-Method": "GET",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "host",
    "X-Forwarded-Uri": "/api/v2/elitea_core/skill/prompt_lib/6/89",
    "X-Forwarded-For": "10.0.0.1",
}


class Response:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status
        self.headers = {}


@pytest.fixture(scope="module")
def modules():
    install_pylon_stubs()
    tools = sys.modules["pylon.core.tools"]
    for name in ("method", "route"):  # decorators the modules apply at import
        if not hasattr(tools.web, name):
            setattr(tools.web, name, lambda *a, **k: (lambda f: f))
    sys.modules.setdefault("flask", types.ModuleType("flask"))
    return types.SimpleNamespace(
        replies=load_module_from_path(PLUGIN_ROOT / "methods" / "replies.py", "auth_core_replies_rejected"),
        route=load_module_from_path(PLUGIN_ROOT / "routes" / "auth.py", "auth_core_route_rejected"),
    )


def reject(_source, _data):
    raise ValueError("bad token")


class FakeCore:
    """The module instance: the real /auth route and replies, with fake handlers and mappers."""

    def __init__(self, modules, public_rules=()):
        self.descriptor = types.SimpleNamespace(config={
            "auth_denied_url": DENIED_URL,
            "other_auth_headers": {"X-Api-Key": "bearer"},
        })
        self.credential_handlers = {
            "bearer": lambda source, data: ("token", "1", "-") if data == "good" else reject(source, data),
        }
        self.success_mappers = {"api": lambda *args: (True, {"X-Auth-Type": args[1]})}
        self.public_rules = list(public_rules)
        self.auth = modules.route.Route.auth.__get__(self)
        for name in ("access_denied_reply", "credential_rejected_reply", "access_success_reply"):
            setattr(self, name, getattr(modules.replies.Method, name).__get__(self))

    @staticmethod
    def public_rule_matches(rule, source):
        return source["uri"].startswith(rule)

    @staticmethod
    def drop_userless_done(ctx):
        return ctx

    @staticmethod
    def get_auth_context():
        return {"done": False}

    def set_auth_context(self, ctx):
        pass

    @staticmethod
    def make_source_url(source):
        return source["uri"]

    @staticmethod
    def sign_target_url(url):
        return url

    @staticmethod
    def access_needed_redirect(target):
        return ("login-redirect", target)


def call_auth(modules, monkeypatch, headers, public_rules=()):
    flask = sys.modules["flask"]
    request = types.SimpleNamespace(headers={**TRAEFIK_HEADERS, **headers}, args={"target": "api"})
    monkeypatch.setattr(flask, "request", request, raising=False)
    monkeypatch.setattr(flask, "redirect", lambda url: ("redirect", url), raising=False)
    monkeypatch.setattr(flask, "make_response", Response, raising=False)
    return FakeCore(modules, public_rules).auth()


@pytest.mark.parametrize("headers", [
    pytest.param({"Authorization": "Bearer invalid.token"}, id="bad-bearer-token"),
    pytest.param({"Authorization": "Bearer"}, id="header-without-credential"),
    pytest.param({"Authorization": "Digest abc"}, id="unknown-credential-type"),
    pytest.param({"X-Api-Key": "invalid.token"}, id="bad-other-auth-header"),
])
def test_a_rejected_credential_is_a_401_not_a_redirect(modules, monkeypatch, headers):
    reply = call_auth(modules, monkeypatch, headers)

    assert isinstance(reply, Response)
    assert reply.status_code == 401
    assert reply.data == {"ok": False, "error": "unauthorized"}
    assert reply.headers["WWW-Authenticate"] == "Bearer"


def test_a_rejected_credential_on_a_public_route_still_passes(modules, monkeypatch):
    reply = call_auth(modules, monkeypatch, {"Authorization": "Bearer invalid.token"}, public_rules=["/api/"])

    assert reply.status_code == 200
    assert reply.headers["X-Auth-Type"] == "public"


def test_a_valid_credential_passes(modules, monkeypatch):
    reply = call_auth(modules, monkeypatch, {"Authorization": "Bearer good"})

    assert reply.status_code == 200
    assert reply.headers["X-Auth-Type"] == "token"


def test_a_request_without_credentials_still_redirects_to_login(modules, monkeypatch):
    reply = call_auth(modules, monkeypatch, {})

    assert reply[0] == "login-redirect"


def test_the_rpc_reply_for_a_rejected_credential_is_a_401_response_not_a_redirect(modules):
    """auth_idp_rpc's auth_authorize returns this to the pylon_main auth proxy, which acts on it."""
    reply = FakeCore(modules).credential_rejected_reply({"uri": "/api/v2/x", "target": "rpc"}, to_json=True)

    assert reply == {
        "auth_ok": False,
        "reply": "access_denied",
        "action": "make_response",
        "data": {"ok": False, "error": "unauthorized"},
        "status_code": 401,
    }


def test_the_rpc_reply_on_a_public_route_still_passes(modules):
    core = FakeCore(modules, public_rules=["/api/"])
    core.success_mappers["rpc"] = core.success_mappers["api"]

    reply = core.credential_rejected_reply({"uri": "/api/v2/x", "target": "rpc"}, to_json=True)

    assert reply["auth_ok"] is True
    assert reply["headers"]["X-Auth-Type"] == "public"
