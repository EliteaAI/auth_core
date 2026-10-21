"""A login refused after its provider wrote the auth context leaves no session behind (#7121)."""
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures.helpers import install_pylon_stubs, load_module_from_path  # noqa: E402

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
DENIED = "denied-reply"


class FakeSession(dict):
    """Flask-Session surface the redirect methods use; records the order of calls."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def destroy(self):
        self.calls.append("destroy")
        self.clear()

    def regenerate(self):
        self.calls.append("regenerate")


@pytest.fixture(scope="module")
def redirects_module():
    install_pylon_stubs()
    web = sys.modules["pylon.core.tools"].web
    for name in ("method", "route"):  # decorators the module applies at import
        if not hasattr(web, name):
            setattr(web, name, lambda *a, **k: (lambda f: f))
    sys.modules.setdefault("flask", types.ModuleType("flask"))
    return load_module_from_path(PLUGIN_ROOT / "methods" / "redirects.py", "auth_core_redirects_denied_login")


class FakeCore:
    """The module instance the Method functions run on, with the real set/get context contract."""

    def __init__(self, module, session, processors, users):
        self._module = module
        self.session = session
        self.auth_processors = processors
        self.users = users  # provider reference -> user id
        self.context = types.SimpleNamespace(rpc_manager=types.SimpleNamespace(call=types.SimpleNamespace()))
        self.descriptor = types.SimpleNamespace(config={"default_login_url": "/home"})
        for index, processor in enumerate(processors):
            setattr(self.context.rpc_manager.call, f"proc{index}", processor)
        self.auth_processors = [f"proc{index}" for index in range(len(processors))]

    def get_auth_context(self):
        s = self.session
        return {
            "done": s.get("auth_done", False), "error": s.get("auth_error", ""),
            "expiration": s.get("auth_expiration"), "provider": s.get("auth_provider"),
            "provider_attr": s.get("auth_provider_attr", {}), "user_id": s.get("auth_user_id"),
        }

    def set_auth_context(self, ctx):
        s = self.session
        s["auth_done"] = ctx.get("done", False)
        s["auth_error"] = ctx.get("error", "")
        s["auth_expiration"] = ctx.get("expiration")
        s["auth_provider"] = ctx.get("provider")
        s["auth_provider_attr"] = ctx.get("provider_attr", {})
        s["auth_user_id"] = ctx.get("user_id")

    def get_user_from_provider(self, ref):
        return {"id": self.users[ref]}

    def verify_target_url(self, token):
        return token

    def access_denied_reply(self):
        return DENIED

    def login_denied_reply(self):
        return self._module.Method.login_denied_reply(self)

    def access_success_redirect(self, token):
        return self._module.Method.access_success_redirect(self, token)


def make(redirects_module, monkeypatch, *, processors, users=None, previous=None):
    session = FakeSession(previous or {})
    flask = sys.modules["flask"]
    monkeypatch.setattr(flask, "session", session, raising=False)
    monkeypatch.setattr(flask, "redirect", lambda url: ("redirect", url), raising=False)
    return FakeCore(redirects_module, session, processors, users or {}), session


def fresh_provider_context(core, user_id=None):
    # what a provider (auth_oidc/auth_form/auth_saml) stores before calling access_success_redirect
    core.set_auth_context({
        "done": True, "error": "", "expiration": None, "provider": "oidc",
        "provider_attr": {"nameid": "nooid"}, "user_id": user_id,
    })


def refuse(_ctx):
    raise RuntimeError("Login denied: no complete IdP subject")


def test_a_refused_first_login_leaves_the_session_unauthenticated(redirects_module, monkeypatch):
    core, session = make(redirects_module, monkeypatch, processors=[refuse])
    fresh_provider_context(core)
    assert core.get_auth_context()["done"] is True  # the state the provider leaves for the processors

    assert core.access_success_redirect("tok") == DENIED

    ctx = core.get_auth_context()
    assert ctx["done"] is False
    assert ctx["user_id"] is None
    assert ctx["provider"] is None
    assert session.calls == ["destroy", "regenerate"]


def test_a_refused_login_over_a_live_session_does_not_keep_the_previous_user(redirects_module, monkeypatch):
    previous = {"auth_done": True, "auth_user_id": 3, "auth_provider": "oidc", "auth_provider_attr": {"nameid": "admin"}}
    core, session = make(redirects_module, monkeypatch, processors=[refuse], previous=previous)
    fresh_provider_context(core)  # the provider replaced the previous user's context

    assert core.access_success_redirect("tok") == DENIED

    assert core.get_auth_context()["done"] is False
    assert core.get_auth_context()["user_id"] is None
    assert "auth_user_id" in session and session["auth_user_id"] is None


def test_a_context_naming_a_foreign_user_is_refused_without_a_session(redirects_module, monkeypatch):
    called = []
    core, session = make(redirects_module, monkeypatch, processors=[lambda ctx: called.append(ctx) or ctx], users={"nooid": 5})
    fresh_provider_context(core, user_id=7)  # user 7 is not the user "nooid" maps to

    assert core.access_success_redirect("tok") == DENIED

    assert called == []  # the processors never saw the foreign user
    assert core.get_auth_context()["done"] is False
    assert session.calls == ["destroy", "regenerate"]


def test_a_later_processor_failing_still_clears_what_the_first_one_did(redirects_module, monkeypatch):
    def first(ctx):
        return {**ctx, "user_id": 9}

    core, session = make(redirects_module, monkeypatch, processors=[first, refuse])
    fresh_provider_context(core)

    assert core.access_success_redirect("tok") == DENIED

    assert core.get_auth_context()["user_id"] is None
    assert core.get_auth_context()["done"] is False


def test_an_accepted_login_keeps_its_context_and_only_regenerates(redirects_module, monkeypatch):
    def accept(ctx):
        return {**ctx, "user_id": 5}

    core, session = make(redirects_module, monkeypatch, processors=[accept], users={"nooid": 5})
    fresh_provider_context(core)

    assert core.access_success_redirect("tok") == ("redirect", "tok")

    ctx = core.get_auth_context()
    assert ctx["done"] is True and ctx["user_id"] == 5
    assert session.calls == ["regenerate"]
