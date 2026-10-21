"""A login refused after its provider wrote the auth context leaves no session behind (#7121)."""
import contextlib
import itertools
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures.helpers import import_plugin_module, install_pylon_stubs, load_module_from_path  # noqa: E402

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
DENIED = "denied-reply"
PROVIDER_STATE = {
    "auth_oidc": {"state-1": {"nonce": "n"}},
    "auth_provider_attr": {"nameid": "admin", "delegation": {"access_token": "secret-at"}},
}
_sids = itertools.count(1)


class PylonLikeSession(dict):
    """pylon/core/tools/session.py: destroy() regenerates, then clears; regenerate() rotates the sid
    and records the old one as deleted from the store."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sid = f"sid-{next(_sids)}"
        self.deleted = set()
        self.modified = False

    def regenerate(self):
        self.deleted.add(self.sid)
        self.sid = f"sid-{next(_sids)}"

    def destroy(self):
        self.regenerate()
        self.clear()
        self.modified = True


class UnreachableStoreSession(PylonLikeSession):
    def destroy(self):
        raise ConnectionError("session store is down")


@pytest.fixture(scope="module")
def modules():
    install_pylon_stubs()
    tools = sys.modules["pylon.core.tools"]
    for name in ("method", "route"):  # decorators the modules apply at import
        if not hasattr(tools.web, name):
            setattr(tools.web, name, lambda *a, **k: (lambda f: f))
    context = types.ModuleType("pylon.core.tools.context")
    context.Context = type("Context", (), {})
    sys.modules.setdefault("pylon.core.tools.context", context)
    sys.modules.setdefault("flask", types.ModuleType("flask"))
    return types.SimpleNamespace(
        redirects=load_module_from_path(PLUGIN_ROOT / "methods" / "redirects.py", "auth_core_redirects_denied_login"),
        auth_context=load_module_from_path(PLUGIN_ROOT / "methods" / "auth_context.py", "auth_core_context_denied_login"),
        route=load_module_from_path(PLUGIN_ROOT / "routes" / "auth.py", "auth_core_route_denied_login"),
        rpc=import_plugin_module(PLUGIN_ROOT, "rpc.auth_context"),
    )


class FakeCore:
    """The module instance: the real context and redirect methods bound to a fake session."""

    def __init__(self, modules, processors, users):
        self.users = users  # provider reference -> user id
        self.descriptor = types.SimpleNamespace(config={"default_login_url": "/home"})
        self.context = types.SimpleNamespace(
            rpc_manager=types.SimpleNamespace(call=types.SimpleNamespace()),
            app=types.SimpleNamespace(session_cookie_name="sess"),
        )
        self.auth_processors = []
        for index, processor in enumerate(processors):
            setattr(self.context.rpc_manager.call, f"proc{index}", processor)
            self.auth_processors.append(f"proc{index}")
        for name in ("get_auth_context", "set_auth_context", "drop_userless_done"):
            setattr(self, name, getattr(modules.auth_context.Method, name).__get__(self))
        for name in ("login_denied_reply", "access_success_redirect"):
            setattr(self, name, getattr(modules.redirects.Method, name).__get__(self))

    def get_user_from_provider(self, ref):
        return {"id": self.users[ref]}

    def verify_target_url(self, token):
        return token

    def access_denied_reply(self):
        return DENIED


def make(modules, monkeypatch, *, processors, users=None, previous=None, session_cls=PylonLikeSession):
    session = session_cls(previous or {})
    flask = sys.modules["flask"]
    monkeypatch.setattr(flask, "session", session, raising=False)
    monkeypatch.setattr(flask, "redirect", lambda url: ("redirect", url), raising=False)
    return FakeCore(modules, processors, users or {}), session


def provider_wrote_context(core, user_id=None):
    # what a provider (auth_oidc/auth_form/auth_saml) stores before calling access_success_redirect
    core.set_auth_context({
        "done": True, "error": "", "expiration": None, "provider": "oidc",
        "provider_attr": {"nameid": "nooid", "delegation": {"access_token": "secret-at"}}, "user_id": user_id,
    })


def refuse(_ctx):
    raise RuntimeError("Login denied: no complete IdP subject")


def assert_no_session_left(core, session, old_sid):
    ctx = core.get_auth_context()
    assert ctx["done"] is False
    assert ctx["user_id"] is None
    assert ctx["provider"] is None
    assert session.sid != old_sid and old_sid in session.deleted
    assert "auth_oidc" not in session  # the provider's login state
    assert "delegation" not in str(dict(session))  # tokens the provider kept server-side
    assert not session.get("auth_provider_attr")


def test_a_refused_first_login_leaves_no_session(modules, monkeypatch):
    core, session = make(modules, monkeypatch, processors=[refuse], previous=PROVIDER_STATE)
    provider_wrote_context(core)
    old_sid = session.sid
    assert core.get_auth_context()["done"] is True  # the state the provider leaves for the processors

    assert core.access_success_redirect("tok") == DENIED

    assert_no_session_left(core, session, old_sid)


def test_a_processor_stage_refusal_over_a_live_session_ends_it(modules, monkeypatch):
    previous = {**PROVIDER_STATE, "auth_done": True, "auth_user_id": 3, "auth_provider": "oidc"}
    core, session = make(modules, monkeypatch, processors=[refuse], previous=previous)
    provider_wrote_context(core)  # the provider replaced the previous user's context
    old_sid = session.sid

    assert core.access_success_redirect("tok") == DENIED

    assert_no_session_left(core, session, old_sid)


def test_a_context_naming_a_foreign_user_is_refused_before_the_processors(modules, monkeypatch):
    called = []
    core, session = make(modules, monkeypatch, processors=[lambda ctx: called.append(ctx) or ctx],
                         users={"nooid": 5}, previous=PROVIDER_STATE)
    provider_wrote_context(core, user_id=7)  # user 7 is not the user "nooid" maps to
    old_sid = session.sid

    assert core.access_success_redirect("tok") == DENIED

    assert called == []
    assert_no_session_left(core, session, old_sid)


@pytest.mark.parametrize("processors", [
    pytest.param([], id="no-processor-registered"),
    pytest.param([lambda ctx: None], id="processor-returns-nothing"),
    pytest.param([lambda ctx: {**ctx, "user_id": None}], id="processor-names-no-user"),
])
def test_a_login_no_processor_attached_a_user_to_is_refused(modules, monkeypatch, processors):
    core, session = make(modules, monkeypatch, processors=processors, previous=PROVIDER_STATE)
    provider_wrote_context(core)
    old_sid = session.sid

    assert core.access_success_redirect("tok") == DENIED

    assert_no_session_left(core, session, old_sid)


def test_nothing_an_earlier_processor_returned_is_stored_when_a_later_one_refuses(modules, monkeypatch):
    core, session = make(modules, monkeypatch, processors=[lambda ctx: {**ctx, "user_id": 9}, refuse],
                         previous=PROVIDER_STATE)
    provider_wrote_context(core)
    old_sid = session.sid

    assert core.access_success_redirect("tok") == DENIED

    assert_no_session_left(core, session, old_sid)


def test_the_in_memory_context_is_clear_even_when_the_session_store_is_down(modules, monkeypatch):
    core, session = make(modules, monkeypatch, processors=[refuse], session_cls=UnreachableStoreSession)
    provider_wrote_context(core)

    with pytest.raises(ConnectionError):
        core.access_success_redirect("tok")

    assert core.get_auth_context()["done"] is False
    assert core.get_auth_context()["user_id"] is None


def test_an_accepted_login_keeps_its_context_and_rotates_the_sid(modules, monkeypatch):
    core, session = make(modules, monkeypatch, processors=[lambda ctx: {**ctx, "user_id": 5}], users={"nooid": 5})
    provider_wrote_context(core)
    old_sid = session.sid

    assert core.access_success_redirect("tok") == ("redirect", "tok")

    ctx = core.get_auth_context()
    assert ctx["done"] is True and ctx["user_id"] == 5
    assert session.sid != old_sid and old_sid in session.deleted


# Sessions poisoned before this fix ("done" with no user) must read as unauthenticated.

def poisoned():
    return {"auth_done": True, "auth_user_id": None, "auth_expiration": None, "auth_provider": "oidc",
            "auth_provider_attr": {"nameid": "nooid"}}


def healthy():
    return {**poisoned(), "auth_user_id": 5}


def run_forward_auth(modules, monkeypatch, data):
    core, session = make(modules, monkeypatch, processors=[], previous=data)
    core.public_rules = []
    core.sign_target_url = lambda url: url
    core.make_source_url = lambda source: "src"
    core.access_needed_redirect = lambda token: "needs-login"
    core.access_success_reply = lambda source, auth_type, auth_id="-", auth_reference="-": f"ok:{auth_type}:{auth_id}"
    headers = {name: "x" for name in (
        "X-Forwarded-Method", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Uri", "X-Forwarded-For")}
    request = types.SimpleNamespace(headers=headers, args={"target": "t"}, cookies={"sess": "c"})
    monkeypatch.setattr(sys.modules["flask"], "request", request, raising=False)
    return modules.route.Route.auth(core), core


def test_forward_auth_reads_a_userless_done_session_as_unauthenticated(modules, monkeypatch):
    reply, core = run_forward_auth(modules, monkeypatch, poisoned())

    assert reply == "needs-login"
    assert core.get_auth_context()["done"] is False  # the existing "auth needed" path also clears it


def test_forward_auth_still_accepts_a_session_with_a_user(modules, monkeypatch):
    reply, _ = run_forward_auth(modules, monkeypatch, healthy())

    assert reply == "ok:user:5"


def referenced(modules, data):
    session = dict(data)
    core = FakeCore(modules, [], {})
    core.context.app.app_context = contextlib.nullcontext
    core.context.app.session_interface = types.SimpleNamespace(open_session=lambda app, request: session)
    return modules.rpc.RPC.get_referenced_auth_context(core, "cookie-value")


def test_the_referenced_context_of_a_userless_done_session_is_not_done(modules):
    ctx = referenced(modules, poisoned())

    assert ctx["done"] is False
    assert ctx["user_id"] is None


def test_the_referenced_context_of_a_session_with_a_user_is_done(modules):
    ctx = referenced(modules, healthy())

    assert ctx["done"] is True and ctx["user_id"] == 5
