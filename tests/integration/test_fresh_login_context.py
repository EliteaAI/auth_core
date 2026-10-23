"""access_success_redirect accepts only a context whose user is the one its provider reference maps to."""
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fixtures.helpers import install_pylon_stubs, load_module_from_path  # noqa: E402

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def belongs():
    install_pylon_stubs()
    web = sys.modules["pylon.core.tools"].web
    for name in ("method", "route"):  # decorators the module applies at import; the helper under test is plain
        if not hasattr(web, name):
            setattr(web, name, lambda *a, **k: (lambda f: f))
    sys.modules.setdefault("flask", types.ModuleType("flask"))  # the helper under test never touches flask
    module = load_module_from_path(PLUGIN_ROOT / "methods" / "redirects.py", "auth_core_redirects_under_test")
    return module.context_belongs_to_provider


def lookup(mapping):
    def get_user_from_provider(ref):
        if ref not in mapping:
            raise LookupError(ref)
        return {"id": mapping[ref]}
    return get_user_from_provider


def test_a_first_login_has_no_user_yet(belongs):
    assert belongs({"user_id": None, "provider_attr": {"nameid": "new@example.com"}}, lookup({})) is True


def test_the_mapped_user_is_accepted(belongs):
    assert belongs({"user_id": 7, "provider_attr": {"nameid": "u@example.com"}}, lookup({"u@example.com": 7})) is True


def test_another_users_session_is_refused(belongs):
    assert belongs({"user_id": 7, "provider_attr": {"nameid": "admin"}}, lookup({"admin": 3})) is False


def test_a_user_without_a_mapping_for_this_reference_is_refused(belongs):
    assert belongs({"user_id": 7, "provider_attr": {"nameid": "admin"}}, lookup({})) is False


def test_a_context_without_a_provider_reference_is_refused(belongs):
    assert belongs({"user_id": 7, "provider_attr": {}}, lookup({})) is False
    assert belongs({"user_id": 7}, lookup({})) is False
