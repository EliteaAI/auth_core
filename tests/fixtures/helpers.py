"""Helpers for importing auth_core modules outside the Pylon runtime."""
import importlib.util
import pathlib
import sys
import types
from typing import Any

# auth_core/__init__.py imports .module, which pulls in the whole Pylon runtime.
# Tests therefore never import the real package: they register a synthetic one
# whose __path__ points at the plugin directory, so relative imports inside the
# module under test resolve against the real files without __init__ running.
PACKAGE_NAME = "auth_core_under_test"

SUBPACKAGES = ("tools", "db", "rpc")


class _Log:
    """Pylon's log, silenced."""

    @staticmethod
    def info(*a, **k): pass

    @staticmethod
    def warning(*a, **k): pass

    @staticmethod
    def warn(*a, **k): pass

    @staticmethod
    def error(*a, **k): pass

    @staticmethod
    def debug(*a, **k): pass

    @staticmethod
    def trace(*a, **k): pass

    @staticmethod
    def exception(*a, **k): pass

    @staticmethod
    def critical(*a, **k): pass


def install_pylon_stubs() -> None:
    """Register the minimal pylon.core.tools surface auth_core imports."""
    pylon = types.ModuleType("pylon")
    pylon_core = types.ModuleType("pylon.core")
    pylon_core_tools = types.ModuleType("pylon.core.tools")

    pylon_core_tools.log = _Log()
    pylon_core_tools.web = types.SimpleNamespace(rpc=lambda *a, **k: lambda f: f)
    pylon_core_tools.module = types.SimpleNamespace()

    pylon.core = pylon_core
    pylon_core.tools = pylon_core_tools

    sys.modules.setdefault("pylon", pylon)
    sys.modules.setdefault("pylon.core", pylon_core)
    sys.modules.setdefault("pylon.core.tools", pylon_core_tools)


def register_plugin_package(plugin_root: pathlib.Path) -> None:
    """Map PACKAGE_NAME onto the plugin directory without executing __init__."""
    if PACKAGE_NAME in sys.modules:
        return

    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(plugin_root)]
    sys.modules[PACKAGE_NAME] = package

    for name in SUBPACKAGES:
        subpackage = types.ModuleType(f"{PACKAGE_NAME}.{name}")
        subpackage.__path__ = [str(plugin_root / name)]
        sys.modules[f"{PACKAGE_NAME}.{name}"] = subpackage
        setattr(package, name, subpackage)


def import_plugin_module(plugin_root: pathlib.Path, dotted: str) -> Any:
    """Import e.g. "rpc.tokens" from the plugin, relative imports included."""
    install_pylon_stubs()
    register_plugin_package(plugin_root)

    return importlib.import_module(f"{PACKAGE_NAME}.{dotted}")


def load_module_from_path(module_path: pathlib.Path, module_name: str) -> Any:
    """Load a standalone file whose filename is not a valid identifier."""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module
