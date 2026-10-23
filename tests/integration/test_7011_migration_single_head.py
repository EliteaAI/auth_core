"""R3.4 of EL-7011: the revision chain keeps one head, with 202610191200 on top of 202610160900."""
import ast
import pathlib
import shutil

import pytest

NEW_REVISION = "202610191200"
PARENT_REVISION = "202610160900"


def read_links(folder: pathlib.Path) -> dict:
    """Map each revision to its down_revision values, read without importing the files."""
    links = {}
    for path in folder.glob("*.py"):
        values = {
            target.id: ast.literal_eval(node.value)
            for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id in ("revision", "down_revision")
        }
        if "revision" not in values:
            continue
        down = values.get("down_revision")
        links[values["revision"]] = (down,) if isinstance(down, str) else tuple(down or ())

    return links


def find_heads(links: dict) -> list:
    """Revisions that no other revision names as its parent."""
    parents = {parent for downs in links.values() for parent in downs}

    return sorted(set(links) - parents)


@pytest.fixture(scope="module")
def migrations_dir(plugin_root: pathlib.Path) -> pathlib.Path:
    return plugin_root / "db" / "migrations"


@pytest.mark.integration
def test_el_7011_r3_4_chain_has_one_head(migrations_dir):
    links = read_links(migrations_dir)

    assert len(find_heads(links)) == 1
    assert links[NEW_REVISION] == (PARENT_REVISION,)


@pytest.mark.integration
def test_el_7011_r3_4_helper_names_two_heads_and_skips_files_without_revision(migrations_dir, tmp_path):
    copy = tmp_path / "migrations"
    shutil.copytree(migrations_dir, copy, ignore=shutil.ignore_patterns("__pycache__"))
    (parent,) = find_heads(read_links(copy))
    (copy / "helpers.py").write_text("LOCK_TIMEOUT = '5s'\n")
    for name in ("202611011200", "202611011300"):
        (copy / f"{name}_split.py").write_text(f'revision = "{name}"\ndown_revision = "{parent}"\n')

    assert find_heads(read_links(copy)) == ["202611011200", "202611011300"]
