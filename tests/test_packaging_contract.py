from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Modules deliberately absent from the runtime image.
DEV_ONLY = {"conftest"}


def _modules() -> set[str]:
    return {
        path.stem
        for path in ROOT.glob("*.py")
        if path.stem not in DEV_ONLY and not path.stem.startswith("test_")
    }


def test_every_module_ships_in_the_wheel_the_sdist_and_the_image():
    """A new module that is imported but not copied fails only in production."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    wheel = re.search(r"\[tool\.hatch\.build\.targets\.wheel\](.*?)\n\[", pyproject, re.S)
    sdist = re.search(r"\[tool\.hatch\.build\.targets\.sdist\](.*?)\n\[", pyproject, re.S)
    assert wheel and sdist
    copy_lines = "\n".join(
        line for line in dockerfile.splitlines() if line.startswith("COPY ")
    )
    for module in _modules():
        assert f'"{module}.py"' in wheel.group(1), f"{module}.py missing from the wheel"
        assert f'"/{module}.py"' in sdist.group(1), f"{module}.py missing from the sdist"
        assert f"{module}.py" in copy_lines, f"{module}.py missing from the Docker image"


def test_every_module_is_held_to_the_coverage_gate():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    addopts = re.search(r'addopts = "(.*?)"', pyproject, re.S)
    assert addopts
    for module in _modules():
        assert f"--cov={module}" in addopts.group(1), f"{module} escapes the coverage gate"


def test_documented_environment_variables_exist_in_the_template():
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    for variable in ("METIS_JOB_STORE", "METIS_JOB_DB", "THEMIS_REPLICAS"):
        assert variable in template, variable
