"""Single source of truth for the pasu application version.

Resolution order
----------------
1. ``pyproject.toml`` in the project root (always current in development).
2. Installed package metadata via ``importlib.metadata`` (deployed / packaged installs
   where ``pyproject.toml`` is not present on disk).
3. The string ``"dev"`` as a last-resort fallback.

``pyproject.toml`` is preferred because editable installs (``pip install -e .``) record
the version in dist-info only at install time.  Any subsequent bump to ``pyproject.toml``
would not be reflected by ``importlib.metadata`` until the package is re-installed, making
the displayed version stale.  Reading the file directly avoids that gap entirely.
"""
from __future__ import annotations

import importlib.metadata
import pathlib
import tomllib


def _version_from_pyproject() -> str | None:
    """Return the version string from pyproject.toml, or None if unavailable."""
    # app/version.py lives one directory below the project root.
    pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    try:
        with open(pyproject, "rb") as fh:
            data = tomllib.load(fh)
        return data["project"]["version"]
    except Exception:
        return None


def get_version() -> str:
    """Return the current pasu version string.

    Tries ``pyproject.toml`` first, then installed package metadata, then
    falls back to ``"dev"``.
    """
    v = _version_from_pyproject()
    if v:
        return v
    try:
        return importlib.metadata.version("pasu")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


__version__: str = get_version()
