"""ASGI app entry point for OpenEnv multi-mode deployment validators.

This wrapper loads the existing root-level server.py and re-exports its FastAPI
application as `app`. It also exposes `main()` for the `project.scripts` entry.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import uvicorn


_ROOT_SERVER_PATH = Path(__file__).resolve().parents[1] / "root_server.py"
_SPEC = importlib.util.spec_from_file_location("soc_openenv_root_server", _ROOT_SERVER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load root server module from {_ROOT_SERVER_PATH}")

_ROOT_SERVER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_ROOT_SERVER)

app = _ROOT_SERVER.app


def main() -> None:
    """Console script entry point used by `[project.scripts]`."""
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()
