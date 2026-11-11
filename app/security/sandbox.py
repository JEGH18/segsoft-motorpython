"""Keeps rule execution inside the analysis sandbox.

The backend sends the path of each file to analyze. When SANDBOX_ROOT is set (it is in the
Docker image), a path whose real location -- after resolving ``..`` and symbolic links -- falls
outside that directory is refused. A cloned repository can contain a symlink such as
``config.yml -> /proc/self/environ``; without this check the engine would read the target and
return its lines as evidence.
"""

import os

from app.executors.errors import ControlledRuleError


def sandbox_root() -> str | None:
    root = os.environ.get("SANDBOX_ROOT", "").strip()
    return os.path.realpath(root) if root else None


def ensure_inside_sandbox(artifact_path: str) -> None:
    root = sandbox_root()
    if root is None:
        return
    real = os.path.realpath(artifact_path)
    try:
        inside = os.path.commonpath([root, real]) == root
    except ValueError:  # different drives on Windows
        inside = False
    if not inside:
        raise ControlledRuleError(
            "PATH_OUTSIDE_SANDBOX",
            "El archivo está fuera del sandbox de análisis (ruta o enlace simbólico no permitido)",
        )
