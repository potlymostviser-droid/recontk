"""
recontk.plugins
~~~~~~~~~~~~~~~
Plugin system based on Python entry-points.

Third-party plugins register a callable under the
``recontk.plugins`` entry-point group in their own pyproject.toml:

  [project.entry-points."recontk.plugins"]
  my_plugin = "my_package:register"

The ``register`` callable receives the ToolRegistry instance and must
call registry.register_wrapper() (Phase 3) for each tool it provides.

This module exposes load_plugins() which is called during CLI startup.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recontk.core.registry import ToolRegistry
    from recontk.core.logging import StructuredLogger


def load_plugins(
    registry: "ToolRegistry",
    logger: "StructuredLogger",
) -> list[str]:
    """
    Discover and load all installed recontk plugins.

    Parameters
    ----------
    registry:
        The active ToolRegistry.  Passed to each plugin's register().
    logger:
        Structured logger for load events.

    Returns
    -------
    list[str]
        Names of successfully loaded plugins.
    """
    loaded: list[str] = []

    # importlib.metadata.entry_points() API changed in Python 3.12:
    # group= keyword is the stable interface from 3.9+.
    eps = entry_points(group="recontk.plugins")

    for ep in eps:
        try:
            register_fn = ep.load()
            register_fn(registry)
            loaded.append(ep.name)
            logger.event(
                "plugin_loaded",
                plugin=ep.name,
                module=ep.value,
            )
        except Exception as exc:  # noqa: BLE001
            from recontk.core.errors import PluginError

            logger.error(
                "Plugin failed to load",
                plugin=ep.name,
                error=str(exc),
            )
            # Log but do not abort startup — other plugins may work fine.

    return loaded
