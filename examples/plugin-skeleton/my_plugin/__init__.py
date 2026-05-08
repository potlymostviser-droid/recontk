
```python title="examples/plugin-skeleton/my_plugin/__init__.py"
"""
my_plugin — example recontk plugin.

Register this plugin by adding to your pyproject.toml:

  [project.entry-points."recontk.plugins"]
  my_plugin = "my_plugin:register"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recontk.core.registry import ToolRegistry


def register(registry: "ToolRegistry") -> None:
    """
    Called by recontk.plugins.load_plugins() at startup.

    Register any tool wrappers or native backends this plugin provides.
    """
    # Phase 3+ will expose registry.register_wrapper().
    # For now, log that the plugin loaded successfully.
    print(f"[my_plugin] registered (registry id={id(registry)})")
