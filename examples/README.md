# recontk plugin skeleton

This directory demonstrates how to write a third-party recontk plugin.

## Structure
my_plugin/
├── init.py # exposes register()
└── tool_wrapper.py # ToolWrapper subclass

text


## Registration (pyproject.toml of your plugin package)

```toml
[project.entry-points."recontk.plugins"]
my_plugin = "my_plugin:register"
Requirements
Implement register(registry: ToolRegistry) -> None
Subclass recontk.tools.base.ToolWrapper
Define TOOL_KEY and CAPABILITY
Return NormalizedResult from run()
Never use shell=True
Never invent severity scores
Authorized use only
This plugin, and recontk itself, may only be used on systems you own,
in CTF/lab environments, in bug bounty programs with explicit written scope,
or on systems with documented written permission. Unauthorized scanning
may be illegal.
