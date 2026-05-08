"""
recontk.cli
~~~~~~~~~~~
Typer-based CLI application.

Commands:
  init        Create workspace directory structure
  doctor      Check tool availability
  scan        Run a scan
  resume      Resume an interrupted scan
  reimport    Re-import raw tool output into normalized findings
  report      Generate reports from a workspace
  profiles    List or show scan profiles
  plugins     List loaded plugins

Every command includes the startup banner with the AUTHORIZED USE notice.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from recontk import __version__
from recontk.core.config import load_config
from recontk.core.errors import (
    ConfirmationRequiredError,
    RecontkError,
    ScopeViolationError,
)
from recontk.core.logging import StructuredLogger
from recontk.core.registry import ToolRegistry, get_registry
from recontk.core.runner import Runner
from recontk.core.workspace import Workspace, list_workspaces

app = typer.Typer(
    name="recontk",
    help="Self-hosted security scanning and reconnaissance toolkit",
    add_completion=False,
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------

_BANNER = f"""\
[bold cyan]recontk[/bold cyan] v{__version__}

[bold red]AUTHORIZED USE ONLY[/bold red]
This tool may only be used on:
  • Systems you own
  • CTF / lab environments
  • Bug bounty programs with [bold]explicit written scope[/bold]
  • Systems with [bold]documented written permission[/bold]

[bold yellow]Unauthorized scanning may be illegal.[/bold yellow]
"""


def _print_banner() -> None:
    console.print(_BANNER)


# ---------------------------------------------------------------------------
# Common options
# ---------------------------------------------------------------------------


def _common_options(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show commands without executing"),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP proxy URL"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow RFC1918/loopback targets"),
    confirm: bool = typer.Option(False, "--confirm", help="Confirm large/destructive operations"),
) -> dict[str, Any]:
    """Collect global flags into a dict for easy unpacking."""
    return {
        "verbose": verbose,
        "dry_run": dry_run,
        "proxy": proxy,
        "allow_private": allow_private,
        "confirm": confirm,
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def init(
    workspace_root: Path = typer.Option(
        Path("workspaces"),
        "--workspace-root",
        help="Where to create the workspace root directory",
    ),
) -> None:
    """Initialize workspace directory structure."""
    _print_banner()
    workspace_root = workspace_root.expanduser().resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    console.print(f"✓ Workspace root created: [bold]{workspace_root}[/bold]")


@app.command()
def doctor(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """
    Check tool availability and capability matrix.

    Runs registry detection, prints a table of installed tools, and
    displays the capability resolution matrix.
    """
    _print_banner()
    config = load_config()
    logger = StructuredLogger.create(
        name="recontk.doctor",
        verbose=verbose,
        force_no_color=False,
    )

    registry = get_registry()
    registry.detect(logger=logger, force=True)

    # Tool table
    table_tools = Table(title="Installed Tools")
    table_tools.add_column("Tool", style="cyan")
    table_tools.add_column("Status", style="green")
    table_tools.add_column("Version", style="dim")

    for tool in sorted(registry.available_tools(), key=lambda t: t.name):
        version_str = tool.version or "(unknown)"
        table_tools.add_row(tool.name, "✓", version_str)

    for tool in sorted(registry.missing_tools(), key=lambda t: t.name):
        table_tools.add_row(tool.name, "[red]✗[/red]", "—")

    console.print(table_tools)
    console.print()

    # Capability matrix
    table_cap = Table(title="Capability Matrix")
    table_cap.add_column("Capability", style="cyan")
    table_cap.add_column("Provider", style="green")

    cap_table_data = registry.capability_table()
    for capability, provider in sorted(cap_table_data.items()):
        if provider:
            style = "bold green" if not provider.startswith("native/") else "yellow"
            table_cap.add_row(capability, f"[{style}]{provider}[/{style}]")
        else:
            table_cap.add_row(capability, "[red]unavailable[/red]")

    console.print(table_cap)


@app.command()
def scan(
    profile: str = typer.Option(..., "--profile", "-p", help="Scan profile name"),
    target: str | None = typer.Option(None, "--target", "-t", help="Single target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="File with target list"),
    workspace_name: str | None = typer.Option(None, "--workspace", help="Workspace name (default: UTC timestamp)"),
    config_file: Path | None = typer.Option(None, "--config", "-c", help="Path to config.yml"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    proxy: str | None = typer.Option(None, "--proxy"),
    allow_private: bool = typer.Option(False, "--allow-private"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """
    Run a scan using the specified profile.

    Either --target or --targets must be provided.
    """
    _print_banner()

    # Validate target input
    if not target and not targets_file:
        console.print("[red]Error:[/red] Must provide --target or --targets", style="bold")
        raise typer.Exit(1)

    if target and targets_file:
        console.print("[red]Error:[/red] Cannot use both --target and --targets", style="bold")
        raise typer.Exit(1)

    # Load targets
    target_list: list[str] = []
    if target:
        target_list = [target]
    elif targets_file:
        if not targets_file.exists():
            console.print(f"[red]Error:[/red] Targets file not found: {targets_file}", style="bold")
            raise typer.Exit(1)
        for line in targets_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                target_list.append(line)

    # Confirmation check
    if len(target_list) > 50 and not confirm:
        console.print(
            f"[yellow]Warning:[/yellow] {len(target_list)} targets require --confirm",
            style="bold",
        )
        raise typer.Exit(1)

    # Load config
    config = load_config(config_file)
    if dry_run:
        config.safety.dry_run = True
    if allow_private:
        config.safety.allow_private = True
    if proxy:
        config.proxy.http = proxy
        config.proxy.https = proxy

    # Load profile
    profile_path = _resolve_profile_path(profile)
    if not profile_path.exists():
        console.print(f"[red]Error:[/red] Profile not found: {profile}", style="bold")
        raise typer.Exit(1)

    import yaml

    profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))

    # Execute scan for each target
    import asyncio

    for tgt in target_list:
        console.print(f"\n[bold]Scanning:[/bold] {tgt}")
        try:
            asyncio.run(_run_scan(tgt, profile_data, config, workspace_name, verbose))
        except RecontkError as exc:
            console.print(f"[red]Scan failed:[/red] {exc.message}", style="bold")
            if exc.context:
                console.print(f"  Context: {exc.context}")
            raise typer.Exit(1)


async def _run_scan(
    target: str,
    profile_data: dict[str, Any],
    config: Any,
    workspace_name: str | None,
    verbose: bool,
) -> None:
    """Internal async scan executor."""
    from importlib import import_module

    # Scope validation
    if not config.safety.allow_private:
        if _is_private_target(target):
            raise ScopeViolationError(target, "RFC1918/loopback range requires --allow-private")

    # Create workspace
    ws = Workspace.create(
        workspace_root=config.workspace_root,
        target=target,
        profile=profile_data["name"],
        name=workspace_name,
    )
    ws.set_status("running")

    logger = StructuredLogger.create(
        name="recontk.scan",
        jsonl_path=ws.run_jsonl(),
        verbose=verbose,
    )

    logger.event(
        "scan_started",
        target=target,
        profile=profile_data["name"],
        workspace=str(ws.path),
    )

    # Registry + runner
    registry = get_registry()
    registry.detect(logger=logger)
    ws.update_tool_versions(registry.versions())

    runner = Runner(registry, ws, config, logger)

    # Execute modules
    modules = profile_data.get("modules", [])
    for module_name in modules:
        logger.info(f"Executing module: {module_name}", module=module_name)
        ws.record_stage_start(module_name)
        try:
            mod = import_module(f"recontk.modules.{module_name}")
            module_config = profile_data.get("module_config", {}).get(module_name, {})
            await mod.run(target, runner, logger, **module_config)
            ws.record_stage_end(module_name, success=True)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Module failed: {module_name}", error=str(exc))
            ws.record_stage_end(module_name, success=False, error=str(exc))

    ws.set_status("completed")
    logger.event("scan_finished", workspace=str(ws.path))
    console.print(f"\n[bold green]✓ Scan complete:[/bold green] {ws.path}")


def _is_private_target(target: str) -> bool:
    """Return True if target is RFC1918 or loopback."""
    import ipaddress
    import re

    # Strip port if present
    host = re.sub(r":\d+$", "", target)
    # Strip scheme if present
    host = re.sub(r"^https?://", "", host)

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        # Not an IP; assume hostname is public
        return False


def _resolve_profile_path(name: str) -> Path:
    """Resolve a profile name to its YAML file path."""
    # Check built-in profiles
    builtin = Path(__file__).parent / "profiles" / f"{name}.yml"
    if builtin.exists():
        return builtin
    # Check CWD
    cwd_profile = Path.cwd() / f"{name}.yml"
    if cwd_profile.exists():
        return cwd_profile
    return builtin  # return the path even if it doesn't exist (caller checks)


@app.command()
def resume(
    workspace_path: Path = typer.Argument(..., help="Path to workspace directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Resume an interrupted scan from its workspace."""
    _print_banner()
    console.print(f"[yellow]resume not yet implemented[/yellow]")
    console.print(f"Workspace: {workspace_path}")
    # TODO Phase 6: implement resume logic
    raise typer.Exit(1)


@app.command()
def reimport(
    workspace_path: Path = typer.Argument(..., help="Path to workspace directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Re-import raw tool output into normalized findings."""
    _print_banner()
    console.print(f"[yellow]reimport not yet implemented[/yellow]")
    console.print(f"Workspace: {workspace_path}")
    # TODO Phase 6: implement re-import logic
    raise typer.Exit(1)


@app.command()
def report(
    workspace_path: Path = typer.Argument(..., help="Path to workspace directory"),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json|md|html|csv"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a report from a workspace."""
    _print_banner()
    console.print(f"[yellow]report not yet implemented[/yellow]")
    console.print(f"Workspace: {workspace_path}, format: {format}")
    # TODO Phase 6: implement reporting
    raise typer.Exit(1)


@app.command()
def profiles(
    action: str = typer.Argument("list", help="Action: list | show <name>"),
    name: str | None = typer.Argument(None, help="Profile name (for 'show' action)"),
) -> None:
    """List or show scan profiles."""
    _print_banner()

    profiles_dir = Path(__file__).parent / "profiles"
    profile_files = list(profiles_dir.glob("*.yml"))

    if action == "list":
        table = Table(title="Available Profiles")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="dim")
        import yaml

        for pf in sorted(profile_files):
            data = yaml.safe_load(pf.read_text())
            table.add_row(data.get("name", pf.stem), data.get("description", ""))
        console.print(table)

    elif action == "show":
        if not name:
            console.print("[red]Error:[/red] Profile name required for 'show'", style="bold")
            raise typer.Exit(1)
        profile_path = _resolve_profile_path(name)
        if not profile_path.exists():
            console.print(f"[red]Error:[/red] Profile not found: {name}", style="bold")
            raise typer.Exit(1)
        console.print(f"[bold]Profile:[/bold] {name}")
        console.print(profile_path.read_text())
    else:
        console.print(f"[red]Error:[/red] Unknown action: {action}", style="bold")
        raise typer.Exit(1)


@app.command()
def plugins_cmd(
    action: str = typer.Argument("list", help="Action: list"),
) -> None:
    """List loaded plugins."""
    _print_banner()
    from recontk.plugins import load_plugins

    logger = StructuredLogger.create(name="recontk.plugins", verbose=False)
    registry = get_registry()
    registry._detected = True  # bypass detection for this command
    loaded = load_plugins(registry, logger)

    if not loaded:
        console.print("[dim]No plugins loaded.[/dim]")
    else:
        console.print("[bold]Loaded plugins:[/bold]")
        for plugin_name in loaded:
            console.print(f"  • {plugin_name}")


# Register the command under "plugins" (avoid shadowing the module)
app.command(name="plugins")(plugins_cmd)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
