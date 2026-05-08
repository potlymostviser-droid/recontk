
# Save as tests/test_integration_phase5.py (outside recontk/ package)

import asyncio
import tempfile
from pathlib import Path

from recontk.cli import _run_scan
from recontk.core.config import load_config


async def test_scan_end_to_end():
    """
    End-to-end test: run a minimal scan profile against example.com.
    Requires network access.
    """
    with tempfile.TemporaryDirectory() as td:
        workspace_root = Path(td) / "workspaces"
        workspace_root.mkdir()

        # Minimal profile
        profile_data = {
            "name": "test-minimal",
            "modules": ["passiverecon"],
            "rate_limit": {"requests_per_second": 5.0, "burst": 10},
            "concurrency": {"max_workers": 5},
        }

        config = load_config()
        config.workspace_root = workspace_root

        await _run_scan(
            target="example.com",
            profile_data=profile_data,
            config=config,
            workspace_name="test-run",
            verbose=True,
        )

        # Verify workspace was created
        workspaces = list(workspace_root.rglob("manifest.json"))
        assert len(workspaces) == 1, f"Expected 1 workspace, found {len(workspaces)}"

        ws_path = workspaces[0].parent
        manifest_path = ws_path / "manifest.json"
        assert manifest_path.exists()

        import json

        manifest = json.loads(manifest_path.read_text())
        assert manifest["status"] == "completed"
        assert manifest["target"] == "example.com"
        assert manifest["profile"] == "test-minimal"

        # Verify passiverecon stage completed
        stages = {s["name"]: s for s in manifest["stages"]}
        assert "passiverecon" in stages
        assert stages["passiverecon"]["status"] == "completed"

        print("✓ End-to-end integration test PASSED")


if __name__ == "__main__":
    asyncio.run(test_scan_end_to_end())
