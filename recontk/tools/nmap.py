"""
recontk.tools.nmap
~~~~~~~~~~~~~~~~~~
Nmap wrapper.  Outputs XML (-oX) which is parsed with stdlib xml.etree.

Capability : port.scan, service.detect
Output     : -oX <path>   (per nmap --help)
Finding types produced:
  "open-port"      value = "<port>/<proto>"  metadata = {service, version, state}
  "os-guess"       value = "<os name>"       metadata = {accuracy}
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class NmapWrapper(ToolWrapper):
    TOOL_KEY = "nmap"
    CAPABILITY = "port.scan"

    # Default flags used for every invocation.
    # -sV  : service/version detection       (per nmap --help)
    # -sC  : default scripts                 (per nmap --help)
    # -T4  : aggressive timing               (per nmap --help)
    # --open: only show open ports           (per nmap --help)
    _DEFAULT_FLAGS: list[str] = ["-sV", "-sC", "-T4", "--open"]

    def _output_extension(self) -> str:
        return ".xml"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            *self._DEFAULT_FLAGS,
            "-oX", str(raw_output_path),  # XML output  (per nmap --help)
            target,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        findings: list[Finding] = []
        try:
            tree = ET.parse(str(raw_output_path))
        except ET.ParseError as exc:
            raise ValueError(f"nmap XML parse error: {exc}") from exc

        root = tree.getroot()

        for host in root.findall("host"):
            # Resolve the address used
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address[@addrtype='ipv6']")
            host_addr = addr_el.get("addr", target) if addr_el is not None else target

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None:
                        continue
                    state = state_el.get("state", "")
                    if state != "open":
                        continue

                    portid = port_el.get("portid", "")
                    proto = port_el.get("protocol", "tcp")
                    value = f"{portid}/{proto}"

                    service_el = port_el.find("service")
                    svc_name = ""
                    svc_version = ""
                    if service_el is not None:
                        svc_name = service_el.get("name", "")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                        svc_version = f"{product} {version}".strip()

                    # Scripts (e.g. banner, http-title)
                    scripts: dict[str, str] = {}
                    for script_el in port_el.findall("script"):
                        sid = script_el.get("id", "")
                        sout = script_el.get("output", "")
                        if sid:
                            scripts[sid] = sout

                    findings.append(
                        Finding(
                            tool=self.TOOL_KEY,
                            type="open-port",
                            target=host_addr,
                            value=value,
                            severity=None,
                            metadata={
                                "service": svc_name,
                                "version": svc_version,
                                "state": state,
                                "scripts": scripts,
                            },
                        )
                    )

            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    os_name = osmatch.get("name", "")
                    accuracy = osmatch.get("accuracy", "")
                    if os_name:
                        findings.append(
                            Finding(
                                tool=self.TOOL_KEY,
                                type="os-guess",
                                target=host_addr,
                                value=os_name,
                                severity=None,
                                metadata={"accuracy": accuracy},
                            )
                        )
                        break  # only take the highest-accuracy match

        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed" reason="reset"/>
        <service name="unknown"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
    </os>
  </host>
</nmaprun>
"""


def _test_parse_xml(tmp_path: Path) -> None:
    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(_SAMPLE_XML)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "10.0.0.1", "test")
    wrapper = NmapWrapper(
        binary="/usr/bin/nmap",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(xml_file, "10.0.0.1")

    ports = [f for f in findings if f.type == "open-port"]
    os_guesses = [f for f in findings if f.type == "os-guess"]

    # Only open ports
    assert len(ports) == 2, f"Expected 2 open ports, got {len(ports)}"
    values = {f.value for f in ports}
    assert "22/tcp" in values
    assert "80/tcp" in values
    assert "9999/tcp" not in values

    assert len(os_guesses) == 1
    assert os_guesses[0].value == "Linux 5.x"
    assert os_guesses[0].metadata["accuracy"] == "95"
    print("nmap._test_parse_xml PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_xml(Path(td))
