"""
recontk.tools.sslyze
~~~~~~~~~~~~~~~~~~~~~
SSLyze wrapper.

Capability  : tls.inspect
Output flag : --json_out <path>   (per sslyze --help)
Finding types:
  "tls-issue"  value = issue key  metadata = {cipher_suite, protocol, detail}
  "tls-info"   value = info key   metadata = {detail}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recontk.models import Finding
from recontk.tools.base import ToolWrapper


class SSLyzeWrapper(ToolWrapper):
    TOOL_KEY = "sslyze"
    CAPABILITY = "tls.inspect"

    def build_cmd(self, target: str, raw_output_path: Path) -> list[str]:
        return [
            self._binary,
            "--json_out", str(raw_output_path),  # (per sslyze --help)
            target,
            *self._extra_args,
        ]

    def parse_output(self, raw_output_path: Path, target: str) -> list[Any]:
        """
        SSLyze JSON output schema (per sslyze --help / documentation):
        {
          "server_scan_results": [
            {
              "server_location": {"hostname": "...", "port": 443},
              "scan_result": {
                "certificate_info": {
                  "result": {
                    "certificate_deployments": [...]
                  }
                },
                "ssl_2_0_cipher_suites": {"result": {"accepted_cipher_suites": [...]}},
                "ssl_3_0_cipher_suites": {"result": {"accepted_cipher_suites": [...]}},
                "tls_1_0_cipher_suites": {"result": {"accepted_cipher_suites": [...]}},
                "tls_1_1_cipher_suites": {"result": {"accepted_cipher_suites": [...]}},
                "tls_1_2_cipher_suites": {"result": {"accepted_cipher_suites": [...]}},
                "tls_1_3_cipher_suites": {"result": {"accepted_cipher_suites": [...]}}
              }
            }
          ]
        }
        We surface deprecated protocol support as tls-issue findings.
        """
        findings: list[Finding] = []
        text = raw_output_path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"sslyze JSON parse error: {exc}") from exc

        for server_result in data.get("server_scan_results", []):
            scan = server_result.get("scan_result", {})
            location = server_result.get("server_location", {})
            hostname = location.get("hostname", target)
            port = location.get("port", 443)

            # Flag deprecated protocols that have accepted cipher suites
            deprecated_protocols = {
                "ssl_2_0_cipher_suites": "SSLv2",
                "ssl_3_0_cipher_suites": "SSLv3",
                "tls_1_0_cipher_suites": "TLSv1.0",
                "tls_1_1_cipher_suites": "TLSv1.1",
            }
            for key, proto_name in deprecated_protocols.items():
                proto_result = scan.get(key, {})
                if proto_result is None:
                    continue
                inner = proto_result.get("result") or {}
                accepted = inner.get("accepted_cipher_suites", [])
                if accepted:
                    findings.append(
                        Finding(
                            tool=self.TOOL_KEY,
                            type="tls-issue",
                            target=target,
                            value=f"deprecated-protocol-{proto_name}",
                            severity=None,  # sslyze does not provide severity
                            metadata={
                                "protocol": proto_name,
                                "hostname": hostname,
                                "port": port,
                                "accepted_cipher_count": len(accepted),
                            },
                        )
                    )

            # Certificate info summary
            cert_info = scan.get("certificate_info", {})
            if cert_info and cert_info.get("result"):
                findings.append(
                    Finding(
                        tool=self.TOOL_KEY,
                        type="tls-info",
                        target=target,
                        value="certificate_info",
                        severity=None,
                        metadata={
                            "hostname": hostname,
                            "port": port,
                            "deployments": len(
                                cert_info["result"].get("certificate_deployments", [])
                            ),
                        },
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Unit-test stub
# ---------------------------------------------------------------------------

_SAMPLE_JSON = """\
{
  "server_scan_results": [
    {
      "server_location": {"hostname": "example.com", "port": 443},
      "scan_result": {
        "ssl_2_0_cipher_suites": {"result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "SSL_CK_RC4_128_WITH_MD5"}}]}},
        "ssl_3_0_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "tls_1_0_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "tls_1_1_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "tls_1_2_cipher_suites": {"result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_RSA_WITH_AES_256_CBC_SHA"}}]}},
        "tls_1_3_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "certificate_info": {"result": {"certificate_deployments": [{"received_certificate_chain": []}]}}
      }
    }
  ]
}
"""


def _test_parse_json(tmp_path: Path) -> None:
    out_file = tmp_path / "sslyze.json"
    out_file.write_text(_SAMPLE_JSON)

    from recontk.core.logging import get_null_logger
    from recontk.core.workspace import Workspace

    ws = Workspace.create(tmp_path / "ws", "example.com:443", "test")
    wrapper = SSLyzeWrapper(
        binary="/usr/bin/sslyze",
        workspace=ws,
        logger=get_null_logger(),
    )
    findings = wrapper.parse_output(out_file, "example.com:443")
    issues = [f for f in findings if f.type == "tls-issue"]
    infos = [f for f in findings if f.type == "tls-info"]
    assert len(issues) == 1
    assert issues[0].value == "deprecated-protocol-SSLv2"
    assert len(infos) == 1
    assert infos[0].value == "certificate_info"
    print("sslyze._test_parse_json PASSED")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        _test_parse_json(Path(td))
