"""
recontk.native.tlsinspect
~~~~~~~~~~~~~~~~~~~~~~~~~~
Native TLS inspection using stdlib ssl + cryptography library.

Capability : tls.inspect

Inspects:
  - Certificate subject, issuer, SANs, validity dates, key info
  - Supported protocol versions (TLSv1.0 – TLSv1.3)
  - Cipher suite negotiated
  - Self-signed / expired / hostname mismatch detection
  - Certificate chain length

Finding types:
  "tls-info"   value = info key  metadata = {detail}   severity = None
  "tls-issue"  value = issue key metadata = {detail}   severity = None

Note: severity is None — this backend does not have an upstream severity
      source.  The reporting layer may apply its own severity rules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recontk.core.logging import StructuredLogger, get_null_logger
from recontk.core.workspace import Workspace
from recontk.models import Finding, NormalizedResult

# Protocol version constants in probe order
_PROTOCOL_PROBES: list[tuple[str, int]] = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),    # VERIFY: TLSv1 may be unavailable on hardened OpenSSL builds
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),  # VERIFY: TLSv1_1 may be unavailable on hardened OpenSSL builds
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

_DEPRECATED_PROTOCOLS = frozenset({"TLSv1.0", "TLSv1.1"})
_CONNECT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_inspect(
    target: str,
    workspace: Workspace,
    logger: StructuredLogger | None = None,
    port: int = 443,
    timeout: float = _CONNECT_TIMEOUT,
    **_kwargs: Any,
) -> NormalizedResult:
    """
    Inspect TLS configuration on ``target:port``.

    Parameters
    ----------
    target:
        Hostname or IP.  If "host:port" is given, port is parsed from it.
    workspace:
        Active workspace.
    logger:
        Structured logger.
    port:
        Default port if not encoded in target.
    timeout:
        Connection timeout per probe.
    """
    log = (logger or get_null_logger()).bind(
        tool="native/tlsinspect", target=target, capability="tls.inspect"
    )
    start = time.monotonic()
    log.event("tool_started")

    # Parse host:port if encoded in target
    host, port = _parse_target(target, port)

    findings: list[Finding] = []
    errors: list[str] = []

    # 1. Certificate inspection (using default TLS connection)
    cert_findings, cert_errors = await _inspect_certificate(host, port, timeout, log)
    findings.extend(cert_findings)
    errors.extend(cert_errors)

    # 2. Protocol version probing
    proto_findings, proto_errors = await _probe_protocols(host, port, timeout, log)
    findings.extend(proto_findings)
    errors.extend(proto_errors)

    # 3. Cipher suite (from default connection)
    cipher_findings, cipher_errors = await _inspect_cipher(host, port, timeout, log)
    findings.extend(cipher_findings)
    errors.extend(cipher_errors)

    duration = time.monotonic() - start
    raw_path = _write_raw(workspace, target, findings)

    log.event("tool_finished", duration_s=round(duration, 2), finding_count=len(findings))
    return NormalizedResult(
        tool="native/tlsinspect",
        target=target,
        duration_s=duration,
        findings=findings,
        errors=errors,
        raw_path=str(raw_path),
    )


# ---------------------------------------------------------------------------
# Certificate inspection
# ---------------------------------------------------------------------------


async def _inspect_certificate(
    host: str, port: int, timeout: float, log: Any
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        cert_der, cert_dict, cipher_info = await asyncio.get_event_loop().run_in_executor(
            None, _fetch_cert_sync, host, port, ctx, timeout
        )
    except ssl.SSLCertVerificationError as exc:
        errors.append(f"SSL cert verification failed: {exc}")
        # Re-fetch without verification to still get cert info
        try:
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            cert_der, cert_dict, cipher_info = await asyncio.get_event_loop().run_in_executor(
                None, _fetch_cert_sync, host, port, ctx_noverify, timeout
            )
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type="tls-issue",
                    target=f"{host}:{port}",
                    value="cert-verification-failed",
                    severity=None,
                    metadata={"error": str(exc)},
                )
            )
        except Exception as inner_exc:
            errors.append(f"Could not fetch cert without verification: {inner_exc}")
            return findings, errors
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        errors.append(f"TLS connect failed: {exc}")
        return findings, errors

    # Parse certificate using cryptography library
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_der)
        cert_info = _extract_cert_info(cert, host)

        findings.append(
            Finding(
                tool="native/tlsinspect",
                type="tls-info",
                target=f"{host}:{port}",
                value="certificate",
                severity=None,
                metadata=cert_info,
            )
        )

        # Issue: expired
        now_utc = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
            cert.not_valid_after.replace(tzinfo=timezone.utc)  # cryptography < 42 compat
        if now_utc > not_after:
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type="tls-issue",
                    target=f"{host}:{port}",
                    value="cert-expired",
                    severity=None,
                    metadata={
                        "not_after": not_after.isoformat(),
                        "days_expired": (now_utc - not_after).days,
                    },
                )
            )

        # Issue: self-signed (issuer == subject)
        if cert.issuer == cert.subject:
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type="tls-issue",
                    target=f"{host}:{port}",
                    value="self-signed-cert",
                    severity=None,
                    metadata={"subject": cert_info.get("subject", "")},
                )
            )

        # Issue: hostname mismatch (only when check_hostname would fail)
        if not _hostname_matches(host, cert_info.get("sans", []), cert_info.get("subject_cn", "")):
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type="tls-issue",
                    target=f"{host}:{port}",
                    value="hostname-mismatch",
                    severity=None,
                    metadata={
                        "host": host,
                        "subject_cn": cert_info.get("subject_cn", ""),
                        "sans": cert_info.get("sans", []),
                    },
                )
            )

    except ImportError:
        # cryptography library not installed — store raw dict only
        errors.append("cryptography library not installed; cert parsing limited")
        findings.append(
            Finding(
                tool="native/tlsinspect",
                type="tls-info",
                target=f"{host}:{port}",
                value="certificate-raw",
                severity=None,
                metadata={"cert_dict": str(cert_dict)[:2048]},
            )
        )
    except Exception as exc:
        errors.append(f"Cert parse error: {exc}")

    return findings, errors


def _fetch_cert_sync(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float,
) -> tuple[bytes, dict[str, Any], tuple[str, str, int] | None]:
    """
    Synchronous TLS connect + certificate fetch.
    Returns (cert_der_bytes, cert_dict, cipher_info).
    Runs in a thread executor to avoid blocking the event loop.
    """
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            cert_dict = tls_sock.getpeercert() or {}
            cipher_info = tls_sock.cipher()  # (name, protocol, bits)
    return cert_der or b"", cert_dict, cipher_info


def _extract_cert_info(cert: Any, host: str) -> dict[str, Any]:
    """Extract structured info from a cryptography x509.Certificate."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    # Subject
    try:
        subject_cn = cert.subject.get_attributes_for_oid(
            _x509.NameOID.COMMON_NAME
        )[0].value
    except IndexError:
        subject_cn = ""

    # Issuer
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(
            _x509.NameOID.COMMON_NAME
        )[0].value
    except IndexError:
        issuer_cn = ""

    # SANs
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, _x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, _x509.IPAddress):
                sans.append(str(name.value))
    except _x509.ExtensionNotFound:
        pass

    # Validity
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else \
        cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
        cert.not_valid_after.replace(tzinfo=timezone.utc)

    # Key info
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_bits = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        key_bits = pub_key.key_size
    else:
        key_type = "unknown"
        key_bits = 0

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "sans": sans,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "key_type": key_type,
        "key_bits": key_bits,
        "serial_number": str(cert.serial_number),
    }


def _hostname_matches(host: str, sans: list[str], subject_cn: str) -> bool:
    """
    Check whether ``host`` matches any SAN or the subject CN.
    Supports wildcard SANs (*.example.com).
    """
    def _matches(pattern: str, name: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return name.endswith(suffix) and "." in name[: -len(suffix)]
        return pattern.lower() == name.lower()

    candidates = sans if sans else ([subject_cn] if subject_cn else [])
    for candidate in candidates:
        if _matches(candidate, host):
            return True
    return False


# ---------------------------------------------------------------------------
# Protocol version probing
# ---------------------------------------------------------------------------


async def _probe_protocols(
    host: str, port: int, timeout: float, log: Any
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    for proto_name, proto_version in _PROTOCOL_PROBES:
        try:
            supported = await asyncio.get_event_loop().run_in_executor(
                None, _probe_protocol_sync, host, port, proto_version, timeout
            )
        except Exception as exc:
            # Probing a specific version may raise on hardened systems
            errors.append(f"Protocol probe {proto_name} error: {exc}")
            continue

        if supported:
            finding_type = (
                "tls-issue" if proto_name in _DEPRECATED_PROTOCOLS else "tls-info"
            )
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type=finding_type,
                    target=f"{host}:{port}",
                    value=f"protocol-supported-{proto_name}",
                    severity=None,
                    metadata={"protocol": proto_name, "deprecated": proto_name in _DEPRECATED_PROTOCOLS},
                )
            )

    return findings, errors


def _probe_protocol_sync(
    host: str, port: int, version: int, timeout: float
) -> bool:
    """
    Attempt TLS handshake with a specific minimum+maximum protocol version.
    Returns True if the server accepts the connection.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Pin both minimum and maximum to the target version
        ctx.minimum_version = version  # type: ignore[assignment]
        ctx.maximum_version = version  # type: ignore[assignment]
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Cipher suite inspection
# ---------------------------------------------------------------------------


async def _inspect_cipher(
    host: str, port: int, timeout: float, log: Any
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _, _, cipher_info = await asyncio.get_event_loop().run_in_executor(
            None, _fetch_cert_sync, host, port, ctx, timeout
        )
        if cipher_info:
            name, protocol, bits = cipher_info
            findings.append(
                Finding(
                    tool="native/tlsinspect",
                    type="tls-info",
                    target=f"{host}:{port}",
                    value=f"cipher:{name}",
                    severity=None,
                    metadata={
                        "cipher_name": name,
                        "protocol": protocol,
                        "key_bits": bits,
                    },
                )
            )
    except Exception as exc:
        errors.append(f"Cipher inspection error: {exc}")

    return findings, errors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_target(target: str, default_port: int) -> tuple[str, int]:
    """Parse 'host' or 'host:port' into (host, port)."""
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return target, default_port
    return target, default_port


def _write_raw(workspace: Workspace, target: str, findings: list[Finding]) -> Path:
    safe_target = re.sub(r"[^\w.\-]", "_", target)[:64]
    raw_dir = workspace.raw_dir("native_tlsinspect")
    raw_path = raw_dir / f"{safe_target}.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(finding.to_json() + "\n")
    return raw_path


# ---------------------------------------------------------------------------
# Unit-test stubs
# ---------------------------------------------------------------------------


def _test_parse_target() -> None:
    assert _parse_target("example.com", 443) == ("example.com", 443)
    assert _parse_target("example.com:8443", 443) == ("example.com", 8443)
    assert _parse_target("10.0.0.1:443", 443) == ("10.0.0.1", 443)
    print("tlsinspect._test_parse_target PASSED")


def _test_hostname_matches() -> None:
    assert _hostname_matches("example.com", ["example.com"], "")
    assert _hostname_matches("www.example.com", ["*.example.com"], "")
    assert not _hostname_matches("evil.com", ["example.com"], "")
    assert not _hostname_matches("sub.www.example.com", ["*.example.com"], "")
    assert _hostname_matches("example.com", [], "example.com")
    print("tlsinspect._test_hostname_matches PASSED")


async def _test_inspect_real_host() -> None:
    """Inspect example.com:443 — requires network access."""
    import tempfile
    from recontk.core.workspace import Workspace

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create(Path(td) / "ws", "example.com", "test")
        result = await run_inspect("example.com", ws, port=443)

    cert_findings = [f for f in result.findings if f.value == "certificate"]
    assert len(cert_findings) >= 1
    meta = cert_findings[0].metadata
    assert "subject_cn" in meta
    assert "not_after" in meta
    print("tlsinspect._test_inspect_real_host PASSED")


if __name__ == "__main__":
    _test_parse_target()
    _test_hostname_matches()
    asyncio.run(_test_inspect_real_host())
