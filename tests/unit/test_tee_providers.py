"""Tests for TPM, SEV-SNP, and TDX TEE provider stubs."""

from __future__ import annotations

import ctypes
import struct
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from agent_manifest import SNP_OFFSETS, SNP_REPORT_LEN, parse_snp_report

from cmcp_runtime.tee.sev_snp import SEVSNPProvider
from cmcp_runtime.tee.tdx import TDXProvider, _TdxReportReq
from cmcp_runtime.tee.tpm import TPMProvider

# ── SNP report layout (HW-006) ────────────────────────────────────────────────
# The layout is agent-manifest's; these assert the resolved version still agrees
# with what this provider assumes, which a floor pin does not otherwise guarantee.

def test_snp_struct_size() -> None:
    """An SNP report must be exactly 0x4A0 bytes."""
    assert SNP_REPORT_LEN == 0x4A0


def test_snp_struct_measurement_field_round_trip() -> None:
    """Write a known pattern at the struct-derived measurement offset,
    parse with from_buffer_copy, assert the named field reads it back."""
    buf = bytearray(SNP_REPORT_LEN)
    struct.pack_into("<I", buf, 0, 2)
    pattern = bytes(range(48))
    offset = SNP_OFFSETS["measurement"]
    buf[offset : offset + 48] = pattern
    report = parse_snp_report(bytes(buf))
    assert bytes(report.measurement) == pattern


def test_snp_struct_host_data_field_round_trip() -> None:
    """Write a known pattern at the host_data offset; read back via named field."""
    buf = bytearray(SNP_REPORT_LEN)
    struct.pack_into("<I", buf, 0, 2)
    pattern = bytes(range(32))
    offset = SNP_OFFSETS["host_data"]
    buf[offset : offset + 32] = pattern
    report = parse_snp_report(bytes(buf))
    assert bytes(report.host_data) == pattern


# ── SEVSNPProvider ─────────────────────────────────────────────────────────────

def test_sev_snp_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "win32"), \
         patch.object(Path, "exists", return_value=False):
        assert SEVSNPProvider().detect() is False


def test_sev_snp_detect_returns_false_when_device_missing() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=False):
        assert SEVSNPProvider().detect() is False


def test_sev_snp_detect_returns_true_when_device_present() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=True):
        assert SEVSNPProvider().detect() is True


def test_sev_snp_provider_name() -> None:
    assert SEVSNPProvider().provider_name() == "sev-snp"


def test_sev_snp_get_report_raises_when_tsm_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configfs-TSM failure (no interface / not root) must surface as RuntimeError."""
    from cmcp_runtime.tee import sev_snp as snp_mod

    def boom(_report_data: bytes) -> bytes:
        raise RuntimeError("SEV-SNP attestation failed: configfs-TSM interface not present")

    monkeypatch.setattr(snp_mod, "_tsm_get_report", boom)
    with pytest.raises(RuntimeError, match="SEV-SNP attestation failed"):
        SEVSNPProvider().get_attestation_report(b"\x00" * 32)


def test_sev_snp_get_report_success_via_tsm(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_attestation_report parses the configfs-TSM outblob and binds the nonce."""
    from cmcp_runtime.tee import sev_snp as snp_mod
    from cmcp_runtime.tee.sev_snp import _SNP_REPORT_SIZE

    nonce = bytes(range(64))
    raw = bytearray(_SNP_REPORT_SIZE)
    raw[SNP_OFFSETS["report_data"]:SNP_OFFSETS["report_data"] + 64] = nonce
    monkeypatch.setattr(snp_mod, "_tsm_get_report", lambda report_data: bytes(raw))

    report = SEVSNPProvider().get_attestation_report(nonce)
    assert report.provider == "sev-snp"
    assert report.report_data == nonce.hex()
    assert report.raw_evidence == bytes(raw)


# ── TDXProvider struct layout (HW-007) ────────────────────────────────────────

def test_tdx_req_struct_size() -> None:
    """_TdxReportReq must be exactly 0x440 bytes."""
    assert ctypes.sizeof(_TdxReportReq) == 0x440


def test_tdx_req_struct_reportdata_round_trip() -> None:
    """Write a nonce into the reportdata field; read it back via named access."""
    req = _TdxReportReq()
    nonce = bytes(range(64))
    req.reportdata[:] = nonce
    assert bytes(req.reportdata) == nonce


def test_tdx_req_struct_tdreport_round_trip() -> None:
    """Write a pattern at the tdreport offset in a bytearray,
    parse with from_buffer_copy, assert named field reads it back."""
    buf = bytearray(ctypes.sizeof(_TdxReportReq))
    pattern = b"\xab" * 1024
    offset = _TdxReportReq.tdreport.offset
    buf[offset : offset + 1024] = pattern
    req = _TdxReportReq.from_buffer_copy(buf)
    assert bytes(req.tdreport) == pattern


# ── TDXProvider ────────────────────────────────────────────────────────────────

def test_tdx_detect_returns_false_when_device_missing() -> None:
    with patch.object(Path, "exists", return_value=False):
        assert TDXProvider().detect() is False


def test_tdx_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "darwin"), \
         patch.object(Path, "exists", return_value=False):
        assert TDXProvider().detect() is False


def test_tdx_detect_returns_true_when_device_present() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=True):
        assert TDXProvider().detect() is True


def test_tdx_provider_name() -> None:
    assert TDXProvider().provider_name() == "tdx"


def test_tdx_get_report_raises_on_ioctl_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """ioctl raising OSError must surface as RuntimeError."""
    mock_fcntl = MagicMock()
    mock_fcntl.ioctl = MagicMock(side_effect=OSError("ioctl failed"))
    monkeypatch.setitem(sys.modules, "fcntl", mock_fcntl)

    mock_fd = MagicMock()
    mock_fd.__enter__ = MagicMock(return_value=mock_fd)
    mock_fd.__exit__ = MagicMock(return_value=False)

    with patch("builtins.open", return_value=mock_fd), pytest.raises(RuntimeError, match="TDX attestation failed"):
        TDXProvider().get_attestation_report(b"\x00" * 32)


# ── TPMProvider ────────────────────────────────────────────────────────────────

def test_tpm_detect_returns_false_when_no_device() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=False):
        assert TPMProvider().detect() is False


def test_tpm_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "win32"):
        assert TPMProvider().detect() is False


def test_tpm_provider_name() -> None:
    assert TPMProvider().provider_name() == "tpm"


def test_tpm_get_report_raises_when_no_tss2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    failed_result = MagicMock(spec=subprocess.CompletedProcess)
    failed_result.returncode = 1
    failed_result.stderr = "error: cannot open /dev/tpm0"
    failed_result.stdout = ""

    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=failed_result))

    with pytest.raises(RuntimeError, match="TPM device found but could not read PCRs"):
        TPMProvider().get_attestation_report(b"\x00" * 32)


def test_tpm_detect_does_not_raise_on_exception() -> None:
    with patch.object(Path, "exists", side_effect=PermissionError("no access")):
        assert TPMProvider().detect() is False


def test_tpm_sha1_fallback_subprocess_produces_software_only_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SHA-1 fallback via subprocess must downgrade provider to software-only."""
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    sha256_fail = MagicMock(spec=subprocess.CompletedProcess)
    sha256_fail.returncode = 1
    sha256_fail.stderr = "algorithm not supported"
    sha256_fail.stdout = ""

    sha1_pcr_output = "\n".join(
        [
            "sha1:",
            *[f"  {i} : 0x" + ("ab" * 20) for i in range(8)],
        ]
    )
    sha1_ok = MagicMock(spec=subprocess.CompletedProcess)
    sha1_ok.returncode = 0
    sha1_ok.stderr = ""
    sha1_ok.stdout = sha1_pcr_output

    monkeypatch.setattr(subprocess, "run", MagicMock(side_effect=[sha256_fail, sha1_ok]))

    report = TPMProvider().get_attestation_report(b"\x00" * 32)

    assert report.provider == "software-only"
    assert report.measurement_note == "sha1-bank-fallback"
    assert report.measurement.startswith("sha256:")


def test_tpm_sha256_subprocess_downgrades_without_quote_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The subprocess path reads PCRs but cannot produce a quote, so the report has no
    signature and nothing binds it to a TPM. It must not present as hardware-attested,
    even though the SHA-256 bank was available."""
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    sha256_pcr_output = "\n".join(
        [
            "sha256:",
            *[f"  {i} : 0x" + ("cd" * 32) for i in range(8)],
        ]
    )
    sha256_ok = MagicMock(spec=subprocess.CompletedProcess)
    sha256_ok.returncode = 0
    sha256_ok.stderr = ""
    sha256_ok.stdout = sha256_pcr_output

    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=sha256_ok))

    report = TPMProvider().get_attestation_report(b"\x00" * 32)

    assert report.provider == "software-only"
    assert report.measurement_note == "tpm-pcr-read-unsigned"
    assert report.measurement.startswith("sha256:")


def test_downgrade_note_keeps_hardware_tier_when_quote_evidence_is_present() -> None:
    assert TPMProvider._downgrade_note(None, b"\xffTCG-quote-bytes") is None


def test_downgrade_note_marks_an_unsigned_pcr_read() -> None:
    assert TPMProvider._downgrade_note(None, None) == "tpm-pcr-read-unsigned"


def test_downgrade_note_preserves_the_sha1_fallback_note() -> None:
    assert TPMProvider._downgrade_note("sha1-bank-fallback", None) == "sha1-bank-fallback"


# ── TPMProvider: the probe reads the PCRs a report reads ─────────────────────

GOOD = [b"\x11" * 32] * 8


class _FakeEsapi:
    """Stands in for tpm2_pytss.ESAPI.ESAPI. ``banks`` maps a bank to the
    digests it returns, or to an exception it raises."""

    open_error: Exception | None = None
    banks: dict[str, object] = {}
    reads: list[str] = []

    def __enter__(self) -> _FakeEsapi:
        if _FakeEsapi.open_error is not None:
            raise _FakeEsapi.open_error
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def pcr_read(self, selection: str):
        bank = selection.split(":")[0]
        _FakeEsapi.reads.append(selection)
        answer = _FakeEsapi.banks.get(bank, RuntimeError(f"no {bank} bank"))
        if isinstance(answer, Exception):
            raise answer
        return None, None, types.SimpleNamespace(digests=answer)


@pytest.fixture
def devices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Two device nodes, both present, with tpm2-pytss faked and nothing else."""
    found = [tmp_path / "tpm0", tmp_path / "tpmrm0"]
    for dev in found:
        dev.touch()
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TPM_DEVICES", found)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", True)
    esapi = types.ModuleType("tpm2_pytss.ESAPI")
    esapi.ESAPI = _FakeEsapi  # type: ignore[attr-defined]
    tss_types = types.ModuleType("tpm2_pytss.types")
    tss_types.TPML_PCR_SELECTION = types.SimpleNamespace(parse=lambda text: text)  # type: ignore[attr-defined]
    tss_types.TPM2B_DATA = bytes  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tpm2_pytss.ESAPI", esapi)
    monkeypatch.setitem(sys.modules, "tpm2_pytss.types", tss_types)
    monkeypatch.setattr(_FakeEsapi, "open_error", None)
    monkeypatch.setattr(_FakeEsapi, "banks", {"sha256": GOOD})
    monkeypatch.setattr(_FakeEsapi, "reads", [])
    monkeypatch.setattr("cmcp_runtime.tee.tpm.os.access", lambda *_: True)
    return found


def _probe() -> tuple[bool, str]:
    provider = TPMProvider()
    usable = provider.detect()
    return usable, provider.unusable_reason() or ""


def test_probe_reads_pcrs_0_to_7_from_sha256(devices: list[Path]) -> None:
    assert _probe() == (True, "")
    assert _FakeEsapi.reads == ["sha256:0,1,2,3,4,5,6,7"]


def test_probe_falls_back_to_sha1_like_the_report(devices: list[Path]) -> None:
    _FakeEsapi.banks = {"sha256": RuntimeError("no bank"), "sha1": GOOD}
    assert _probe() == (True, "")
    assert _FakeEsapi.reads == ["sha256:0,1,2,3,4,5,6,7", "sha1:0,1,2,3,4,5,6,7"]


@pytest.mark.parametrize(
    "banks, expected",
    [
        ({"sha256": RuntimeError("PCR 7 unreadable"), "sha1": RuntimeError("no sha1")}, "no sha1"),
        ({"sha256": GOOD[:7]}, "got 7, expected 8"),
    ],
    ids=["no-bank-reads", "seven-pcrs"],
)
def test_a_tpm_that_answers_but_cannot_give_the_report_pcrs_is_unusable(
    devices: list[Path], banks: dict, expected: str
) -> None:
    """The case a capability query would have passed."""
    _FakeEsapi.banks = banks
    usable, reason = _probe()
    assert usable is False and expected in reason


def test_a_tpm_that_does_not_open_is_unusable(devices: list[Path]) -> None:
    _FakeEsapi.open_error = RuntimeError("tcti:IO failure")
    usable, reason = _probe()
    assert usable is False and "did not answer: tcti:IO failure" in reason


@pytest.mark.parametrize(
    "blocked", [set(), {0}, {1}, {0, 1}], ids=["none", "tpm0", "tpmrm0", "both"]
)
def test_the_permission_hint_names_only_blocked_devices(
    devices: list[Path], monkeypatch: pytest.MonkeyPatch, blocked: set[int]
) -> None:
    monkeypatch.setattr(
        "cmcp_runtime.tee.tpm.os.access", lambda path, _mode: Path(path) not in {devices[i] for i in blocked}
    )
    assert _probe()[0] is True  # modes never decide usability
    _FakeEsapi.open_error = RuntimeError("tcti:IO failure")
    usable, reason = _probe()
    assert usable is False
    for i, dev in enumerate(devices):
        assert (f"{dev}" in reason.split("cannot read and write", 1)[-1]) is (i in blocked) or not blocked
    assert ("which may be the cause" in reason) is bool(blocked)


def test_esapi_is_preferred_when_both_backends_exist(
    devices: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("cmcp_runtime.tee.tpm.shutil.which", lambda _: "/usr/bin/tpm2_pcrread")
    monkeypatch.setattr("cmcp_runtime.tee.tpm.subprocess.run", lambda *a, **k: pytest.fail("ran tools"))
    assert _probe() == (True, "")


def test_no_backend_installed(devices: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)
    monkeypatch.setattr("cmcp_runtime.tee.tpm.shutil.which", lambda _: None)
    usable, reason = _probe()
    assert usable is False and "not on this process's PATH" in reason


_PCRREAD_OK = "sha256:\n" + "".join(f"  {i} : 0x{'11' * 32}\n" for i in range(8))


def _tools(monkeypatch: pytest.MonkeyPatch, answer) -> list[list[str]]:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: object):
        seen.append(argv)
        return answer(argv)

    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)
    monkeypatch.setattr("cmcp_runtime.tee.tpm.shutil.which", lambda _: "/usr/bin/tpm2_pcrread")
    monkeypatch.setattr("cmcp_runtime.tee.tpm.subprocess.run", fake_run)
    return seen


def _done(code: int, out: str = "", err: str = ""):
    return subprocess.CompletedProcess([], code, out, err)


def test_tools_probe_reads_the_report_selection(devices: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _tools(monkeypatch, lambda _a: _done(0, _PCRREAD_OK))
    assert _probe() == (True, "")
    assert seen == [["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"]]


def test_tools_probe_falls_back_to_sha1(devices: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _tools(monkeypatch, lambda a: _done(0, _PCRREAD_OK) if a[1].startswith("sha1") else _done(1))
    assert _probe() == (True, "")
    assert [a[1] for a in seen] == ["sha256:0,1,2,3,4,5,6,7", "sha1:0,1,2,3,4,5,6,7"]


@pytest.mark.parametrize(
    "answer, expected, calls",
    [
        (lambda _a: _done(1, err="ERROR: Esys_PCR_Read"), "exited 1: ERROR: Esys_PCR_Read", 2),
        (lambda _a: _done(0, "sha256:\n  0 : 0x" + "11" * 32 + "\n"), "parsed 1 PCRs", 1),
        (lambda _a: (_ for _ in ()).throw(subprocess.TimeoutExpired("tpm2_pcrread", 30)), "timed out", 1),
        (lambda _a: (_ for _ in ()).throw(FileNotFoundError("tpm2_pcrread")), "tpm2_pcrread", 1),
    ],
    ids=["both-banks-fail", "one-pcr-only", "times-out", "binary-vanished"],
)
def test_tools_that_cannot_give_the_report_pcrs(
    devices: list[Path], monkeypatch: pytest.MonkeyPatch, answer, expected: str, calls: int
) -> None:
    """A launch failure is not bank-specific, so it does not retry with SHA-1."""
    seen = _tools(monkeypatch, answer)
    usable, reason = _probe()
    assert usable is False and expected in reason
    assert len(seen) == calls


def test_probe_and_report_share_one_reader(devices: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    """Whatever the report's PCR read needs, detection checks, by construction."""
    from cmcp_runtime.tee import tpm

    def broken(_ectx: object) -> None:
        raise RuntimeError("reader broke")

    monkeypatch.setattr(tpm, "_read_pcrs_tss2", broken)
    assert _probe()[0] is False
    with pytest.raises(RuntimeError, match="reader broke"):
        TPMProvider().get_attestation_report(b"\x00" * 64)


def test_absent_tpm_is_not_a_fault_and_is_not_probed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TPM_DEVICES", [tmp_path / "missing"])
    monkeypatch.setattr("cmcp_runtime.tee.tpm._tss2_error", lambda: pytest.fail("probed"))
    assert _probe() == (False, "")


def test_not_linux_is_not_probed(devices: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert _probe() == (False, "")
    assert _FakeEsapi.reads == []


@pytest.mark.parametrize("broken", ["exists", "access"])
def test_a_failing_check_is_a_reason_not_an_exception(
    devices: list[Path], monkeypatch: pytest.MonkeyPatch, broken: str
) -> None:
    def boom(*_: object) -> bool:
        raise PermissionError("EACCES on /dev")

    if broken == "exists":
        monkeypatch.setattr(Path, "exists", boom)
    else:
        _FakeEsapi.open_error = RuntimeError("no answer")
        monkeypatch.setattr("cmcp_runtime.tee.tpm.os.access", boom)
    usable, reason = _probe()
    assert usable is False
    assert "PermissionError: EACCES on /dev" in reason


def test_detect_and_reason_share_one_probe(devices: list[Path]) -> None:
    """The reason explains the same look at the TPM that detect() decided on."""
    _FakeEsapi.open_error = RuntimeError("first look")
    provider = TPMProvider()
    assert provider.detect() is False
    _FakeEsapi.open_error = None  # the TPM comes back after detection
    assert "first look" in (provider.unusable_reason() or "")
    assert provider.detect() is True
    assert provider.unusable_reason() is None


