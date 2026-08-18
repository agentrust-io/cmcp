"""TDREPORT_STRUCT layout, shared by the TDX producer and the TDX verifier.

One definition, imported by both, because the alternative is what issue #371
found: `cmcp_runtime/tee/tdx.py` and `cmcp_verify/tdx.py` each carried their own
offsets, both wrong in the same way, and agreeing with each other is exactly how
that survived. Nothing is imported here beyond ctypes, so either side can pull
it in without dragging the other package along.

Layout per the Intel TDX Module ABI specification:

    TDREPORT_STRUCT (1024 bytes)
      0x000  REPORTMACSTRUCT   256
      0x100  TEE_TCB_INFO      239
      0x1EF  RESERVED           17
      0x200  TDINFO_STRUCT     512

Every offset below is computed by ctypes from that layout rather than written
as a literal.
"""
from __future__ import annotations

import ctypes


class ReportMacStruct(ctypes.LittleEndianStructure):
    """REPORTMACSTRUCT, the first 256 bytes of TDREPORT_STRUCT.

    ``report_data`` is the 64 bytes the guest passed to TDG.MR.REPORT, at
    offset 0x80. The verifier previously read 0x08, which is inside the leading
    RESERVED block.
    """

    _pack_ = 1
    _fields_ = [
        ("report_type",       ctypes.c_uint8 * 4),    # 0x00
        ("_reserved0",        ctypes.c_uint8 * 12),   # 0x04
        ("cpu_svn",           ctypes.c_uint8 * 16),   # 0x10
        ("tee_tcb_info_hash", ctypes.c_uint8 * 48),   # 0x20
        ("tee_info_hash",     ctypes.c_uint8 * 48),   # 0x50
        ("report_data",       ctypes.c_uint8 * 64),   # 0x80
        ("_reserved1",        ctypes.c_uint8 * 32),   # 0xC0
        ("mac",               ctypes.c_uint8 * 32),   # 0xE0
    ]


class TdInfo(ctypes.LittleEndianStructure):
    """TDINFO_STRUCT, the trailing 512 bytes of TDREPORT_STRUCT.

    ``mrtd`` is the TD build-time measurement, at 0x10 within TDINFO and so
    0x210 within the report.
    """

    _pack_ = 1
    _fields_ = [
        ("attributes",      ctypes.c_uint8 * 8),      # 0x000
        ("xfam",            ctypes.c_uint8 * 8),      # 0x008
        ("mrtd",            ctypes.c_uint8 * 48),     # 0x010
        ("mr_config_id",    ctypes.c_uint8 * 48),     # 0x040
        ("mr_owner",        ctypes.c_uint8 * 48),     # 0x070
        ("mr_owner_config", ctypes.c_uint8 * 48),     # 0x0A0
        ("rtmr",            ctypes.c_uint8 * 192),    # 0x0D0 - RTMR0..RTMR3
        ("servtd_hash",     ctypes.c_uint8 * 48),     # 0x190
        ("_reserved",       ctypes.c_uint8 * 64),     # 0x1C0
    ]


class TdReport(ctypes.LittleEndianStructure):
    """TDREPORT_STRUCT as returned by the TDX_CMD_GET_REPORT0 ioctl."""

    _pack_ = 1
    _fields_ = [
        ("report_mac",    ReportMacStruct),           # 0x000 - 256 bytes
        ("_tee_tcb_info", ctypes.c_uint8 * 239),      # 0x100 - 239 bytes
        ("_reserved",     ctypes.c_uint8 * 17),       # 0x1EF - 17 bytes
        ("td_info",       TdInfo),                    # 0x200 - 512 bytes
    ]


assert ctypes.sizeof(ReportMacStruct) == 256, (
    f"ReportMacStruct size mismatch: got {ctypes.sizeof(ReportMacStruct)}, expected 256"
)
assert ctypes.sizeof(TdInfo) == 512, (
    f"TdInfo size mismatch: got {ctypes.sizeof(TdInfo)}, expected 512"
)
assert ctypes.sizeof(TdReport) == 1024, (
    f"TdReport size mismatch: got {ctypes.sizeof(TdReport)}, expected 1024"
)

TDREPORT_SIZE = ctypes.sizeof(TdReport)

# Absolute offsets into the report buffer, derived from the structs above.
MRTD_OFFSET = TdReport.td_info.offset + TdInfo.mrtd.offset                  # 0x210
MRTD_SIZE = TdInfo.mrtd.size                                                # 48
REPORT_DATA_OFFSET = TdReport.report_mac.offset + ReportMacStruct.report_data.offset  # 0x80
REPORT_DATA_SIZE = ReportMacStruct.report_data.size                         # 64

# The ABI offsets this module exists to pin. A layout edit that moves either
# field is a change to what an attestation means, so it fails here first.
assert MRTD_OFFSET == 0x210, f"MRTD offset moved: {MRTD_OFFSET:#x}"
assert REPORT_DATA_OFFSET == 0x80, f"REPORTDATA offset moved: {REPORT_DATA_OFFSET:#x}"
