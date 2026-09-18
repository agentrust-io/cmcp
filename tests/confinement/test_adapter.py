"""Contract tests run on every OS; actual Docker evidence is in test_linux.py."""

import json
from copy import deepcopy

import pytest
from examples.confinement.adapter import (
    Refused,
    check_core_pattern,
    create_arguments,
    decode_request,
    verify_container,
)


@pytest.mark.parametrize("pattern", ["|/usr/lib/systemd/systemd-coredump %P", " |handler", ""])
def test_unsupported_crash_policy_refused(pattern):
    with pytest.raises(Refused):
        check_core_pattern(pattern)


def test_file_core_policy_and_immutable_image():
    check_core_pattern("core.%p")
    assert "--network=none" in create_arguments("sha256:" + "a" * 64, "cmcp-" + "b" * 32)
    with pytest.raises(Refused):
        create_arguments("agent:latest", "cmcp-" + "b" * 32)


@pytest.mark.parametrize("value", [
    {"operation": "missing", "arguments": {}},
    {"operation": "ok", "arguments": {}, "declared_data_class": "public"},
    {"operation": "ok", "arguments": {}, "sink_policy": None},
    {"operation": ["ok"], "arguments": {}},
    {"operation": "ok", "arguments": []}, [], "secret", None,
])
def test_agent_cannot_select_configuration_or_arbitrary_metadata(value):
    with pytest.raises(Refused, match="^invalid agent request$"):
        decode_request(json.dumps(value).encode(), {"ok": "trusted.tool"})


def test_valid_alias_and_non_json():
    assert decode_request(b'{"operation":"ok","arguments":{"x":1}}', {"ok": "trusted.tool"}) == ("trusted.tool", {"x": 1})
    with pytest.raises(Refused, match="^invalid agent request$"):
        decode_request(b"private plaintext\n", {})


def valid_inspect():
    return {"Mounts": [], "Config": {
        "User": "10001:10001", "Entrypoint": ["python"], "Cmd": ["-I", "/agent.py"],
    }, "HostConfig": {
        "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
        "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
        "LogConfig": {"Type": "none"}, "RestartPolicy": {"Name": "no"},
        "PidsLimit": 32, "Memory": 134217728, "MemorySwap": 134217728,
        "IpcMode": "private", "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}],
    }}


@pytest.mark.parametrize("section,key,value", [
    ("HostConfig", "NetworkMode", "host"), ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "Privileged", True), ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    ("HostConfig", "LogConfig", {"Type": "json-file"}),
    ("HostConfig", "RestartPolicy", {"Name": "always"}),
    ("HostConfig", "Ulimits", [{"Name": "core", "Soft": -1, "Hard": -1}]),
    ("HostConfig", "Binds", ["/tmp:/export"]), ("HostConfig", "PidMode", "host"),
    ("HostConfig", "IpcMode", "host"), ("Config", "User", "0"),
    ("Config", "Volumes", {"/export": {}}),
])
def test_inspection_refuses_weakened_profile(section, key, value):
    info = valid_inspect()
    verify_container(info)
    mutant = deepcopy(info)
    mutant[section][key] = value
    with pytest.raises(Refused):
        verify_container(mutant)
