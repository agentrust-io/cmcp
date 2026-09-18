import json

from tests.confinement.gateway import make_gateway


async def test_real_gateway_records_only_authorized_delivery(tmp_path):
    sink = tmp_path / "received.jsonl"
    proxy, dispatch = make_gateway(sink)
    try:
        assert (await dispatch("permitted.tool", {"value": "synthetic"}))["allowed"]
        assert not (await dispatch("public.tool", {"value": "synthetic"}))["allowed"]
    finally:
        await proxy.aclose()
    assert [json.loads(line)["name"] for line in sink.read_text().splitlines()] == ["permitted.tool"]


async def test_removing_sink_ceiling_delivers_to_public_peer(tmp_path):
    sink = tmp_path / "received.jsonl"
    proxy, dispatch = make_gateway(sink, public_ceiling="confidential")
    try:
        assert (await dispatch("public.tool", {"value": "synthetic"}))["allowed"]
    finally:
        await proxy.aclose()
    assert json.loads(sink.read_text())["name"] == "public.tool"
