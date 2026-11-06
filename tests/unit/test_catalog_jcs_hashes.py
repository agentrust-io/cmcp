import hashlib

import rfc8785

from cmcp_runtime.catalog.loader import _catalog_hash, _compute_definition_hash


def test_catalog_and_definition_hashes_use_rfc8785():
    definition = {"description": "café", "input_schema": {"\uffff": 1, "\U00010000": 1e-7}}
    entries = [{"tool_name": "café", "definition": definition}]
    def digest(value):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()

    assert _compute_definition_hash(definition) == digest(definition)
    assert _catalog_hash(entries) == digest(entries)
