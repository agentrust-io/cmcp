# Catalog lifecycle: immutable until restart

**Status:** Decided and enforced  
**Decision:** A running cMCP process never reloads or mutates its approved catalog.

The catalog binds tool names to upstream identities, TLS pins, measured stdio
executables, and approved schemas. Changing it at runtime can redirect a
permitted call to different code or a different network authority. That blast
radius is larger than changing a policy decision over an otherwise stable route.

`CMCP_CATALOG_HASH` therefore means exactly one approved catalog artifact for
the process lifetime. To change it, an operator writes the new artifact,
computes and pins its hash, restarts the gateway, and obtains fresh attestation
evidence naming that hash. There is no polling interval, reload endpoint,
filesystem watcher, or signing-key exception for the catalog.

This does not hide upstream drift. `CATALOG_DRIFT_DETECTED` compares advertised
tool definitions with the sealed catalog and fails closed; it reports that
reality moved rather than silently rewriting the authority.

## Executable guard

Configuration keys implying runtime mutation, including
`catalog_reload_interval_seconds` and `catalog_reload_path`, are reserved and
rejected with `CATALOG_RESTART_REQUIRED`. A future implementation cannot make
one valid by only adding a parser field. Changing this lifecycle requires
deliberately removing the guard, revising this decision, and replacing its tests
with a complete authorization and attestation model.
