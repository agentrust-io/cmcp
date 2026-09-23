"""CI smoke test for the shipped Compose mounts, UID and audit persistence."""
import os
import sqlite3
import sys
from pathlib import Path

from cmcp_runtime.config import load_config


def main() -> None:
    mode = sys.argv[1]
    if mode not in {"write", "read"}:
        raise ValueError("expected write or read")
    if os.getuid() != 10001:
        raise RuntimeError("smoke test must run as the image's non-root user")
    config = load_config("/etc/cmcp/cmcp-config.yaml")
    if not Path(config.policy_bundle_path).is_dir() or not Path(config.catalog_path).is_file():
        raise RuntimeError("relative policy/catalog paths do not resolve")
    database = Path(config.audit_db_path).resolve()
    if database != Path("/var/lib/cmcp/audit.db"):
        raise RuntimeError(f"unexpected audit path: {database}")
    connection = sqlite3.connect(database)
    try:
        if mode == "write":
            connection.execute("CREATE TABLE compose_storage_probe (value TEXT NOT NULL)")
            connection.execute("INSERT INTO compose_storage_probe VALUES ('retained')")
            connection.commit()
        else:
            rows = connection.execute("SELECT value FROM compose_storage_probe").fetchall()
            if rows != [("retained",)]:
                raise RuntimeError(f"audit volume did not preserve the probe: {rows}")
    finally:
        connection.close()
    print(f"Compose storage {mode}: passed as uid {os.getuid()}")


if __name__ == "__main__":
    main()
