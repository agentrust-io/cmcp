"""Test-only cleanup when a bridge can concurrently remove its container."""

from examples.confinement.adapter import Refused


async def remove_if_present(observer, container):
    async def present():
        names = await observer.docker("ps", "--all", "--format", "{{.Names}}")
        return container.encode() in names.splitlines()

    if not await present():
        return
    try:
        await observer.docker("rm", "--force", container)
    except Refused:
        # A bridge finally block may have removed it since the first listing.
        # Accept only a successful independent observation of absence.
        if await present():
            raise
        return
    if await present():
        raise Refused("container cleanup incomplete")
