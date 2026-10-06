import asyncio
import time

from trishul_snmp import V2cManager


async def main() -> None:
    manager = V2cManager(host="127.0.0.1", port=1199, community="public")
    async with manager:
        await manager.get((1, 3, 6, 1, 2, 1, 1, 1, 0))

        n = 200
        t0 = time.perf_counter()
        for _ in range(n):
            await manager.get((1, 3, 6, 1, 2, 1, 1, 1, 0))
        dt = time.perf_counter() - t0
        print(
            f"py-lib: {n} sequential gets in {dt:.3}s "
            f"-> {n / dt:.1f} req/s ({dt / n * 1e6:.0f} us/req)"
        )

        await manager.walk((1, 3, 6, 1, 2, 1))
        t0 = time.perf_counter()
        vbs = await manager.walk((1, 3, 6, 1, 2, 1))
        dt = time.perf_counter() - t0
        print(f"py-lib: mib-2 walk: {len(vbs)} varbinds in {dt:.3}s")


asyncio.run(main())
