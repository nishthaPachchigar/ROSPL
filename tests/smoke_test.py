import asyncio
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(
        command="python",
        args=["-m", "server.main"],
        cwd=os.getcwd(),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Registered tools:")
            for t in tools.tools:
                print(" -", t.name, "|", t.description.splitlines()[0])


if __name__ == "__main__":
    asyncio.run(main())