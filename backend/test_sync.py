import asyncio, httpx

async def sync():
    async with httpx.AsyncClient() as c:
        r = await c.post("http://localhost:8000/api/wifi/192-168-0-1/sync", timeout=30)
        data = r.json()
        print("Sync:", data.get("success"))
        if data.get("data"):
            ifaces = data["data"].get("interfaces", [])
            print(f"Interfaces scraped: {len(ifaces)}")
            for i in ifaces:
                print(f"  {i['name']:8} {i['status']:8} {i.get('speed',''):6} {i.get('mac',''):20} {i.get('ip','')}")

asyncio.run(sync())
