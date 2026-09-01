import asyncio, logging
logging.basicConfig(level=logging.DEBUG)
print("Calling start_bot...")
from telegram_bot import start_bot, _bot_app
async def test():
    await start_bot()
    print("Done. Bot running:", _bot_app is not None)
asyncio.run(test())
