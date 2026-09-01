import os
import asyncio
import logging
import json
import httpx
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

logger = logging.getLogger(__name__)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID_STR = os.getenv("TELEGRAM_CHAT_ID", "")
API_KEY = os.getenv("NETBOT_API_KEY", "")
API_BASE = "http://localhost:8000"

SAFE_CMD_PREFIXES = ("show", "display", "ping", "traceroute", "tracert", "dir", "who", "help")

_bot_app: Application | None = None
_conversations: dict[int, list[dict]] = {}
MAX_HISTORY = 10


async def _send_long(update: Update, text: str):
    """Send a message, splitting if longer than 4000 chars."""
    if len(text) <= 4000:
        await update.message.reply_text(text)
        return
    while text:
        chunk = text[:4000]
        idx = max(chunk.rfind("\n"), chunk.rfind(". "), chunk.rfind("? "), chunk.rfind("! "), 0)
        if idx > 2000:
            chunk = text[: idx + 1]
        await update.message.reply_text(chunk)
        text = text[len(chunk) :].strip()


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "\U0001f916 Network Monitor Bot\n\n"
        "Sends alerts for device status changes.\n\n"
        "Commands:\n"
        "/status \u2014 current device statuses\n"
        "/devices \u2014 list all registered devices with IDs\n"
        "/show <device> <command> \u2014 run a show command on a device\n"
        "/clear \u2014 reset AI conversation history\n"
        "/help \u2014 this message\n\n"
        "Or just send any message and I'll answer via the AI!"
    )


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    from database import get_devices
    devices = await get_devices()
    if not devices:
        await update.message.reply_text("No devices registered.")
        return
    lines = ["\U0001f4ca Device Status:"]
    for d in devices:
        icon = "\U0001f7e2" if d.status == "online" else "\U0001f534" if d.status == "offline" else "\U0001f7e1"
        lines.append(f"{icon} {d.hostname} ({d.ip}) \u2014 {d.status}")
    await update.message.reply_text("\n".join(lines))


async def cmd_devices(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    from database import get_devices
    devices = await get_devices()
    if not devices:
        await update.message.reply_text("No devices registered.")
        return
    lines = ["\U0001f4f1 Registered Devices:"]
    for d in devices:
        icon = "\U0001f7e2" if d.status == "online" else "\U0001f534" if d.status == "offline" else "\U0001f7e1"
        lines.append(f"{icon} {d.hostname} ({d.ip}) \u2014 id: `{d.id}`")
    await update.message.reply_text("\n".join(lines))


async def cmd_show(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    from database import get_devices
    text = update.message.text.strip()
    parts = text.split(maxsplit=2)
    if len(parts) < 3:
        await update.message.reply_text(
            "Usage: `/show <device> <command>`\n"
            "Example: `/show switch show interfaces status`\n"
            "Use `/devices` to see device IDs and hostnames."
        )
        return
    _, device_arg, command = parts
    if not command or not command.strip():
        await update.message.reply_text("Please provide a command to run.")
        return
    cmd_lower = command.strip().lower()
    if not any(cmd_lower.startswith(p) for p in SAFE_CMD_PREFIXES):
        await update.message.reply_text(
            "Only read-only commands are allowed from Telegram.\n"
            f"Allowed prefixes: {', '.join(SAFE_CMD_PREFIXES)}"
        )
        return
    devices = await get_devices()
    target = None
    for d in devices:
        if d.id == device_arg or d.hostname.lower() == device_arg.lower():
            target = d
            break
    if not target:
        await update.message.reply_text(
            f"Device '{device_arg}' not found. Use `/devices` to see available devices."
        )
        return
    await update.message.reply_text(
        f"\U0001f4e1 Running `{command}` on {target.hostname}..."
    )
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{API_BASE}/api/devices/{target.id}/execute",
                json={"command": command},
                headers={"X-NetBot-Api-Key": API_KEY} if API_KEY else {},
                timeout=30,
            )
            if r.status_code == 200:
                data = r.json()
                output = data.get("output", "") or "(no output)"
                hostname = data.get("hostname", target.hostname)
                if len(output) > 3900:
                    output = output[:3900] + "\n... [truncated]"
                await update.message.reply_text(
                    f"`{hostname}# {command}`\n```\n{output}\n```"
                )
            else:
                detail = ""
                try:
                    detail = r.json().get("detail", r.text)
                except Exception:
                    detail = r.text
                detail = detail[:1500]
                await update.message.reply_text(f"\u274c Error: {detail}")
    except httpx.TimeoutException:
        await update.message.reply_text("\u23f3 Command timed out after 30s. The device may be unreachable.")
    except Exception as e:
        await update.message.reply_text(f"\u274c Failed: {str(e)[:500]}")


async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    _conversations.pop(update.effective_chat.id, None)
    await update.message.reply_text("\U0001f9f9 Conversation history cleared.")


async def handle_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    user_text = update.message.text.strip()
    if not user_text:
        return
    await update.message.reply_text("\U0001f4ac Thinking...")
    history = _conversations.get(chat_id, [])
    history.append({"role": "user", "content": user_text})
    if len(history) > MAX_HISTORY * 2:
        history = history[-(MAX_HISTORY * 2) :]
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-NetBot-Api-Key"] = API_KEY
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{API_BASE}/api/chat",
                json={"message": user_text, "history": history},
                headers=headers,
                timeout=120,
            )
            if r.status_code == 200:
                data = r.json()
                reply = data.get("reply", "") or "(no response)"
                history.append({"role": "assistant", "content": reply})
                _conversations[chat_id] = history
                await _send_long(update, reply)
            else:
                detail = ""
                try:
                    detail = r.json().get("detail", r.text)
                except Exception:
                    detail = r.text
                await update.message.reply_text(f"\u274c AI Error: {detail[:1000]}")
    except httpx.TimeoutException:
        await update.message.reply_text("\u23f3 The AI took too long to respond. Try a simpler query.")
    except Exception as e:
        await update.message.reply_text(f"\u274c Failed: {str(e)[:500]}")


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_start(update, ctx)


async def send_alert(text: str):
    """Send a notification to the configured Telegram chat via direct API call."""
    if not TOKEN or not CHAT_ID_STR:
        return
    try:
        chat_id = int(CHAT_ID_STR)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text},
                timeout=10,
            )
            if r.status_code != 200:
                logger.error(f"Telegram API error: {r.status_code} {r.text[:200]}")
    except Exception:
        logger.exception("Failed to send Telegram alert")


async def start_bot():
    """Initialize and start the Telegram bot polling."""
    global _bot_app
    if not TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set \u2014 Telegram bot disabled")
        return
    for attempt in range(5):
        app = None
        try:
            app = Application.builder().token(TOKEN).read_timeout(15).connect_timeout(10).build()
            app.add_handler(CommandHandler("start", cmd_start))
            app.add_handler(CommandHandler("status", cmd_status))
            app.add_handler(CommandHandler("devices", cmd_devices))
            app.add_handler(CommandHandler("show", cmd_show))
            app.add_handler(CommandHandler("clear", cmd_clear))
            app.add_handler(CommandHandler("help", cmd_help))
            app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            await app.initialize()
            await app.start()
            await app.updater.start_polling(drop_pending_updates=True, error_callback=lambda e: logger.debug(f"Polling error: {e}"))
            _bot_app = app
            logger.info("Telegram bot started")
            return
        except Exception:
            logger.warning(f"Telegram bot start attempt {attempt + 1} failed, cleaning up...")
            if app:
                try:
                    await app.updater.stop()
                except Exception:
                    pass
                try:
                    await app.stop()
                except Exception:
                    pass
                try:
                    await app.shutdown()
                except Exception:
                    pass
            if attempt < 4:
                await asyncio.sleep(5)
    _bot_app = None
    raise RuntimeError("Telegram bot failed after 5 attempts")


async def stop_bot():
    """Stop the Telegram bot gracefully."""
    global _bot_app
    app = _bot_app
    _bot_app = None
    if not app:
        return
    for cleanup in ("updater.stop", "stop", "shutdown"):
        try:
            parts = cleanup.split(".")
            obj = app
            for p in parts:
                obj = getattr(obj, p)
            await obj()
        except Exception:
            pass
