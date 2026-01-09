import json
import asyncio
from functools import wraps
from typing import Optional

from telethon import TelegramClient, events
from telethon.sessions import StringSession

API_ID = 0
API_HASH = ""
SESSION = ""
GROUP_ID = 0          # group/supergroup/channel id (int)
K_DEFENDER_ID = 0     # bot id (int)
CHAT_TOKEN = ""

_bot = None
_mt: Optional[TelegramClient] = None
_lock = asyncio.Lock()

KDEFENDER_CMD = {"/start", "/help", "/get_info", "/settings", "/menu"}


class KDefenderNotReady(RuntimeError):
    pass


async def setup(
    bot=None,
    api_id=None,
    api_hash=None,
    session=None,
    group_id=None,
    chat_token=None,
    kdefender_id=None,
):
    """
    One-line setup:
        await setup(bot=bot, api_id=..., api_hash=..., session=..., group_id=..., chat_token=..., kdefender_id=...)
    """
    missing = []
    if bot is None:
        missing.append("bot")
    if not api_id:
        missing.append("api_id")
    if not api_hash:
        missing.append("api_hash")
    if not session:
        missing.append("session")
    if not group_id:
        missing.append("group_id")
    if not chat_token:
        missing.append("chat_token")
    if not kdefender_id:
        missing.append("kdefender_id")

    if missing:
        raise KDefenderNotReady("K-Defender wrapper not configured. Missing: " + ", ".join(missing))

    global _bot, _mt, API_ID, API_HASH, SESSION, GROUP_ID, CHAT_TOKEN, K_DEFENDER_ID
    API_ID = int(api_id)
    API_HASH = str(api_hash)
    SESSION = str(session)
    GROUP_ID = int(group_id)
    CHAT_TOKEN = str(chat_token)
    K_DEFENDER_ID = int(kdefender_id)
    _bot = bot

    # Start Telethon (MTProto user client)
    if _mt is None:
        _mt = TelegramClient(StringSession(SESSION), API_ID, API_HASH)
        await _mt.start()
    elif not _mt.is_connected():
        await _mt.connect()


async def close():
    global _mt
    if _mt and _mt.is_connected():
        await _mt.disconnect()
    _mt = None


def _strip_kdefender_command(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""

    for cmd in KDEFENDER_CMD:
        if t == cmd:
            return ""
        if t.startswith(cmd + " "):
            return t[len(cmd):].lstrip()
    return t


def _extract_user_text(update) -> Optional[str]:
    # Message-like
    text = getattr(update, "text", None)
    if text:
        return text

    caption = getattr(update, "caption", None)
    if caption:
        return caption

    # CallbackQuery-like
    data = getattr(update, "data", None)
    if data:
        return data

    return None


def _blocked_reply_target(update):
    # aiogram Message
    if hasattr(update, "answer") and not hasattr(update, "data"):
        return update

    # aiogram CallbackQuery -> message
    msg = getattr(update, "message", None)
    if msg and hasattr(msg, "answer"):
        return msg

    return None


async def _send_and_wait_verdict(text: str, timeout: int = 10) -> bool:
    """
    Sends to GROUP via MTProto:
        "<bot_id> | <text> | <CHAT_TOKEN>"
    Waits for K-Defender JSON verdict message in the same group.

    Returns:
        True  -> ok
        False -> blocked/timeout/error
    """
    if _mt is None:
        raise KDefenderNotReady("Call await setup(...) before using @kdefender_check().")

    global _bot
    users_bot = await _bot.get_me()

    payload = f"{users_bot.id} | {text} | {CHAT_TOKEN}"

    async with _lock:
        got_reply = asyncio.Event()
        verdict_ok = False

        def _try_parse_json_from_message(raw: str):
            if not raw:
                return None
            
            for line in raw.splitlines():
                s = line.strip()
                if s.startswith("{") and s.endswith("}"):
                    try:
                        return json.loads(s)
                    except Exception:
                        continue
            return None

        async def handler(event):
            nonlocal verdict_ok
            raw = (event.raw_text or "").strip()
            data = _try_parse_json_from_message(raw)
            if not isinstance(data, dict):
                return
            if "result" not in data:
                return

            verdict_ok = (data.get("result") == "ok")
            got_reply.set()

        event_filter = events.NewMessage(chats=GROUP_ID, from_users=K_DEFENDER_ID, incoming=True)
        _mt.add_event_handler(handler, event_filter)

        try:
            await _mt.send_message(GROUP_ID, payload)
            await asyncio.wait_for(got_reply.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            verdict_ok = False
        finally:
            try:
                _mt.remove_event_handler(handler, event_filter)
            except Exception:
                pass

        return verdict_ok


def kdefender_check(timeout: int = 10):
    """
    Decorator:
        @kdefender_check()
        async def handler(message): ...

    Flow:
      - extracts user text
      - skips messages from GROUP_ID
      - strips kdefender commands (/start ...)
      - sends to K-Defender via MTProto-group relay
      - blocks if verdict != ok
    """
    def deco(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # find update-like object
            update = None
            for a in args:
                if hasattr(a, "chat") or hasattr(a, "data") or hasattr(a, "from_user"):
                    update = a
                    break
            if update is None:
                update = next(iter(kwargs.values()), None)

            if not update:
                return await func(*args, **kwargs)

            # skip traffic inside defender group itself
            chat = getattr(update, "chat", None)
            chat_id = getattr(chat, "id", None)
            if chat_id == GROUP_ID:
                return

            text = _extract_user_text(update)
            text = _strip_kdefender_command(text or "")
            if not text:
                return await func(*args, **kwargs)

            ok = await _send_and_wait_verdict(text, timeout=timeout)
            if not ok:
                target = _blocked_reply_target(update)
                if target:
                    await target.answer("Message blocked by 🛡️K-Defender🔐")
                return

            return await func(*args, **kwargs)
        return wrapper
    return deco