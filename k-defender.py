import asyncio, random, string, os, time, json, html, secrets, hashlib, sys
from typing import Any, Dict

from aiogram import Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ContentType
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, Message, CallbackQuery
from aiogram.exceptions import TelegramBadRequest

from normalization import normalize_input

import dotenv
dotenv.load_dotenv()

# ---------------- Bot API ----------------
TOKEN = os.getenv("TOKEN")
bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

STATE_FILE = "state.json"
SIG_FILE = "signatures.json"

_autosave_task = None
logs_num = logs_num_save = 100

DRAFT_BOT_KEY = "new_bot"   # temp bot slot name while connecting (must be not a num, not to be same as bot_id)


async def autosave_loop():
    while True:
        await asyncio.sleep(30)
        try:
            save_state()
        except Exception:
            pass


def _atomic_write_json(path: str, data: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{default}")
            return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_state() -> None:
    _atomic_write_json(STATE_FILE, state)


state = load_json(STATE_FILE, {})      # user_id(str) -> data
signatures = load_json(SIG_FILE, {
    "SQLi": {
        "patterns": ["'", '"', "--", " or ", " and ", "1=1", "union select", "sleep(", "benchmark("],
        "risk": 100
    },
    "XSS": {
        "patterns": ["<script", "onerror=", "onload=", "javascript:", "<img", "<iframe"],
        "risk": 80
    }
})  # type → commands

DEFAULT_BOT_SETTINGS = {
    "SQLi": True,
    "XSS": True,
    "Inline_injection": True,
    "Entity_manipulation": True,
    "Markdown_injection": True,
    "Bot_command_injection": True,
    "Callback_query_injection": True,
    "Inline_query_injection": True,
    "Flood": True,
}

DEFAULT_USER_SETTINGS = {
    "enabled": True,
    "strict": False,
    "mode": "normal"      # normal / allow_all / block_all
}


# ---------------- STATE HELPERS ----------------
def ensure_user(user_id: int | str) -> dict:
    u = state.setdefault(str(user_id), {})
    u.setdefault("bots", {})
    u.setdefault("settings", {})
    return u


def bots_of(user_id: int | str) -> dict:
    return ensure_user(user_id)["bots"]


def ensure_draft(user_id: int | str, reset: bool = False) -> dict:
    bots = bots_of(user_id)
    if reset or DRAFT_BOT_KEY not in bots:
        bots[DRAFT_BOT_KEY] = {
            "step": 1,
            "verified": False,
            "instr_page": 0,
            "settings": {},
        }
    return bots[DRAFT_BOT_KEY]


def drop_draft(user_id: int | str) -> None:
    bots_of(user_id).pop(DRAFT_BOT_KEY, None)


def ensure_bot(user_id: int | str, bot_id: int | str) -> dict:
    bots = bots_of(user_id)
    b = bots.setdefault(str(bot_id), {})
    b.setdefault("step", 1)
    b.setdefault("verified", False)
    b.setdefault("instr_page", 0)
    b.setdefault("settings", {})
    return b


def real_bots_dict(user_id: int | str) -> dict:
    bots = bots_of(user_id)
    return {k: v for k, v in bots.items() if k != DRAFT_BOT_KEY}


def get_bot_settings(user_id: int, bot_id: int | str) -> dict:
    b = ensure_bot(user_id, bot_id)
    st = b.setdefault("settings", {})
    for k, v in DEFAULT_BOT_SETTINGS.items():
        st.setdefault(k, v)
    return st


def get_user_settings(user_id: int) -> dict:
    u = ensure_user(user_id)
    st = u.setdefault("settings", {})
    for k, v in DEFAULT_USER_SETTINGS.items():
        st.setdefault(k, v)
    return st


def reset_bot_token(user_id: int, bot_id: int | str) -> str:
    u = state.get(str(user_id))
    if not u:
        raise ValueError("User not found")

    bots = u.get("bots", {})
    b = bots.get(str(bot_id))
    if not b:
        raise ValueError("Bot not found")

    bot_username = b.get("bot_username")
    if not bot_username:
        raise ValueError("Bot username missing")

    new_token = generate_bot_token(bot_username)
    b["bot_token"] = new_token

    save_state()
    return new_token


# ---------------- SECURITY FUNCTIONS ----------------
def detect_inj(text, inj, user_state, sender):
    global signatures
    if inj == "Flood":
        return detect_flood(user_state, sender)
    sig = signatures.get(inj)
    if not sig:
        return False
    return any(x in text.lower() for x in sig.get("patterns", []))


def get_risk_score(inj_arr):
    global signatures
    score = 0
    for inj, hit in inj_arr.items():
        if not hit:
            continue
        sig = signatures.get(inj)
        if not sig:
            continue
        score += int(sig.get("risk", 0))
    return score


def detect_flood(user_state, sender):
    t = time.time()
    logs = user_state.setdefault("Flood", {})
    if sender not in logs:
        logs[sender] = []
    logs[sender] = [x for x in logs[sender] if t - x < 5]
    logs[sender].append(t)
    return len(logs[sender]) > 5


# ---------------- Instruction pages ----------------
setup_pages = [
    "<b>K-Defender Setup — Step 1</b>\n\nCreate a private group in Telegram. Name it something like \"K-Defender Security\".",
    "<b>K-Defender Setup — Step 2</b>\n\nAdd the K-Defender bot to the group (search @kdefender_bot).",
    "<b>K-Defender Setup — Step 4</b>\n\nSend the GROUP ID to me (paste the numeric ID here).\n\nIf you don't know how to get the GROUP ID, press the \"How to get group ID\" button.",
    "<b>K-Defender Setup — Step 5</b>\n\nAfter we have the GROUP ID: go to your protected bot and send in the group: <code>/connect</code>."
]

get_id_pages = [
    "<b>How to get Group ID — Step 1</b>\n\nOpen the group (on desktop or mobile).",
    "<b>How to get Group ID — Step 2</b>\n\nUse this bot (add it to group --&gt; write <code>/get_info</code> to it and it'll give chat info).",
    "<b>How to get Group ID — Step 3</b>\n\nYou can use info getting bots, but be careful!.",
    "<b>How to get Group ID — Final</b>\n\nGroup IDs for supergroups are usually negative numbers (e.g. -1001234567890). Paste that exact numeric ID to me."
]


def make_nav_kb(flow="setup", index=0):
    kb = []
    if flow == "setup":
        prev_data = f"setup_prev:{index}"
        next_data = f"setup_next:{index}"
        kb_row = []
        if index > 0:
            kb_row.append(InlineKeyboardButton(text="⬅ Prev", callback_data=prev_data))
        if index < len(setup_pages) - 1:
            kb_row.append(InlineKeyboardButton(text="Next ➡", callback_data=next_data))
        kb_row.append(InlineKeyboardButton(text="How to get group ID", callback_data="open_getid:0"))
        kb.append(kb_row)
        kb.append([InlineKeyboardButton(text="Cancel", callback_data="cancel_setup")])
    else:  # getid flow
        prev_data = f"getid_prev:{index}"
        next_data = f"getid_next:{index}"
        kb_row = []
        if index > 0:
            kb_row.append(InlineKeyboardButton(text="⬅ Prev", callback_data=prev_data))
        if index < len(get_id_pages) - 1:
            kb_row.append(InlineKeyboardButton(text="Next ➡", callback_data=next_data))
        kb_row.append(InlineKeyboardButton(text="Back to Setup", callback_data="open_setup:3"))
        kb.append(kb_row)
    return InlineKeyboardMarkup(inline_keyboard=kb)


# ============================================================
# ================= BOT API HANDLERS =========================
# ============================================================

async def edit_msg(msg: Message, text: str, reply_markup=None, parse_mode=ParseMode.HTML):
    await msg.edit_text(text, reply_markup=reply_markup, parse_mode=parse_mode)


@dp.message(Command("start"))
async def start_cmd(msg: Message):
    user_id = msg.from_user.id
    is_new = str(user_id) not in state
    ensure_user(user_id)
    save_state()

    if is_new:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="➕ Start binding", callback_data="bind_start")]
        ])
        await msg.answer(
            "<b>K-Defender Activated</b>\n\n"
            f"Welcome to K-Defender, {msg.from_user.first_name}!\n"
            "Here you can connect your bot and see what was blocked or allowed.\n"
            "Press the button below to connect your bot.",
            reply_markup=kb
        )
    else:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="Menu", callback_data="menu")]
        ])
        await msg.answer(
            f"Welcome back, {msg.from_user.first_name}!",
            reply_markup=kb
        )


@dp.message(Command("menu"))
async def menu_cmd_handler(msg: Message):
    msg = await msg.answer("Loading...")
    await menu_cmd(msg)


@dp.callback_query(F.data == "menu")
async def menu_callback_handler(call: CallbackQuery):
    await menu_cmd(call.message)


async def menu_cmd(msg: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📦 My bots", callback_data="bots_info")],
        [InlineKeyboardButton(text="📊 Stats", callback_data="stats")],
        [InlineKeyboardButton(text="🧾 Recent activity", callback_data="activity")],
        [InlineKeyboardButton(text="⚙️ Settings", callback_data="settings")],
        [InlineKeyboardButton(text="❓ Help", callback_data="help")],
    ])

    await edit_msg(
        msg,
        "<code>Menu</code>",
        reply_markup=kb
    )


@dp.callback_query(F.data == "stats")
async def stats_panel(call: CallbackQuery):
    user = str(call.from_user.id)
    ensure_user(user)
    bots = real_bots_dict(user)

    total_bots = len(bots)
    total_msgs = 0
    total_blocked = 0
    for b in bots.values():
        total_msgs += int(b.get("stats_total", 0))
        total_blocked += int(b.get("stats_blocked", 0))

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⬅ Back", callback_data="menu")]
    ])

    await call.message.edit_text(
        "<b>📊 Stats</b>\n\n"
        f"Protected bots: <b>{total_bots}</b>\n"
        f"Checked messages: <b>{total_msgs}</b>\n"
        f"Blocked messages: <b>{total_blocked}</b>\n\n"
        "Tip: open <b>My bots</b> to see per-bot details.",
        reply_markup=kb,
        parse_mode=ParseMode.HTML
    )


@dp.callback_query(F.data == "activity")
async def activity_panel(call: CallbackQuery):
    user = str(call.from_user.id)
    ensure_user(user)
    bots = real_bots_dict(user)

    items = []
    for b in bots.values():
        name = b.get("bot_username", "unknown")
        for t in (b.get("logs") or [])[-20:]:
            items.append((name, t))

    items = items[-15:]
    if not items:
        text = "<b>🧾 Recent activity</b>\n\nNo messages checked yet."
    else:
        lines = []
        for name, t in items:
            short = (t[:80] + "…") if len(t) > 80 else t
            lines.append(f"• <code>@{name}</code>: {html.escape(short)}")
        text = "<b>🧾 Recent activity</b>\n\nText|Normalized|Score|Reason\n" + "\n".join(lines)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⬅ Back", callback_data="menu")]
    ])

    await call.message.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)


@dp.message(Command("help"))
async def help_cmd_handler(msg: Message):
    msg = await msg.answer("Loading...")
    await help_cmd(msg)


@dp.callback_query(F.data == "help")
async def help_callback_handler(call: CallbackQuery):
    await help_cmd(call.message)


async def help_cmd(msg: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⬅ Back", callback_data="menu")]
    ])
    await edit_msg(
        msg,
        "<code>Help</code>\n\n"
        "<b>❓ Help</b>\n\n"
        "K-Defender protects your bot from suspicious messages.\n\n"
        "<b>What you can do here:</b>\n"
        "• <b>My bots</b> — see your protected bots\n"
        "• <b>Stats</b> — how many messages were checked/blocked\n"
        "• <b>Recent activity</b> — latest checked messages\n"
        "• <b>Settings</b> — turn protection types on/off\n\n"
        "Commands:\n"
        "• <code>/start</code> — start or restart the bot\n"
        "• <code>/menu</code> — open the main menu\n"
        "• <code>/get_info</code> — get info about a chat\n"
        "• <code>/help</code> — show this help message\n",
        reply_markup=kb
    )


def _onoff(v: bool) -> str:
    return "✅ ON" if v else "❌ OFF"


def _mode_label(mode: str) -> str:
    return {
        "normal": "Normal",
        "allow_all": "Allow All (pause protection)",
        "block_all": "Block All (lockdown)",
    }.get(mode, mode)


def settings_kb(user_id: int) -> InlineKeyboardMarkup:
    st = get_user_settings(user_id)

    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"🛡️ Protection: {_onoff(st['enabled'])}", callback_data="set:enabled")],
        [InlineKeyboardButton(text=f"⚡ Strict mode: {_onoff(st['strict'])}", callback_data="set:strict")],
        [InlineKeyboardButton(text=f"🧯 Mode: {_mode_label(st['mode'])}", callback_data="set:mode")],
        [InlineKeyboardButton(text="⬅ Back", callback_data="menu")]
    ])


def settings_text(user_id: int) -> str:
    st = get_user_settings(user_id)

    if not st["enabled"]:
        status = "🔴 Protection is OFF"
    elif st["mode"] == "allow_all":
        status = "🟡 Protection paused (Allow All)"
    elif st["mode"] == "block_all":
        status = "🔴 Lockdown (Block All)"
    else:
        status = "🟢 Protection active"

    return (
        "<b>⚙️ Settings</b>\n\n"
        f"<b>Status:</b> {status}\n\n"
        "Use buttons to change behavior.\n"
        "• <b>Strict mode</b>: blocks more suspicious messages\n"
        "• <b>Mode</b>: emergency switch\n"
    )


@dp.callback_query(F.data == "settings")
async def settings_callback_handler(call: CallbackQuery):
    uid = call.from_user.id
    await call.message.edit_text(
        settings_text(uid),
        parse_mode=ParseMode.HTML,
        reply_markup=settings_kb(uid),
        disable_web_page_preview=True
    )
    await call.answer()


@dp.callback_query(F.data.startswith("set:"))
async def settings_click(call: CallbackQuery):
    uid = call.from_user.id
    st = get_user_settings(uid)
    action = call.data.split(":", 1)[1]

    if action == "enabled":
        st["enabled"] = not st["enabled"]

    elif action == "strict":
        st["strict"] = not st["strict"]

    elif action == "mode":
        order = ["normal", "allow_all", "block_all"]
        st["mode"] = order[(order.index(st["mode"]) + 1) % len(order)]

    save_state()

    await call.message.edit_text(
        settings_text(uid),
        parse_mode=ParseMode.HTML,
        reply_markup=settings_kb(uid),
        disable_web_page_preview=True
    )
    await call.answer("Saved ✅")


@dp.message(Command("get_info"))
async def get_info_cmd(msg: types.Message):
    if msg.reply_to_message:
        u = msg.reply_to_message.from_user
        await msg.answer(
            f"""<code>Info</code>
<b>User / Bot</b>
 ├ id: <code>{u.id}</code>
 ├ username: {f'@{u.username}' if u.username else 'N/A'}
 ├ first_name: {u.first_name or 'N/A'}
 ├ last_name: {u.last_name or 'N/A'}
 └ is_bot: {u.is_bot}"""
        )
        return

    c = msg.chat
    await msg.answer(
        f"""<code>Info</code>
<b>This Chat</b>
 ├ id: <code>{c.id}</code>
 ├ title: {c.title or 'N/A'}
 └ type: {c.type}"""
    )


@dp.callback_query(F.data == "bots_info")
async def bots_info(call: CallbackQuery):
    ensure_user(call.from_user.id)

    btn_arr = []
    for bot_id, data in real_bots_dict(call.from_user.id).items():
        uname = data.get("bot_username")
        if not uname:
            continue
        btn_arr.append(
            InlineKeyboardButton(
                text=f"@{uname}",
                callback_data=f"bot_{uname}"
            )
        )

    rows = []
    if btn_arr:
        rows.append(btn_arr)

    rows.append([InlineKeyboardButton(text="Add Bot", callback_data="bind_start")])
    rows.append([InlineKeyboardButton(text="⬅ Back", callback_data="menu")])

    kb = InlineKeyboardMarkup(inline_keyboard=rows)
    message = "\nNo bots connected. Add one by pressing the button below." if not btn_arr else ""

    await call.message.edit_text(
        f"<code>Bots Info</code>{message}",
        reply_markup=kb
    )


@dp.callback_query(F.data.startswith("botset_"))
async def bot_settings_toggle(call: CallbackQuery):
    global DEFAULT_BOT_SETTINGS
    bot_username, setting = call.data.split(":")
    bot_username = '_'.join(bot_username.split("_")[1:])

    # Find bot record by username (skip draft)
    for bid, b in real_bots_dict(call.from_user.id).items():
        if b.get("bot_username") == bot_username:
            st = b.setdefault("settings", {})
            for k, v in DEFAULT_BOT_SETTINGS.items():
                st.setdefault(k, v)

            st[setting] = not st.get(setting, False)

            save_state()
            await call.answer(f"{setting.upper()} → {'ON' if st[setting] else 'OFF'}", show_alert=False)
            return await show_bot_panel(call.message, b, bid)

    await call.answer("Bot not found", show_alert=True)


@dp.callback_query(F.data.startswith("botlogs_"))
async def bot_show_logs(call: CallbackQuery):
    bot_username = '_'.join(call.data.split("_")[1:])

    b = None
    bid = None
    for _bid, data in real_bots_dict(call.from_user.id).items():
        if data.get("bot_username") == bot_username:
            b = data
            bid = _bid
            break

    if not b:
        return await call.answer("Bot not found", show_alert=True)

    global logs_num
    logs = b.get("logs", [])[-logs_num:]
    if not logs:
        text = f"<b>@{bot_username} — No logs yet.</b>"
    else:
        text = f"<b>Last {logs_num} messages:</b>\n\n"
        for item in logs:
            text += f"• <code>{html.escape(item)}</code>\n"

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⬅ Back", callback_data=f"botstats_{bot_username}")]
    ])

    await call.message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)


def get_bot_stats(user_id, bot_username):
    b = None
    for _, data in real_bots_dict(user_id).items():
        if data.get("bot_username") == bot_username:
            b = data
            break

    if not b:
        return "Not found"

    total = int(b.get("stats_total", 0))
    blocked = int(b.get("stats_blocked", 0))
    allowed = max(total - blocked, 0)

    blocked_pct = int((blocked / total) * 100) if total else 0
    allowed_pct = 100 - blocked_pct if total else 0

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "blocked_pct": blocked_pct,
        "allowed_pct": allowed_pct,
    }


def make_bar(label: str, percent: int, size: int = 12):
    filled = int((percent / 100) * size)
    empty = size - filled
    return f"{label} [{'█' * filled}{'░' * empty}] {percent}%"


def bot_stats_text(user_id, bot_username):
    b = None
    for _, data in real_bots_dict(user_id).items():
        if data.get("bot_username") == bot_username:
            b = data
            break

    if not b:
        return "Not found"

    stats = get_bot_stats(user_id, bot_username)
    if stats == "Not found":
        return "Not found"

    diagram = (
        make_bar("Allowed ", stats["allowed_pct"]) + "\n" +
        make_bar("Blocked ", stats["blocked_pct"])
    )

    return (
        f"📊 <b>Bot statistics</b>\n\n"
        f"🤖 Bot: <code>@{b['bot_username']}</code>\n\n"
        f"📨 Messages checked: <b>{stats['total']}</b>\n"
        f"✅ Allowed: <b>{stats['allowed']}</b>\n"
        f"🚫 Blocked: <b>{stats['blocked']}</b>\n\n"
        f"<b>Activity diagram</b>\n"
        f"<pre>{diagram}</pre>\n\n"
        f"ℹ️ <i>Blocked messages were detected as suspicious.\n"
        f"Allowed messages passed security checks.</i>"
    )


@dp.callback_query(F.data.startswith("botstats_"))
async def bot_stats_handler(call: CallbackQuery):
    user_id = call.from_user.id
    bot_username = call.data.split("_", 1)[1]

    text = bot_stats_text(user_id, bot_username)

    if text == "Not found":
        return await call.answer("Bot not found", show_alert=True)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🧾 View logs", callback_data=f"botlogs_{bot_username}")],
        [InlineKeyboardButton(text="⬅ Back to bot", callback_data=f"bot_{bot_username}")]
    ])

    await call.message.edit_text(
        text,
        parse_mode="HTML",
        reply_markup=kb
    )
    await call.answer()


def delete_bot(user_id, bot_id):
    u = state.get(str(user_id))
    if not u:
        return False
    bots = u.get("bots", {})
    if str(bot_id) == DRAFT_BOT_KEY:
        return False
    bots.pop(str(bot_id), None)
    save_state()
    return True


async def show_bot_panel(msg, bot_state, bot_id):
    global DEFAULT_BOT_SETTINGS
    bot_username = bot_state.get("bot_username") or "unknown"
    settings = bot_state.setdefault("settings", {})
    for k, v in DEFAULT_BOT_SETTINGS.items():
        settings.setdefault(k, v)

    total = bot_state.get("stats_total", 0)
    blocked = bot_state.get("stats_blocked", 0)
    allowed = total - blocked

    text = (
        f"<b>Bot: @{bot_username}</b>\n"
        f"ID: <code>{bot_id}</code>\n\n"
        f"<b>Statistics:</b>\n"
        f"• Total messages: <b>{total}</b>\n"
        f"• Allowed: <b>{allowed}</b>\n"
        f"• Blocked: <b>{blocked}</b>\n\n"
        f"<b>WAF Settings:</b>"
    )

    inj_arr = []
    for inj in settings.keys():
        inj_arr.append([
            InlineKeyboardButton(
                text=f"{inj}: {'🟢 ON' if settings.get(inj, False) else '🔴 OFF'}",
                callback_data=f"botset_{bot_username}:{inj}"
            )
        ])
    inj_arr.append([
        InlineKeyboardButton(
            text="📊 Statistics",
            callback_data=f"botstats_{bot_username}"
        )
    ])
    inj_arr.append([
        InlineKeyboardButton(
            text="🔁 Reset access token",
            callback_data=f"botresettoken_{bot_id}|{bot_username}"
        )
    ])

    inj_arr.append([
        InlineKeyboardButton(
            text="🗑 Delete bot",
            callback_data=f"botdelete_{bot_id}|{bot_username}"
        )
    ])

    inj_arr.append([
        InlineKeyboardButton(
            text="⬅ Back",
            callback_data="bots_info"
        )
    ])
    kb = InlineKeyboardMarkup(inline_keyboard=inj_arr)

    await msg.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)


@dp.callback_query(F.data.startswith("botresettoken_"))
async def bot_reset_token_confirm(call: CallbackQuery):
    bot_info = ''.join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Yes, reset", callback_data=f"botresettokenyes_{bot_id}|{bot_username}"),
            InlineKeyboardButton(text="❌ Cancel", callback_data=f"bot_{bot_username}")
        ]
    ])

    await call.message.edit_text(
        "<b>🔁 Reset access token?</b>\n\n"
        "This will immediately disable the current token.\n\n"
        "Your protected bot will stop receiving messages until you "
        "update the new token in its <code>.env</code> file and restart it.\n\n"
        "Are you sure?",
        reply_markup=kb,
        parse_mode="HTML"
    )
    await call.answer()


@dp.callback_query(F.data.startswith("botresettokenyes_"))
async def bot_reset_token_apply(call: CallbackQuery):
    user_id = call.from_user.id
    bot_info = ''.join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    try:
        new_token = reset_bot_token(user_id, bot_id)
    except Exception:
        await call.answer("Failed to reset token", show_alert=True)
        return

    await call.message.edit_text(
        "<b>✅ Token reset successful</b>\n\n"
        "Here is your new access token:\n"
        f"<code>{new_token}</code>\n\n"
        "<b>What to do next:</b>\n"
        "1) Open your protected bot project\n"
        "2) Replace <code>CHAT_TOKEN</code> in <code>.env</code>\n"
        "3) Restart the bot\n\n"
        "The old token no longer works.",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⬅ Back to bot", callback_data=f"bot_{bot_username}")]
        ])
    )
    await call.answer("Token reset")


@dp.callback_query(F.data.startswith("botdelete_"))
async def bot_delete_confirm(call: CallbackQuery):
    bot_info = ''.join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Yes, delete", callback_data=f"botdeleteyes_{bot_id}|{bot_username}"),
            InlineKeyboardButton(text="❌ Cancel", callback_data=f"bot_{bot_username}")
        ]
    ])

    await call.message.edit_text(
        "<b>🗑 Delete bot?</b>\n\n"
        "This will immediately delete this bot from protection.\n\n"
        "Rewrite (delete <code>setup()</code> and <code>close()</code> lines and wrappers -- <code>@kdefender_check()</code>) and restart your bot.\n"
        "K-Defender protection will be deleted for it.\n\n"
        "Are you sure?",
        reply_markup=kb,
        parse_mode="HTML"
    )
    await call.answer()


@dp.callback_query(F.data.startswith("botdeleteyes_"))
async def bot_delete_apply(call: CallbackQuery):
    user_id = call.from_user.id
    bot_info = ''.join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]

    try:
        delete_bot(user_id, bot_id)
    except Exception:
        await call.answer("Failed to delete bot", show_alert=True)
        return

    await call.message.edit_text(
        "<b>✅ Bot deleted successfully</b>\n\n"
        "Again, rewrite and restart your bot.",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⬅ Back", callback_data=f"bots_info")]
        ])
    )
    await call.answer("Bot deleted")


@dp.callback_query(F.data.startswith("bot_"))
async def bot_info(call: CallbackQuery):
    bot_username = '_'.join(call.data.split("_")[1:])
    bot_state = None
    bot_id = None

    for bid, b in real_bots_dict(call.from_user.id).items():
        if b.get("bot_username") == bot_username:
            bot_state = b
            bot_id = bid
            break

    if not bot_state:
        return await call.answer("Bot not found", show_alert=True)

    return await show_bot_panel(call.message, bot_state, bot_id)


@dp.callback_query(F.data == "bind_start")
async def bind_start(call: CallbackQuery):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=True)
    nb["step"] = 2
    nb["instr_page"] = 0
    nb["verified"] = False
    save_state()

    await call.message.edit_text(
        setup_pages[0],
        reply_markup=make_nav_kb("setup", 0),
        parse_mode=ParseMode.HTML
    )


@dp.callback_query(
    F.data.in_(["open_getid:0", "cancel_setup"]) |
    F.data.startswith(("setup_next:", "setup_prev:", "open_setup:"))
)
async def setup_nav(call: CallbackQuery):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=False)
    data = call.data

    if data == "cancel_setup":
        drop_draft(uid)
        save_state()
        await call.message.edit_text("Setup cancelled. Send /start to begin again.")
        return

    if data.startswith("open_setup:"):
        idx = int(data.split(":", 1)[1])
        nb["instr_page"] = idx
        save_state()
        await call.message.edit_text(
            setup_pages[idx],
            reply_markup=make_nav_kb("setup", idx),
            parse_mode=ParseMode.HTML
        )
        return

    if data == "open_getid:0":
        nb["instr_page"] = 0
        save_state()
        await call.message.edit_text(
            get_id_pages[0],
            reply_markup=make_nav_kb("getid", 0),
            parse_mode=ParseMode.HTML
        )
        return

    kind, raw = data.split(":", 1)
    idx = int(raw)
    if kind == "setup_next":
        idx = min(idx + 1, len(setup_pages) - 1)
    elif kind == "setup_prev":
        idx = max(idx - 1, 0)

    nb["instr_page"] = idx
    save_state()
    await call.message.edit_text(
        setup_pages[idx],
        reply_markup=make_nav_kb("setup", idx),
        parse_mode=ParseMode.HTML
    )


@dp.callback_query(F.data.startswith(("getid_next:", "getid_prev:")))
async def getid_nav(call: CallbackQuery):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=False)

    kind, raw = call.data.split(":", 1)
    idx = int(raw)
    if kind == "getid_next":
        idx = min(idx + 1, len(get_id_pages) - 1)
    elif kind == "getid_prev":
        idx = max(idx - 1, 0)

    nb["instr_page"] = idx
    save_state()
    await call.message.edit_text(
        get_id_pages[idx],
        reply_markup=make_nav_kb("getid", idx),
        parse_mode=ParseMode.HTML
    )


# ---------------- Receive GROUP ID from user (private chat) ----------------
@dp.message(F.chat.type == "private")
async def private_msg_handler(msg: Message):
    uid = msg.from_user.id
    bots = bots_of(uid)
    nb = bots.get(DRAFT_BOT_KEY)
    if not nb:
        return

    text = (msg.text or "").strip()

    if nb.get("step") == 2:
        try:
            gid = int(text)
        except:
            await msg.answer(
                "Please paste the numeric GROUP ID (e.g. -1001234567890) or use the setup buttons to learn how to get it."
            )
            return

        nb["pending_group_id"] = gid
        nb["step"] = 3
        save_state()
        await msg.answer(
            f"✅ Group ID saved: <code>{html.escape(str(gid))}</code>\n\n"
            "Now, in that group, send the following command:\n\n"
            "<code>/connect</code>\n\n"
            "When K-Defender sees <code>/connect</code> in that group, it will reply with the next steps.",
            parse_mode=ParseMode.HTML
        )
        return


# -- Group messages handler (bot API) --
@dp.message(
    F.chat.type.in_({"group", "supergroup"}),
    F.content_type == ContentType.TEXT
)
async def group_handler(msg: Message):
    chat_id = msg.chat.id
    me = await bot.get_me()
    if msg.from_user.id == me.id:
        return

    text = (msg.text or "").strip()

    for user_id, s in list(state.items()):
        ensure_user(user_id)
        bots = s.get("bots") or {}

        nb = bots.get(DRAFT_BOT_KEY)
        if nb:
            step = int(nb.get("step", 0))
            pending_gid = int(nb.get("pending_group_id", 0) or 0)

            if step == 3 and pending_gid and int(pending_gid) == int(chat_id):
                if text == "/connect":
                    nb["step"] = 4
                    save_state()
                    await msg.reply(
                        "✅ <b>K-Defender received /connect</b>\n\n"
                        "Now send: <code>/connect_bot BOT_ID @bot_username</code>.\n"
                        "Can get them by adding the bot (that will be protected) to the same group (K-Defender will automatically give needed info about it).\n",
                        parse_mode=ParseMode.HTML
                    )
                continue

            if step == 4 and text.startswith("/connect_bot"):
                del_cmd = text[len("/connect_bot"):].strip()
                parts = del_cmd.split()
                if len(parts) < 2:
                    await msg.reply("❗ Format: <code>/connect_bot BOT_ID @bot_username</code>", parse_mode=ParseMode.HTML)
                    continue

                bot_id, bot_username = parts[0], parts[1]
                if not bot_username.startswith("@"):
                    await msg.reply(
                        f"❗ Bot username '{html.escape(bot_username)}' must be like: @Username_bot!",
                        parse_mode=ParseMode.HTML
                    )
                    continue

                try:
                    bot_id_int = int(bot_id)
                except ValueError:
                    await msg.reply(f"❗ Bot_id '{html.escape(bot_id)}' must be a number!", parse_mode=ParseMode.HTML)
                    continue

                bot_username_clean = bot_username[1:]  # without @

                if str(bot_id_int) in bots and str(bot_id_int) != DRAFT_BOT_KEY:
                    await bot.send_message(
                        int(user_id),
                        f"❗ User/bot {msg.from_user.username} is trying to reconnect bot '{bot_username_clean}'({bot_id_int}) in chat '{chat_id}'"
                    )
                    continue

                bot_st = ensure_bot(user_id, bot_id_int)

                bot_st["group_id"] = int(chat_id)
                bot_st["bot_username"] = bot_username_clean

                token = generate_bot_token(bot_username_clean)
                bot_st["bot_token"] = token

                bot_st["step"] = 5
                bot_st["verified"] = True
                bot_st["instr_page"] = int(nb.get("instr_page", 1))

                if isinstance(nb.get("settings"), dict) and nb["settings"]:
                    bot_st.setdefault("settings", {})
                    for k, v in nb["settings"].items():
                        bot_st["settings"][k] = v

                # cleanup draft
                bots.pop(DRAFT_BOT_KEY, None)

                pages = build_protected_bot_pages(
                    group_id=chat_id,
                    chat_token=token,
                    kdefender_id=k_defender_id,
                    protected_username=bot_st["bot_username"]
                )
                bot_st["protected_wizard"] = {"index": 0, "pages": pages}

                save_state()

                await msg.reply(
                    f"🎉 <b>Connection successful!</b> 🎉\n"
                    f"Protected bot: <code>@{bot_st['bot_username']}</code>\n"
                    f"Token for sending messages: <code>{token}</code>\n\n"
                    f"📩 I’m sending setup instructions to the owner in DM.",
                    parse_mode=ParseMode.HTML
                )

                owner_id = int(user_id)

                await bot.send_message(
                    owner_id,
                    pages[0],
                    parse_mode=ParseMode.HTML,
                    reply_markup=make_protected_wiz_kb(bot_id_int, 0, len(pages)),
                    disable_web_page_preview=True
                )
                continue

        # ---- PAYLOAD CHECK: "bot_id | text | token" ----
        if '|' not in text:
            continue

        arr = text.split('|')
        if len(arr) < 3:
            continue

        bot_id_str = arr[0].strip()
        payload_token = arr[-1].strip()
        message_text = '|'.join(arr[1:-1]).strip()

        user_bot = bots.get(str(bot_id_str))
        if not user_bot or str(bot_id_str) == DRAFT_BOT_KEY:
            continue

        if not user_bot.get("verified", False):
            continue

        if int(user_bot.get("group_id", 0) or 0) != int(chat_id):
            continue

        real_token = user_bot.get("bot_token")

        if not payload_token:
            await msg.reply("⚠ No token provided! ⚠")
            return

        if payload_token != real_token:
            message = f"⚠ INVALID TOKEN attempt (got={payload_token}) ⚠"
            await msg.reply(message)
            await bot.send_message(int(user_id), message)
            user_bot.setdefault("logs", []).append(message)
            user_bot["stats_blocked"] = user_bot.get("stats_blocked", 0) + 1
            user_bot["stats_total"] = user_bot.get("stats_total", 0) + 1
            save_state()
            return

        normal = normalize_input(message_text)

        user_st = get_user_settings(int(user_id))
        bot_st_settings = get_bot_settings(int(user_id), str(bot_id_str))

        threshold = 30 if user_st["strict"] else 50
        check_msg = True

        if not user_st["enabled"]:
            check_msg = False
            score = 0
            reason_str = "Protection disabled"
            result_json = {"result": "ok"}

        if user_st["mode"] == "allow_all":
            check_msg = False
            score = 0
            reason_str = "All messages are allowed"
            result_json = {"result": "ok"}

        if user_st["mode"] == "block_all":
            check_msg = False
            score = 100
            reason_str = "All messages are blocked"
            result_json = {"result": "blocked"}

        global DEFAULT_BOT_SETTINGS
        botname = user_bot.get("bot_username", "unknown")
        settings = user_bot.setdefault("settings", {})
        for k, v in DEFAULT_BOT_SETTINGS.items():
            settings.setdefault(k, v)

        if check_msg:
            inj_report_arr = {}
            for inj in settings.keys():
                inj_report_arr[inj] = detect_inj(normal, inj, s, str(bot_id_str))

            for inj in settings.keys():
                if not settings[inj]:
                    inj_report_arr[inj] = False

            score = get_risk_score(inj_report_arr)
            result_json = {"result": "ok"} if score < threshold else {"result": "blocked"}
            reason = [inj for inj, hit in inj_report_arr.items() if hit]
            reason_str = ", ".join(reason)

        # logs
        global logs_num_save
        user_bot.setdefault("logs", []).append(f"{message_text}|{normal}|{score}|{reason_str}")
        user_bot["logs"] = user_bot["logs"][-logs_num_save:]

        # stats
        user_bot["stats_total"] = user_bot.get("stats_total", 0) + 1
        if score >= threshold:
            user_bot["stats_blocked"] = user_bot.get("stats_blocked", 0) + 1

        save_state()

        await msg.answer(json.dumps(result_json))
        if score >= threshold:
            await bot.send_message(
                int(user_id),
                f"@{botname} ❌ Blocked\n"
                f"Reason: {reason_str}\nMessage: <code>{html.escape(message_text)}</code>\n"
                f"Normalized message: <code>{html.escape(normal)}</code>",
                parse_mode=ParseMode.HTML
            )


def build_protected_bot_pages(group_id: int, chat_token: str, kdefender_id: int, protected_username: str):
    return [
        (
            "✅ <b>Protected bot connected!</b>\n\n"
            f"Bot: <code>@{protected_username}</code>\n"
            f"GROUP_ID: <code>{group_id}</code>\n"
            f"CHAT_TOKEN: <code>{chat_token}</code>\n\n"
        ),
        (
            "📦 <b>Step 1 — Install wrapper</b>\n\n"
            "Run in your protected bot project:\n"
            "<pre>pip install kdefender-wrapper telethon</pre>\n\n"
            "Optional (for .env autoload):\n"
            "<pre>pip install python-dotenv</pre>"
        ),
        (
            "🧾 <b>Step 2 — Create .env</b>\n\n"
            "Create <code>.env</code> in protected bot folder:\n"
            f"<pre>"
            f"API_ID=YOUR_API_ID\n"
            f"API_HASH=YOUR_API_HASH\n"
            f"TELETHON_SESSION=YOUR_SESSION_STRING\n"
            f"GROUP_ID={group_id}\n"
            f"CHAT_TOKEN={chat_token}\n"
            f"K_DEFENDER_ID={kdefender_id}\n"
            f"</pre>\n\n"
            "Get API keys here:\n"
            "<code>https://my.telegram.org/apps</code>"
        ),
        (
            "🔐 <b>Step 3 — Generate TELETHON_SESSION</b>\n\n"
            "Create <code>gen_session.py</code> and run once:\n"
            "<pre>"
            "from telethon import TelegramClient\n"
            "from telethon.sessions import StringSession\n\n"
            "API_ID = int(input('API_ID: '))\n"
            "API_HASH = input('API_HASH: ')\n"
            "session = StringSession()\n\n"
            "with TelegramClient(session, API_ID, API_HASH) as client:\n"
            "    print('\\nTELETHON_SESSION=')\n"
            "    print(session.save())\n"
            "</pre>\n\n"
            "Copy the output into <code>.env</code> as TELETHON_SESSION."
        ),
        (
            "🧩 <b>Step 4 — Use wrapper in your bot</b>\n\n"
            "Minimal example (aiogram v3):\n"
            "<pre>"
            "import os, asyncio\n"
            "from dotenv import load_dotenv\n"
            "from aiogram import Bot, Dispatcher\n"
            "from aiogram.types import Message\n"
            "from kdefender_wrapper import setup, close, kdefender_check\n\n"
            "# requires python-dotenv module\n"
            "load_dotenv()\n"
            "TOKEN = os.getenv('TOKEN')  # your bot token\n"
            "bot = Bot(TOKEN)\n"
            "dp = Dispatcher()\n\n"
            "API_ID = int(os.getenv('API_ID'))\n"
            "API_HASH = os.getenv('API_HASH')\n"
            "SESSION = os.getenv('TELETHON_SESSION')\n"
            "GROUP_ID = int(os.getenv('GROUP_ID'))\n"
            "CHAT_TOKEN = os.getenv('CHAT_TOKEN')\n"
            "K_DEFENDER_ID = int(os.getenv('K_DEFENDER_ID'))\n\n"
            "@dp.message()\n"
            "@kdefender_check()\n"
            "async def handler(message: Message):\n"
            "    await message.answer('OK (passed K-Defender)')\n\n"
            "async def main():\n"
            "    try:\n"
            "        await setup(bot, API_ID, API_HASH, SESSION, GROUP_ID, CHAT_TOKEN, K_DEFENDER_ID)\n"
            "        await dp.start_polling(bot, polling_timeout=60)\n"
            "    finally:\n"
            "        await close()\n"
            "        await bot.session.close()\n\n"
            "if __name__ == '__main__':\n"
            "    asyncio.run(main())\n"
            "</pre>"
        ),
        (
            "🧪 <b>Step 5 — Quick test</b>\n\n"
            "1) Run your protected bot\n"
            "2) Send normal text → should pass\n"
            "3) Send suspicious payload (SQLi/XSS) → should be blocked\n\n"
            "<b>How it works:</b>\n"
            "• bot sends message to defender group with <code>id | text | token</code> using MTProto\n"
            "• K-Defender replies JSON: <code>{\"result\":\"ok\"}</code> or <code>{\"result\":\"blocked\"}</code>\n"
            "• wrapper allows/blocks handler execution"
        ),
    ]


def make_protected_wiz_kb(bot_id: int, index: int, total: int):
    row = []
    if index > 0:
        row.append(InlineKeyboardButton(text="⬅ Prev", callback_data=f"pw_prev:{bot_id}:{index}"))
    if index < total - 1:
        row.append(InlineKeyboardButton(text="Next ➡", callback_data=f"pw_next:{bot_id}:{index}"))

    kb = []
    if row:
        kb.append(row)
    kb.append([InlineKeyboardButton(text="❌ Close", callback_data=f"pw_close:{bot_id}")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


@dp.callback_query(F.data.startswith(("pw_next:", "pw_prev:", "pw_close:")))
async def protected_wizard_nav(call: CallbackQuery):
    uid = call.from_user.id
    ensure_user(uid)

    if call.data.startswith("pw_close:"):
        try:
            await call.message.delete()
        except Exception:
            pass
        await call.answer("Closed.")
        return

    # pw_next:<bot_id>:<idx>  / pw_prev:<bot_id>:<idx>
    kind, bot_id_s, raw = call.data.split(":", 2)
    idx = int(raw)

    b = bots_of(uid).get(str(bot_id_s))
    if not b or not b.get("protected_wizard"):
        await call.answer("Wizard expired. Re-connect if needed.", show_alert=True)
        return

    wiz = b["protected_wizard"]
    pages = wiz.get("pages") or []
    if not pages:
        await call.answer("Wizard empty.", show_alert=True)
        return

    if kind == "pw_next":
        idx = min(idx + 1, len(pages) - 1)
    else:
        idx = max(idx - 1, 0)

    wiz["index"] = idx
    save_state()

    await call.message.edit_text(
        pages[idx],
        parse_mode=ParseMode.HTML,
        reply_markup=make_protected_wiz_kb(int(bot_id_s), idx, len(pages)),
        disable_web_page_preview=True
    )
    await call.answer()


def generate_bot_token(bot_username: str):
    random_part = secrets.token_hex(32)
    base = f"{bot_username}:{random_part}"
    token = hashlib.sha256(base.encode()).hexdigest()
    return token


def message_text_token_extract(text: str):
    if "__TOKEN__:" not in text:
        return None
    try:
        return text.split("__TOKEN__:", 1)[1].strip()
    except:
        return None


@dp.message(F.new_chat_members)
async def on_join(msg: types.Message):
    for m in msg.new_chat_members:
        if m.is_bot:
            await msg.answer(
                "New bot joined.\n"
                f"""<b>Bot Info</b>
 ├ id: <code>{m.id}</code>
 ├ username: {f'@{m.username}' if m.username else 'N/A'}
 ├ first_name: {m.first_name or 'N/A'}
 └ last_name: {m.last_name or 'N/A'}"""
            )


# ============================================================
# ======================= MAIN ===============================
# ============================================================
async def main():
    global k_defender_id
    me = await bot.get_me()
    k_defender_id = me.id
    print(f"K-Defender running as @{me.username} ({k_defender_id})")

    try:
        global _autosave_task
        _autosave_task = asyncio.create_task(autosave_loop())

        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot, polling_timeout=60)
    finally:
        if _autosave_task:
            _autosave_task.cancel()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("K-Defender stopped by user")
