from os import utime
import ipaddress
from flask import Flask, request, jsonify, abort
from core import *
from normalization import normalize_input
import time

app = Flask(__name__)
logs_num = 5000

TG_NETS = [
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("91.108.4.0/22"),
] # https://core.telegram.org/bots/webhooks <-- there are Telegram IPs

@app.route("/")
def index():
    return "ok"

def blocked(bot, text, normalized, reason, score, cur_time=None):
    if cur_time is None: cur_time = time.time()
    bot.setdefault("pending", {}).setdefault("alert", []).append({
        "text": text,
        "normal": normalized,
        "reason": reason,
        "score": score,
        "time": cur_time
    })
    save_json(STATE_FILE, state)


@app.route("/check/", methods=["POST"])
def check():
    global state
    state = load_json(STATE_FILE, state)

    data = request.get_json(force=True)

    bot_id = str(data.get("bot_id", ""))
    token = data.get("token", "")
    text = data.get("text", "")

    # === Find bot ===
    owner_id = None
    bot = None

    for uid, u in state.items():
        if bot_id in u.get("bots", {}):
            bot = u["bots"][bot_id]
            owner_id = uid
            break

    if not bot:
        return jsonify(result="blocked", score=100, reason=["BOT_NOT_FOUND"])

    # === Token check ===
    if token != bot.get("bot_token"):
        bot["stats_total"] += 1
        bot["stats_blocked"] += 1
        save_json(STATE_FILE, state)
        blocked(bot, text, "", ["INVALID_TOKEN"], 100)
        return jsonify(result="blocked", score=100, reason=["INVALID_TOKEN"])

    user = state[owner_id]
    user_settings = user["settings"]
    bot_settings = bot["settings"]

    normalized = normalize_input(text)

    # === Global modes ===
    if not user_settings.get("enabled", True):
        status, score, reason = "ok", 0, []

    elif user_settings.get("mode") == "allow_all":
        status, score, reason = "ok", 0, []

    elif user_settings.get("mode") == "block_all":
        status, score, reason = "blocked", 100, ["LOCKDOWN"]

    else:
        report = detect_injection(
            uid=owner_id,
            bot_id=bot_id,
            text=normalized
        )

        report = {
            k: v for k, v in report.items()
            if bot_settings.get(k, False)
        }

        score = get_risk_score(report)

        threshold = 30 if user_settings.get("strict") else 50
        reason = list(report.keys())

        status = "blocked" if score >= threshold else "ok"

    bot["stats_total"] += 1
    if status == "blocked":
        bot["stats_blocked"] += 1

    cur_time = time.time()

    bot.setdefault("logs", [])
    bot["logs"].append({
        "text": text,
        "normalized": normalized,
        "score": score,
        "reason": reason,
        "status": status,
        "time": cur_time
    })

    global logs_num
    bot["logs"] = bot["logs"][-logs_num:]

    save_json(STATE_FILE, state)

    if status == "blocked":
        blocked(bot, text, normalized, reason, score, cur_time)

    return jsonify(
        result=status,
        score=score,
        reason=reason
    )


@app.route("/status/", methods=["GET"])
def status():
    return jsonify(result="ok")

@app.route("/webhook/<secret>/", methods=["POST"])
def webhook(secret):
    update = request.get_json(force=True)
    global state
    state = load_json(STATE_FILE, state)
    for uid, user in state.items():
        for bot_id, bot in user.get("bots", {}).items():
            ip_str = request.headers.get("X-Real-IP", request.remote_addr or "")
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                abort(403)

            if (bot.get("webhook") == secret and 
            update.get("message", {}).get("chat", {}).get("id") == int(uid) and 
            update.get("message", {}).get("text", "") == f"/verify_webhook {secret}" and
            any(ip in net for net in TG_NETS) and 
             not bot.get("verified", False)):
                bot["verified"] = True
                bot.setdefault("pending", {}).setdefault("info", []).append({
                    "text": "Webhook verified"
                })
    save_json(STATE_FILE, state)
    return jsonify(result="ok")

if __name__ == "__main__":
    app.run("127.0.0.1", 8001)
