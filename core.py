import time
import json
import os
import hashlib
import secrets
import joblib
from collections import defaultdict

STATE_FILE = "state.json"
SIG_FILE = "signatures.json"
MODEL_FILE = "kdefender_ai.pkl"

# ================= SETTINGS =================

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
    "mode": "normal"
}

check = "hybrid" # file / ai / hybrid

# ================= LOADERS =================

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

state = load_json(STATE_FILE, {})
signatures = load_json(SIG_FILE, {})

# ================= MODEL LOAD =================
try:
    model = joblib.load(MODEL_FILE)
    print("[AI] Model loaded.")
except Exception as e:
    print(f"[AI] Could not load model: {e}")
    model = None

# ================= USER/BOT =================

def ensure_user(uid):
    u = state.setdefault(str(uid), {})
    u.setdefault("bots", {})
    u.setdefault("settings", DEFAULT_USER_SETTINGS.copy())
    return u

def ensure_bot(uid, bot_id):
    u = ensure_user(uid)
    b = u["bots"].setdefault(str(bot_id), {})
    b.setdefault("settings", DEFAULT_BOT_SETTINGS.copy())
    b.setdefault("stats_total", 0)
    b.setdefault("stats_blocked", 0)
    b.setdefault("logs", [])
    return b

def generate_bot_token(bot_username):
    return hashlib.sha256(
        f"{bot_username}:{secrets.token_hex(32)}".encode()
    ).hexdigest()

# ================= ANTIFLOOD =================

FLOOD_WINDOW = 5      # seconds
FLOOD_LIMIT = 6       # messages

def detect_flood(user_state, bot_id):
    now = time.time()
    flood = user_state.setdefault("Flood", defaultdict(list))
    logs = flood[bot_id]

    # очищаем старые
    logs[:] = [t for t in logs if now - t < FLOOD_WINDOW]
    logs.append(now)

    return len(logs) >= FLOOD_LIMIT

# ================= SIGNATURE DETECTION =================

def detect_signature(text):
    text_lower = text.lower()
    report = {}

    for inj, data in signatures.items():
        patterns = data.get("patterns", [])
        if not patterns:
            continue
        if any(p in text_lower for p in patterns):
            report[inj] = True

    return report

# ================= AI DETECTION =================

def detect_ai(text):
    if not model:
        return {}

    try:
        probs = model.predict_proba([text])[0]
        classes = model.classes_

        best_idx = probs.argmax()
        best_label = classes[best_idx]
        confidence = probs[best_idx]

        print(f"[AI] Text: {text}")
        print(f"[AI] Best label: {best_label}")
        print(f"[AI] Confidence: {confidence}")

        # если модель не уверена → считаем безопасным
        if best_label == "Safe":
            return {}

        if confidence < 0.80:   # ← вот ключевой момент
            return {}

        return {str(best_label): True}

    except Exception as e:
        print(f"[AI ERROR] {e}")
        return {}

# ================= RISK SCORE =================

def get_risk_score(report):
    score = 0
    for inj in report:
        score += signatures.get(inj, {}).get("risk", 0)
    return score

# ================= MAIN DETECTOR =================

def detect_injection(uid, bot_id, text):
    user = ensure_user(uid)
    bot = ensure_bot(uid, bot_id)

    if not user["settings"]["enabled"]:
        return {}

    final_report = {}

    # --- Flood ---
    if bot["settings"].get("Flood") and detect_flood(user, bot_id):
        final_report["Flood"] = True

    global check
    check_mode = check

    # --- Signature ---
    if check_mode in ["file", "hybrid"]:
        sig_report = detect_signature(text)
        final_report.update(sig_report)

    # --- AI ---
    if check_mode in ["ai", "hybrid"]:
        ai_report = detect_ai(text)
        final_report.update(ai_report)

    # --- Apply bot settings ---
    final_report = {
        k: v for k, v in final_report.items()
        if bot["settings"].get(k, False)
    }

    # --- Strict mode ---
    if user["settings"]["strict"] and final_report:
        bot["stats_blocked"] += 1
        bot["logs"].append({
            "text": text,
            "report": final_report,
            "time": time.time()
        })

    save_json(STATE_FILE, state)

    return final_report