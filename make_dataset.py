import json
import random
import re
import urllib.parse

random.seed()

# ================= CONFIG =================

SAFE_COMMANDS = [
    "/start", "/help", "/settings", "/stats",
    "/register", "/login", "/profile",
    "/search cats", "/echo hello", "/btn menu"
]

SAFE_CHAT = [
    "привет", "как дела", "что нового",
    "спасибо", "помоги пожалуйста",
    "где настройки", "как подключить бота",
    "всё работает", "не работает кнопка",
    "скинь ссылку", "дай инструкцию"
]

RANDOM_WORDS = [
    "cat", "dog", "user", "admin", "hello",
    "world", "config", "status", "menu"
]

# ================= HELPERS =================

def random_noise():
    if random.random() < 0.3:
        return f" #{random.randint(1,999)}"
    if random.random() < 0.3:
        return f" {random.choice(RANDOM_WORDS)}"
    return ""

def random_typo(s):
    if len(s) < 3:
        return s
    i = random.randint(0, len(s)-2)
    return s[:i] + s[i+1] + s[i] + s[i+2:]

def safe_samples(n=15000):
    data = []
    for _ in range(n):
        base = random.choice(SAFE_COMMANDS + SAFE_CHAT)
        if random.random() < 0.3:
            base = random_typo(base)
        base += random_noise()
        data.append((base, "Safe"))
    return data

# ================= INJECTION BUILDERS =================

def sqli_payload():
    templates = [
        "' OR 1=1 --",
        "' UNION SELECT password FROM users --",
        "'; DROP TABLE users; --",
        "admin' --",
        "1 OR 1=1",
        "' AND SLEEP(5) --"
    ]
    return random.choice(templates)

def xss_payload():
    templates = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>"
    ]
    return random.choice(templates)

def cmd_payload():
    templates = [
        "&& whoami",
        "; rm -rf /",
        "| id",
        "|| ls -la",
        "$(cat /etc/passwd)"
    ]
    return random.choice(templates)

def markdown_payload():
    templates = [
        "`rm -rf /`",
        "```bash\nls\n```",
        "[click](javascript:alert(1))"
    ]
    return random.choice(templates)

def entity_payload():
    templates = [
        "token=abc123",
        "chat_id=999999",
        "file://etc/passwd",
        "data:text/html;base64,PHNjcmlwdD4="
    ]
    return random.choice(templates)

INJ_BUILDERS = {
    "SQLi": sqli_payload,
    "XSS": xss_payload,
    "Bot_command_injection": cmd_payload,
    "Markdown_injection": markdown_payload,
    "Entity_manipulation": entity_payload
}

def wrap_payload(p):
    wrappers = [
        f"q={p}",
        f"search={p}",
        f"id={p}",
        f"text={p}",
        f"msg={p}",
        f"/search {p}",
        f"/login {p}",
        f"/echo {p}"
    ]
    return random.choice(wrappers)

def malicious_samples(n_per_class=4000):
    data = []
    for label, builder in INJ_BUILDERS.items():
        for _ in range(n_per_class):
            payload = builder()
            payload = wrap_payload(payload)

            if random.random() < 0.2:
                payload = urllib.parse.quote(payload)

            if random.random() < 0.2:
                payload = random_typo(payload)

            data.append((payload, label))
    return data

# ================= MAIN =================

def main():
    data = []

    data += safe_samples(20000)
    data += malicious_samples(5000)

    random.shuffle(data)

    texts = [t for t, y in data]
    labels = [y for t, y in data]

    print("Total samples:", len(texts))

    with open("dataset_py.py", "w", encoding="utf-8") as f:
        f.write("texts = " + repr(texts) + "\n\n")
        f.write("labels = " + repr(labels) + "\n")

    print("Saved dataset_py.py")

if __name__ == "__main__":
    main()