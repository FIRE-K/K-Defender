import re
import base64
import binascii
import html
import unicodedata
from urllib.parse import unquote_plus


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_WS_RE = re.compile(r"\s+")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")


def _try_url_decode(s: str, rounds: int = 1) -> str:
    out = s
    for _ in range(rounds):
        new = unquote_plus(out)
        if new == out:
            break
        out = new
    return out


def _try_html_unescape(s: str, rounds: int = 1) -> str:
    out = s
    for _ in range(rounds):
        new = html.unescape(out)
        if new == out:
            break
        out = new
    return out


def _try_unicode_escapes(s: str) -> str:
    def repl_u(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    def repl_x(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    s = re.sub(r"\\u([0-9a-fA-F]{4})", repl_u, s)
    s = re.sub(r"\\x([0-9a-fA-F]{2})", repl_x, s)
    return s


def _try_base64_decode_token(token: str, max_out: int = 4096) -> str | None:
    t = token.strip()
    if not _B64_RE.fullmatch(t):
        return None

    t2 = t.replace("-", "+").replace("_", "/")
    pad = (-len(t2)) % 4
    if pad:
        t2 += "=" * pad

    try:
        raw = base64.b64decode(t2, validate=False)
    except (binascii.Error, ValueError):
        return None

    if not raw or len(raw) > max_out:
        return None

    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = raw.decode("latin-1", errors="replace")

    printable = sum(ch.isprintable() for ch in decoded)
    if printable / max(1, len(decoded)) < 0.75:
        return None

    return decoded


def normalize_input(
    text: str,
    *,
    lowercase: bool = True,
    nfkc: bool = True,
    strip_zero_width: bool = True,
    strip_controls: bool = True,
    collapse_whitespace: bool = True,
    url_decode_rounds: int = 2,
    html_unescape_rounds: int = 2,
    unicode_escapes: bool = True,
    base64_decode: bool = True,
    base64_max_len: int = 4096,
    max_len: int = 8192,
    max_passes: int = 3,
) -> str:
    """
    Нормализация пользовательского ввода для сигнатурного анализа.

    Делает:
    - ограничение длины (чтобы не повесить бота),
    - URL decode (%xx, + -> space) в несколько раундов,
    - HTML entity unescape (&lt; &amp; &#xNN;),
    - декодирование \\uXXXX / \\xNN,
    - удаление zero-width / bidi control,
    - NFKC-нормализацию (сведение похожих символов),
    - очистку управляющих символов,
    - схлопывание пробелов,
    - опционально: попытка base64/base64url decode, если строка похожа на токен.

    Возвращает *одну* строку (готовую для in-поиска).
    """
    if text is None:
        return ""

    s = str(text)

    if len(s) > max_len:
        s = s[:max_len]

    s = s.replace("\r\n", "\n").replace("\r", "\n")

    for _ in range(max_passes):
        before = s

        if url_decode_rounds > 0:
            s = _try_url_decode(s, rounds=url_decode_rounds)

        if html_unescape_rounds > 0:
            s = _try_html_unescape(s, rounds=html_unescape_rounds)

        if unicode_escapes:
            s = _try_unicode_escapes(s)

        if s == before:
            break

    if strip_zero_width:
        s = _ZERO_WIDTH_RE.sub("", s)

    if nfkc:
        s = unicodedata.normalize("NFKC", s)

    if strip_controls:
        s = _CTRL_RE.sub("", s)

    if collapse_whitespace:
        s = _WS_RE.sub(" ", s).strip()

    if lowercase:
        s = s.lower()

    if base64_decode:
        decoded = _try_base64_decode_token(s, max_out=base64_max_len)
        if decoded:
            decoded_norm = normalize_input(
                decoded,
                lowercase=lowercase,
                nfkc=nfkc,
                strip_zero_width=strip_zero_width,
                strip_controls=strip_controls,
                collapse_whitespace=collapse_whitespace,
                url_decode_rounds=1,
                html_unescape_rounds=1,
                unicode_escapes=unicode_escapes,
                base64_decode=False,
                max_len=max_len,
                max_passes=2,
            )
            s = f"{s} || {decoded_norm}"

    if len(s) > max_len:
        s = s[:max_len]

    return s
