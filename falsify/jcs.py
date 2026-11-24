"""JCS — каноникализация JSON по RFC 8785.

Правила, которые здесь зафиксированы кодом:

* ключи сортируются по байтам UTF-16BE (не по code point и не по локали);
* числа — только целые в диапазоне двойной точности (|n| <= 2^53-1);
  дробное число — ошибка, а не повод округлить;
* строки экранируются минимально: кавычка, обратная косая, управляющие символы.

Почему это не мелочь: разница между UTF-16BE и code point видна ровно на одном
символе — эмодзи. Реализация, которая сортирует по code point, даёт другой хеш
на записи с эмодзи в ключе, и обе реализации при этом «работают».
"""

MAX_SAFE_INT = 2 ** 53 - 1


class JCSNumberError(ValueError):
    """Число, которое нельзя канонизировать без потери точности."""


def check_numbers(obj, path="record"):
    """Отказ на дробных и на целых вне диапазона double."""
    if obj is None or isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise JCSNumberError("дробное число в %s: %r" % (path, obj))
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INT:
            raise JCSNumberError("целое вне диапазона double в %s: %r" % (path, obj))
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            check_numbers(v, "%s[%d]" % (path, i))
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            check_numbers(v, "%s.%s" % (path, k))


def jcs(obj):
    """Строка канонического JSON для null/bool/int/str/list/dict."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        out = ['"']
        for ch in obj:
            code = ord(ch)
            if ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            elif ch in "\b\f\n\r\t":
                out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n",
                            "\r": "\\r", "\t": "\\t"}[ch])
            elif code < 0x20:
                out.append("\\u%04x" % code)
            else:
                out.append(ch)
        return "".join(out) + '"'
    if isinstance(obj, list):
        return "[" + ",".join(jcs(v) for v in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs(k) + ":" + jcs(obj[k]) for k in keys) + "}"
    raise TypeError("тип не поддержан каноникой: %s" % type(obj).__name__)
