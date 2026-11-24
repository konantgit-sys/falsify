"""Мутанты: проверка самой проверки.

Идея простая и жестокая. Взять запись и испортить её так, чтобы правильная
проверка обязана была упасть. Если испорченная запись всё равно проходит —
проверка бесполезна, каким бы аккуратным ни был её код.

Но есть и вторая половина, о которой обычно молчат: два мутанта обязаны
ПРОЙТИ, потому что фиксируют не ошибку, а границу формата.

* `ts_human_plus4days` — метка для человека лежит вне хеша и подписи. Запись
  с меткой, переписанной на 4 дня вперёд, обязана остаться валидной. Именно
  поэтому `ts_human` нельзя считать доказательством времени; проверка, которая
  падает здесь, врёт в другую сторону — она «защищает» то, чего нет.
* `key_order_shuffle` — порядок ключей в JSON не должен ничего менять, иначе
  каноникализация не работает и хеш зависит от форматирования файла.

Итог: 7 мутантов должны упасть, 2 должны пройти. Инструмент печатает оба счёта
раздельно — потому что «все упали» без второго счёта означает, что проверка
падает вообще на всё, включая пустоту.
"""
import copy
import random

from .record import verify

# Валидный чужой открытый ключ нужен для мутанта «подмена ключа»: он обязан быть
# настоящим Ed25519-ключом, иначе проверка упадёт не из-за подмены, а из-за битого
# ключа, и тест соврёт. Здесь он зафиксирован константой: пакету не нужен доступ
# ни к одному приватному ключу — проверка этим и отличается от подписи.
_OTHER_PUBKEY_HEX = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"


def _m_content_edit(rec):
    out = copy.deepcopy(rec)
    for field in ("dharma_name", "su_yin_fp", "degraded_id"):
        if field in out and isinstance(out[field], str):
            out[field] = out[field] + "x"
            return out
    out["payload"] = dict(out.get("payload") or {})
    out["payload"]["edited"] = 1
    return out


def _m_signature_bitflip(rec):
    out = copy.deepcopy(rec)
    sig = str(out.get("signature") or "")
    if not sig:
        return None
    out["signature"] = sig[:-2] + ("00" if sig[-2:] != "00" else "11")
    return out


def _m_hash_bitflip(rec):
    out = copy.deepcopy(rec)
    h = str(out.get("record_sha256") or "")
    if not h:
        return None
    out["record_sha256"] = h[:-1] + ("0" if h[-1] != "0" else "4")
    return out


def _m_unix_tick_plus1(rec):
    out = copy.deepcopy(rec)
    ts = dict(out.get("timestamp") or {})
    if "unix_tick" not in ts:
        return None
    ts["unix_tick"] = int(ts["unix_tick"]) + 1
    out["timestamp"] = ts
    return out


def _m_unix_tz_swap(rec):
    out = copy.deepcopy(rec)
    ts = dict(out.get("timestamp") or {})
    if "unix_tz" not in ts:
        return None
    ts["unix_tz"] = "Asia/Shanghai" if ts["unix_tz"] != "Asia/Shanghai" else "Europe/Moscow"
    out["timestamp"] = ts
    return out


def _m_pubkey_swap(rec):
    out = copy.deepcopy(rec)
    if not out.get("ed25519_pubkey"):
        return None
    out["ed25519_pubkey"] = _OTHER_PUBKEY_HEX
    return out


def _m_float_smuggled(rec):
    out = copy.deepcopy(rec)
    out["payload"] = dict(out.get("payload") or {})
    out["payload"]["float_smuggled"] = 1.5
    return out


def _m_ts_human_plus4days(rec):
    out = copy.deepcopy(rec)
    if "ts_human" not in out:
        return None
    out["ts_human"] = str(out["ts_human"]) + " (+4 дня вперёд — подпись не замечает)"
    return out


def _m_key_order_shuffle(rec):
    items = list(rec.items())
    random.Random(7).shuffle(items)
    return dict(items)


MUTANTS = [
    ("content_edit", "fail", "правка подписанного поля", _m_content_edit),
    ("signature_bitflip", "fail", "подмена последнего байта подписи", _m_signature_bitflip),
    ("hash_bitflip", "fail", "подмена последнего символа record_sha256", _m_hash_bitflip),
    ("unix_tick_plus1", "fail", "сдвиг unix_tick на 1 секунду", _m_unix_tick_plus1),
    ("unix_tz_swap", "fail", "смена unix_tz", _m_unix_tz_swap),
    ("pubkey_swap", "fail", "подмена открытого ключа на другой валидный", _m_pubkey_swap),
    ("float_smuggled", "fail", "дробное число в payload", _m_float_smuggled),
    ("ts_human_plus4days", "pass", "метка для человека вне подписи — так и должно быть",
     _m_ts_human_plus4days),
    ("key_order_shuffle", "pass", "порядок ключей не влияет на хеш — каноника работает",
     _m_key_order_shuffle),
]


def run(rec):
    """Прогнать всех мутантов. Возвращает список результатов и сводку."""
    results = []
    for name, expect, about, apply_mutation in MUTANTS:
        mutated = apply_mutation(rec)
        if mutated is None:
            results.append({"mutant": name, "about": about, "expect": expect,
                            "got": "n/a", "ok": True, "detail": "поле отсутствует — пропущено"})
            continue
        outcome = verify(mutated)
        got = "pass" if outcome["verdict"] == "verified_pass" else "fail"
        failed_checks = [c["check"] + ": " + c["detail"] for c in outcome["checks"] if c["status"] == "fail"]
        results.append({
            "mutant": name, "about": about, "expect": expect, "got": got,
            "ok": got == expect,
            "detail": "; ".join(failed_checks)[:200] if failed_checks else "проверки прошли",
        })
    summary = {
        "total": len(results),
        "must_fail": sum(1 for r in results if r["expect"] == "fail" and r["got"] != "n/a"),
        "failed_as_required": sum(1 for r in results if r["expect"] == "fail" and r["got"] == "fail"),
        "must_pass": sum(1 for r in results if r["expect"] == "pass" and r["got"] != "n/a"),
        "passed_as_required": sum(1 for r in results if r["expect"] == "pass" and r["got"] == "pass"),
        "broken": [r["mutant"] for r in results if not r["ok"]],
    }
    return results, summary
