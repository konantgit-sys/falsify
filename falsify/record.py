"""Проверка подписанной записи журнала.

Границы диапазонов (объявлены при появлении формата и подтверждены независимой
реализацией):

  canon_v1     HASH = sha256(JCS(rec - record_sha256))
               SIG  = Ed25519(JCS(rec - signature - record_sha256))
  canon_v1.3   то же, плюс ts_human исключается из ОБОИХ диапазонов

Следствие v1.3, которое важно понимать: ts_human лежит вне хеша и подписи, значит
доказательством времени не является. Это не дефект проверки, а свойство формата —
и инструмент обязан говорить это вслух, а не молчать.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jcs import JCSNumberError, check_numbers, jcs

# ts_human в исключениях всегда: в v1.3 его там нет физически, в v1 он входил,
# но наши эталонные записи v1 его не содержат — различие не влияет на результат.
EXCLUDED_FROM_HASH = ("record_sha256", "ts_human")
EXCLUDED_FROM_SIG = ("signature", "record_sha256", "ts_human")

# Незнакомая версия — FAIL, а не «попробуем угадать». Ровно на этом ломается
# свежесть: реализация, которая молча проверяет новую версию по старым правилам,
# выдаёт PASS на записи, которую не понимает.
KNOWN_VERSIONS = (None, "canon_v1", "canon_v1.3")

UNSIGNED_BY_DESIGN = ("ts_human",)

# Полнота записи. Без timestamp запись не утверждает, КОГДА произошла (ts_human
# лежит вне подписи), без payload — не утверждает, ЧТО произошло. Отсутствие
# поля нельзя читать как согласие: проверка обязана назвать его вслух.
REQUIRED_FIELDS = ("timestamp", "payload")

PASS, FAIL, SKIP = "pass", "fail", "skip"


def _body(rec, excluded):
    return {k: v for k, v in rec.items() if k not in excluded}


def record_hash(rec):
    """record_sha256 — sha256 от JCS(rec минус record_sha256 и ts_human)."""
    check_numbers(rec)
    return hashlib.sha256(jcs(_body(rec, EXCLUDED_FROM_HASH)).encode("utf-8")).hexdigest()


def signature_bytes(rec):
    """Байты, над которыми стоит подпись."""
    check_numbers(rec)
    return jcs(_body(rec, EXCLUDED_FROM_SIG)).encode("utf-8")


def _check(name, status, detail=""):
    return {"check": name, "status": status, "detail": detail}


def verify(rec, expect_pubkey=None, prev_record=None):
    """Проверить одну запись.

    Возвращает dict:
      verdict  — "verified_pass" | "verified_fail"
      checks   — список {check, status, detail}
      hash     — пересчитанный record_sha256 (None, если запись не разобрана)
      unsigned — поля, которые лежат вне подписи (граница формата, не ошибка)

    prev_record — предыдущая запись журнала целиком; если передана, проверяется
    связь prev_record_sha256 → record_sha256 предыдущей.
    """
    checks = []

    if not isinstance(rec, dict):
        return {"verdict": "verified_fail", "hash": None,
                "checks": [_check("parse", FAIL, "запись не является объектом")],
                "unsigned": []}

    version = rec.get("canonicalization_version")
    version_known = version in KNOWN_VERSIONS
    checks.append(_check(
        "version", PASS if version_known else FAIL,
        "версия %r" % (version,) if version_known
        else "неизвестная canonicalization_version %r: нет правил проверки, не угадываю" % (version,)))

    missing = [f for f in REQUIRED_FIELDS if f not in rec]
    checks.append(_check(
        "required", PASS if not missing else FAIL,
        "обязательные поля на месте" if not missing
        else "отсутствуют обязательные поля: %s" % ", ".join(missing)))

    computed = None
    try:
        check_numbers(rec)
        checks.append(_check("numbers", PASS, "только целые в диапазоне double"))
        computed = record_hash(rec)
        declared = rec.get("record_sha256")
        if not declared:
            checks.append(_check("hash", FAIL, "record_sha256 отсутствует"))
        elif computed != declared:
            checks.append(_check("hash", FAIL,
                                 "посчитан %s…%s, объявлен %s…%s"
                                 % (computed[:12], computed[-4:],
                                    str(declared)[:12], str(declared)[-4:])))
        else:
            checks.append(_check("hash", PASS, computed))
    except JCSNumberError as e:
        checks.append(_check("numbers", FAIL, str(e)))
        checks.append(_check("hash", SKIP, "каноника невозможна"))

    signature = rec.get("signature")
    record_key = rec.get("ed25519_pubkey")
    key_hex = expect_pubkey or record_key
    if not signature:
        checks.append(_check("signature", FAIL, "подпись отсутствует"))
    elif not key_hex:
        checks.append(_check("signature", FAIL, "нет ed25519_pubkey — проверить нечем"))
    else:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
                bytes.fromhex(signature), signature_bytes(rec))
            checks.append(_check("signature", PASS, "Ed25519 ok, ключ %s…" % key_hex[:12]))
        except (InvalidSignature, ValueError) as e:
            checks.append(_check("signature", FAIL, type(e).__name__))
        except Exception as e:  # noqa: BLE001 — любая неожиданность не должна давать PASS
            checks.append(_check("signature", FAIL, "неожиданно: %s" % type(e).__name__))

    if expect_pubkey and record_key not in (None, expect_pubkey):
        checks.append(_check("key_match", FAIL, "ключ в записи не тот, что ожидали"))
    elif expect_pubkey:
        checks.append(_check("key_match", PASS, "ключ совпал с ожидаемым"))

    if prev_record is not None:
        prev_hash = prev_record.get("record_sha256") if isinstance(prev_record, dict) else None
        claimed_prev = rec.get("prev_record_sha256")
        if not claimed_prev:
            checks.append(_check("chain", FAIL, "prev_record_sha256 отсутствует"))
        elif not prev_hash:
            checks.append(_check("chain", FAIL, "у предыдущей записи нет record_sha256"))
        elif claimed_prev != prev_hash:
            checks.append(_check("chain", FAIL,
                                 "объявлено %s…%s, у предыдущей %s…%s"
                                 % (str(claimed_prev)[:12], str(claimed_prev)[-4:],
                                    prev_hash[:12], prev_hash[-4:])))
        else:
            checks.append(_check("chain", PASS, "связь с предыдущей записью сходится"))

    verdict = "verified_pass" if all(c["status"] in (PASS, SKIP) for c in checks) else "verified_fail"
    unsigned = [f for f in UNSIGNED_BY_DESIGN if f in rec]
    return {"verdict": verdict, "hash": computed, "checks": checks, "unsigned": unsigned}
