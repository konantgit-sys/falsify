#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Демо-кейс: запись без подписанного времени обязана быть отклонена.

Утверждение теста (одно):
    запись без обязательных полей `timestamp` и `payload`, у которой хеш
    пересчитан, а подпись поставлена заново, обязана получить verdict
    `verified_fail`, и причина обязана назвать отсутствующие поля.

Код возврата:
    0 — утверждение выполнено (дефект закрыт),
    1 — утверждение ложно: запись принята как verified_pass (дефект воспроизведён).

Ничего не пишет на диск и не ходит в сеть. Приватный ключ генерируется в памяти:
кейс перезапускается у любого, у кого нет наших секретов.
"""
import hashlib
import json
import platform
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from falsify.record import record_hash, signature_bytes, verify  # noqa: E402

MISSING = ("timestamp", "payload")


def env_digest():
    """Дайджест окружения: без него зелёный результат может быть про зависимость."""
    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    try:
        import cryptography

        dep = "cryptography %s" % cryptography.__version__
    except Exception:  # noqa: BLE001
        dep = "cryptography неизвестна"
    try:
        osrel = ""
        for line in open("/etc/os-release", encoding="utf-8"):
            if line.startswith("PRETTY_NAME="):
                osrel = line.split("=", 1)[1].strip().strip('"')
        image = "%s | %s" % (platform.platform(), osrel)
    except Exception:  # noqa: BLE001
        image = platform.platform()
    lock_sha = hashlib.sha256(pyproject.read_bytes()).hexdigest() if pyproject.exists() else "нет pyproject"
    return {
        "python": platform.python_version(),
        "dependencies": dep,
        "dependency_lock_sha256": lock_sha,
        "os_image": image,
    }


def build_record():
    """Самосогласованная запись без timestamp и payload."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    rec = {
        "canonicalization_version": "canon_v1.3",
        "dharma_name": "demo-required-fields",
        "degraded_id": "demo-degraded-1",
        "su_yin_fp": "demo-fp",
        "su_yin_state": "incomplete_2_of_4",
        "prev_record_sha256": "0" * 64,
        "ed25519_pubkey": pub,
    }
    # Порядок как в формате: подпись ложится над телом без signature и
    # record_sha256, а хеш считается уже по записи с подписью (проверено на
    # эталоне: record_hash(эталон) == объявленный record_sha256).
    rec["signature"] = key.sign(signature_bytes(rec)).hex()
    rec["record_sha256"] = record_hash(rec)
    return rec


def main():
    rec = build_record()
    res = verify(rec)
    checks = {c["check"]: c["status"] for c in res["checks"]}
    detail = " ".join(c.get("detail") or "" for c in res["checks"])

    print("== демо-кейс: обязательные поля записи")
    print("  отсутствует      : %s" % ", ".join(MISSING))
    print("  verdict          : %s" % res["verdict"])
    print("  checks           : %s" % ", ".join("%s %s" % (k, v) for k, v in checks.items()))
    named = [f for f in MISSING if f in detail]
    print("  причиной названы : %s" % (", ".join(named) if named else "—"))
    print("  дайджест окружения: %s" % json.dumps(env_digest(), ensure_ascii=False))

    ok = res["verdict"] == "verified_fail" and len(named) == len(MISSING)
    if ok:
        print("\nУТВЕРЖДЕНИЕ ВЫПОЛНЕНО: запись без обязательных полей отклонена, поля названы.")
        return 0
    print("\nУТВЕРЖДЕНИЕ ЛОЖНО: запись без %s принята как %s." % (", ".join(MISSING), res["verdict"]))
    if res["verdict"] == "verified_fail":
        print("Отклонена, но причина не называет отсутствующие поля: %s" % (detail[:200] or "пусто"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
