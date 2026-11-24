"""Проверки falsify. Чистый stdlib, без pytest: запускается где угодно.

    python3 tests/run_tests.py

Печатает по строке на проверку и итог «пройдено N из N». Возвращает 0, только
если пройдено всё — цифрами, а не «на глаз».
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from falsify import record_hash, verify  # noqa: E402
from falsify.mutants import run as run_mutants  # noqa: E402

PASSED = []
FAILED = []


def check(name, condition, fact=""):
    if condition:
        PASSED.append(name)
        print("  PASS  %-46s %s" % (name, fact))
    else:
        FAILED.append(name)
        print("  FAIL  %-46s %s" % (name, fact))


def main():
    golden = json.load(open(os.path.join(HERE, "golden.json"), encoding="utf-8"))

    print("== эталонные записи (%d)" % len(golden))
    for entry in golden:
        rec = entry["record"]
        label = entry["label"]
        out = verify(rec)
        check("%s: проходит" % label, out["verdict"] == "verified_pass",
              out["verdict"])
        check("%s: хеш совпал с эталонным ядром" % label,
              out["hash"] == entry["recomputed_by_reference_core"],
              "%s…" % str(out["hash"])[:16])
        check("%s: объявленный хеш = пересчитанный" % label,
              rec.get("record_sha256") == entry["recomputed_by_reference_core"],
              "%s…" % str(rec.get("record_sha256"))[:16])

    print("\n== мутанты")
    for entry in golden:
        results, summary = run_mutants(entry["record"])
        check("%s: проверка ломается там, где обязана" % entry["label"],
              not summary["broken"], "сломанные: %s" % (summary["broken"] or "нет"))
        check("%s: все «должны упасть» упали" % entry["label"],
              summary["failed_as_required"] == summary["must_fail"],
              "%d/%d" % (summary["failed_as_required"], summary["must_fail"]))
        check("%s: все «должны пройти» прошли" % entry["label"],
              summary["passed_as_required"] == summary["must_pass"],
              "%d/%d" % (summary["passed_as_required"], summary["must_pass"]))

    print("\n== границы формата (должны вести себя именно так)")
    v13 = [e for e in golden if e["record"].get("ts_human")]
    if v13:
        results, _ = run_mutants(v13[0]["record"])
        by_name = {r["mutant"]: r for r in results}
        check("ts_human +4 дня → PASS (метка вне подписи)",
              by_name["ts_human_plus4days"]["got"] == "pass",
              by_name["ts_human_plus4days"]["got"])
        check("unix_tick +1 с → FAIL", by_name["unix_tick_plus1"]["got"] == "fail",
              by_name["unix_tick_plus1"]["got"])
        check("unix_tz смена → FAIL (иначе метка врёт)", by_name["unix_tz_swap"]["got"] == "fail",
              by_name["unix_tz_swap"]["got"])

    print("\n== незнакомая версия каноники")
    unknown = dict(golden[0]["record"])
    unknown["canonicalization_version"] = "canon_v1.99"
    out = verify(unknown)
    check("неизвестная версия → FAIL, а не «угадать»", out["verdict"] == "verified_fail",
          out["verdict"])
    check("причина названа", any("неизвестная canonicalization_version" in c["detail"]
                                 for c in out["checks"]), "")

    print("\n== связь с предыдущей записью")
    chain = [e for e in golden if e["record"].get("prev_record_sha256")]
    if len(chain) >= 2:
        # 93b2d484 объявляет prev = f2aa74a5
        child = next((e for e in golden if e["label"].startswith("93b2d484")), None)
        parent = next((e for e in golden if e["label"].startswith("f2aa74a5")), None)
        if child and parent:
            out = verify(child["record"], prev_record=parent["record"])
            check("цепь: связь с f2aa74a5 сходится",
                  any(c["check"] == "chain" and c["status"] == "pass" for c in out["checks"]), "")
            wrong = dict(child["record"])
            wrong["prev_record_sha256"] = "0" * 16 + str(parent["record"]["record_sha256"])[16:]
            out2 = verify(wrong, prev_record=parent["record"])
            check("цепь: подменённая ссылка → FAIL",
                  any(c["check"] == "chain" and c["status"] == "fail" for c in out2["checks"]), "")

    print("\n== ожидаемый ключ")
    rec = golden[0]["record"]
    out = verify(rec, expect_pubkey=str(rec.get("ed25519_pubkey")))
    check("свой ключ → PASS", out["verdict"] == "verified_pass", out["verdict"])
    out = verify(rec, expect_pubkey="00" * 32)
    check("чужой ключ → FAIL", out["verdict"] == "verified_fail", out["verdict"])

    print("\n== гигиена пакета")
    sources = []
    pkg = os.path.join(ROOT, "falsify")
    for name in sorted(os.listdir(pkg)):
        if name.endswith(".py"):
            sources.append((name, open(os.path.join(pkg, name), encoding="utf-8").read()))
    blob = "\n".join(text for _, text in sources)
    check("не читает приватный ключ", "artifact_ed25519" not in blob and "PrivateKey" not in
          blob.replace("Ed25519PrivateKey.from_private_bytes", ""), "по исходникам пакета")
    check("не ходит в сеть", not any(w in blob for w in ("urllib", "requests", "socket", "http")),
          "ни одного импорта сети")
    check("не зависит от colony-dash", "colony" not in blob, "импортов нет")

    print("\n%d/%d проверок пройдено" % (len(PASSED), len(PASSED) + len(FAILED)))
    if FAILED:
        print("провалено: %s" % ", ".join(FAILED))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
