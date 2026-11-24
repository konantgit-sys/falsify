"""falsify — проверить подписанный журнал и проверить саму проверку.

    falsify verify  record.json [--prev prev.json] [--key HEX] [--json]
    falsify mutants record.json [--json]
    falsify inspect record.json [--json]

Код возврата: 0 — всё прошло, 1 — провал, 2 — файл не разобран.
"""
import json
import sys

from .record import verify
from .mutants import run as run_mutants

__all__ = ["verify", "run_mutants", "main"]
__version__ = "0.1.0"

RC_PASS, RC_FAIL, RC_PARSE = 0, 1, 2


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:  # noqa: BLE001 — на входе может быть что угодно
        return None, "%s: %s" % (type(e).__name__, str(e)[:160])


def _print_verify(out):
    print(out["verdict"])
    for c in out["checks"]:
        mark = {"pass": "  PASS", "fail": "  FAIL", "skip": "  SKIP"}[c["status"]]
        print("%s  %-10s %s" % (mark, c["check"], c["detail"]))
    if out.get("unsigned"):
        print("  UNSIGNED   %s — вне хеша и подписи, доказательством не является"
              % ", ".join(out["unsigned"]))


def _print_mutants(results, summary):
    for r in results:
        mark = "  ok " if r["ok"] else "  BROKEN"
        print("%s %-20s ожидали %-4s получили %-4s | %s"
              % (mark, r["mutant"], r["expect"], r["got"], r["detail"]))
    print("\nдолжны упасть: %d/%d упали" % (summary["failed_as_required"], summary["must_fail"]))
    print("должны пройти: %d/%d прошли" % (summary["passed_as_required"], summary["must_pass"]))
    if summary["broken"]:
        print("ПРОВЕРКА СЛОМАНА на: %s" % ", ".join(summary["broken"]))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return RC_PASS
    if argv[0] in ("-V", "--version"):
        print("falsify %s" % __version__)
        return RC_PASS

    command = argv[0]
    args = argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]

    prev_path = None
    expect_key = None
    if "--prev" in args:
        i = args.index("--prev")
        prev_path = args[i + 1]
        del args[i:i + 2]
    if "--key" in args:
        i = args.index("--key")
        expect_key = args[i + 1]
        del args[i:i + 2]

    if not args:
        print("нужен путь к файлу записи", file=sys.stderr)
        return RC_PARSE

    rec, error = _load(args[0])
    if error:
        print("не разобрано: %s" % error, file=sys.stderr)
        return RC_PARSE

    if command == "verify":
        prev = None
        if prev_path:
            prev, perr = _load(prev_path)
            if perr:
                print("предыдущая запись не разобрана: %s" % perr, file=sys.stderr)
                return RC_PARSE
        out = verify(rec, expect_pubkey=expect_key, prev_record=prev)
        if as_json:
            print(json.dumps(out, ensure_ascii=False, indent=1))
        else:
            _print_verify(out)
        return RC_PASS if out["verdict"] == "verified_pass" else RC_FAIL

    if command == "mutants":
        results, summary = run_mutants(rec)
        if as_json:
            print(json.dumps({"results": results, "summary": summary}, ensure_ascii=False, indent=1))
        else:
            _print_mutants(results, summary)
        return RC_PASS if not summary["broken"] else RC_FAIL

    if command == "inspect":
        if as_json:
            print(json.dumps(rec, ensure_ascii=False, indent=1))
            return RC_PASS
        print("ключи: %s" % ", ".join(sorted(rec)))
        print("версия каноники: %r" % (rec.get("canonicalization_version"),))
        ts = rec.get("timestamp") or {}
        print("timestamp: %s" % json.dumps(ts, ensure_ascii=False))
        if "ts_human" in rec:
            print("ts_human:   %s  (вне подписи)" % rec["ts_human"])
        print("prev:       %s" % (rec.get("prev_record_sha256") or "—"))
        print("record_sha256: %s" % (rec.get("record_sha256") or "—"))
        print("подпись:    %s…" % str(rec.get("signature") or "")[:24])
        return RC_PASS

    print("неизвестная команда: %s" % command, file=sys.stderr)
    return RC_PARSE


if __name__ == "__main__":
    sys.exit(main())
