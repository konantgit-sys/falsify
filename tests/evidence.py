#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Собрать и подписать бандл доказательств демо-кейса.

Что кладёт в бандл:
  - три прогона демо-теста (до фикса, после фикса, после откатa) — путь, rc,
    sha256 сырых байтов, время UTC;
  - два прогона полного набора (до фикса и после откатa) — для критерия 4:
    их sha256 обязаны совпасть;
  - дайджест окружения (интерпретатор, зависимости, хеш pyproject, образ ОС);
  - коммиты репозитория на момент сборки.

Подпись: Ed25519 над JCS-подобной каноникой бандла (sort_keys, UTF-8, без
пробелов). Приватный ключ берётся по пути из аргумента --key или из
переменной окружения FALSIFY_EVIDENCE_KEY; сам ключ в бандл не попадает,
публичный кладётся рядом (.pub).

Запуск:
    python3 tests/evidence.py --out evidence --key /path/to/ed25519.key
"""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def env_digest():
    try:
        import cryptography
        dep = "cryptography %s" % cryptography.__version__
    except Exception:  # noqa: BLE001
        dep = "cryptography неизвестна"
    osrel = ""
    try:
        for line in open("/etc/os-release", encoding="utf-8"):
            if line.startswith("PRETTY_NAME="):
                osrel = line.split("=", 1)[1].strip().strip('"')
    except Exception:  # noqa: BLE001
        pass
    pyproject = ROOT / "pyproject.toml"
    return {
        "python": platform.python_version(),
        "dependencies": dep,
        "dependency_lock_sha256": sha256_bytes(pyproject.read_bytes()) if pyproject.exists() else "нет pyproject",
        "os_image": "%s | %s" % (platform.platform(), osrel),
        "harness": "tests/run_tests.py + tests/demo_required_fields.py",
    }


def git(*args):
    try:
        out = subprocess.run(["git"] + list(args), cwd=str(ROOT), capture_output=True, text=True, timeout=20)
        return out.stdout.strip() if out.returncode == 0 else "ошибка: %s" % out.stderr.strip()[:120]
    except Exception as e:  # noqa: BLE001
        return "ошибка: %s" % type(e).__name__


def add_run(bundle, label, path, rc):
    p = Path(path)
    if not p.exists():
        bundle["runs"].append({"label": label, "path": str(path), "present": False})
        return
    raw = p.read_bytes()
    txt = raw.decode("utf-8", errors="replace")
    verdict = ""
    for line in txt.splitlines():
        if line.strip().startswith("verdict"):
            verdict = line.split(":", 1)[1].strip()
    bundle["runs"].append({
        "label": label,
        "path": str(p),
        "present": True,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "rc": rc,
        "verdict": verdict,
        "recorded_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--key", default="")
    a = ap.parse_args()

    key_path = a.key or __import__("os").environ.get("FALSIFY_EVIDENCE_KEY", "")
    if not key_path or not Path(key_path).exists():
        print("нет ключа подписи: передайте --key или FALSIFY_EVIDENCE_KEY")
        return 2

    out = ROOT / a.out
    out.mkdir(exist_ok=True)

    bundle = {
        "case": "required-fields: запись без timestamp и payload обязана быть отклонена",
        "spec": "docs/DEMO_CASE.md",
        "criteria": 5,
        "env": env_digest(),
        "git": {
            "head": git("rev-parse", "HEAD"),
            "tag_pre_fix": git("rev-parse", "demo-pre-fix"),
            "subject": git("log", "-1", "--pretty=%s"),
        },
        "runs": [],
        "collected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    for label, fname, rc in (
        ("before_fix", "runs/before_fix_demo.txt", 1),
        ("after_fix", "runs/after_fix_demo.txt", 0),
        ("after_rollback", "runs/after_rollback_demo.txt", 1),
        ("suite_before_fix", "runs/before_fix_suite.txt", 0),
        ("suite_after_rollback", "runs/after_rollback_suite.txt", 0),
    ):
        add_run(bundle, label, out / fname, rc)

    suites = {r["label"]: r.get("sha256") for r in bundle["runs"] if r["label"].startswith("suite_") and r.get("present")}
    bundle["unrelated_fixtures_sha256_equal"] = (
            suites.get("suite_before_fix") == suites.get("suite_after_rollback") and bool(suites))
    bundle["unrelated_sha256"] = suites.get("suite_before_fix")

    raw_key = Path(key_path).read_text(encoding="utf-8").strip()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_key))
    body = {k: v for k, v in bundle.items() if k != "signature"}
    sig = key.sign(canon(body))
    bundle["signature"] = {
        "alg": "Ed25519",
        "over": "sha256-free JCS-каноника бандла без поля signature",
        "signature_hex": sig.hex(),
        "public_key_hex": key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex(),
    }

    (out / "evidence.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "evidence.sig").write_text(sig.hex() + "\n", encoding="utf-8")
    (out / "evidence.pub").write_text(bundle["signature"]["public_key_hex"] + "\n", encoding="utf-8")

    print("== бандл собран")
    for r in bundle["runs"]:
        print("   %-20s %s rc=%s %s" % (r["label"], (r.get("sha256") or "нет файла")[:16], r.get("rc"), r.get("verdict") or ""))
    print("   несвязанные фикстуры совпали:", bundle["unrelated_fixtures_sha256_equal"])
    print("   подпись:", bundle["signature"]["signature_hex"][:32], "…")
    print("   файлы: evidence.json, evidence.sig, evidence.pub")
    return 0


if __name__ == "__main__":
    sys.exit(main())
