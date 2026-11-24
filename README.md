# falsify

Verify a signed record log — and verify the **verifier**.

A verifier that cannot fail is not a verifier, it is decoration. `falsify` does two things:
it checks a signed record (hash, Ed25519 signature, chain link), and it breaks the record
on purpose to see whether the check actually falls over. If a broken record still passes,
`falsify` says so, loudly, and returns a non-zero code.

## What it does

```
falsify verify  record.json [--prev prev.json] [--key HEX] [--json]
falsify mutants record.json [--json]
falsify inspect record.json [--json]
```

Exit codes: `0` — everything passed, `1` — a check failed, `2` — the file could not be parsed.

Real output on a published record:

```
$ falsify verify cell6.json --prev cell5.json
verified_pass
  PASS  version    версия 'canon_v1.3'
  PASS  numbers    только целые в диапазоне double
  PASS  hash       93b2d484bb30efb8ebd3152caf08439f311c7b7a112c463b08b16b086e0da8ea
  PASS  signature  Ed25519 ok, ключ f6d6ac1254b6…
  PASS  chain      связь с предыдущей записью сходится
  UNSIGNED   ts_human — вне хеша и подписи, доказательством не является
```

The `UNSIGNED` line is not a warning about a bug — it is a fact about the format, printed
because silence there is how people end up treating a human-readable label as proof of time.

## Mutants — the part that matters

```
$ falsify mutants cell6.json
  ok  content_edit         ожидали fail получили fail | hash: посчитан ff9462…9bb6, объявлен 93b2d4…efb8; signature: InvalidSignature
  ok  signature_bitflip    ожидали fail получили fail | ...
  ok  hash_bitflip         ожидали fail получили fail | ...
  ok  unix_tick_plus1      ожидали fail получили fail | ...
  ok  unix_tz_swap         ожидали fail получили fail | ...
  ok  pubkey_swap          ожидали fail получили fail | ...
  ok  float_smuggled       ожидали fail получили fail | numbers: дробное число в record.payload.float_smuggled: 1.5
  ok  ts_human_plus4days   ожидали pass получили pass | проверки прошли
  ok  key_order_shuffle    ожидали pass получили pass | проверки прошли

должны упасть: 7/7 упали
должны пройти: 2/2 прошли
```

Seven mutants **must fail**. Two mutants **must pass**, and they are the interesting half:

* `ts_human_plus4days` — the human label sits outside hash and signature, so a record whose
  label was rewritten four days into the future must still verify. A verifier that fails
  here is lying in the other direction: it pretends to protect something that was never
  signed. This is how you know `ts_human` is not evidence of time — only `unix_tick`
  together with `unix_tz` is (and both are covered by the signature).
* `key_order_shuffle` — reordering JSON keys must change nothing. If it does, the
  canonicalisation is not working and the hash depends on file formatting.

Two counters, printed separately, for one reason: "all mutants failed" without the second
count also describes a verifier that fails on everything, including an empty file.

## Rules it enforces

* **Canonicalisation** — JCS / RFC 8785: keys sorted by UTF-16BE bytes, integers only
  (doubles are rejected, not rounded), |n| ≤ 2^53−1.
* **Unknown version is a FAIL.** `canonicalization_version` outside the known table is never
  guessed at. A verifier that checks a new version with old rules returns PASS on a record
  it does not understand — that is how freshness silently breaks.
* **No private keys.** Verification needs a public key only; the package never reads a
  private key file and never touches the network.
* **Boundaries are stated, not hidden.** Hash covers `rec − record_sha256 − ts_human`;
  signature covers `rec − signature − record_sha256 − ts_human`.

## Install and test

```
pip install .            # one dependency: cryptography
python3 tests/run_tests.py
```

`tests/run_tests.py` is plain stdlib, no pytest. It checks the four published records
against their golden hashes, runs all mutants, checks the format boundaries, the chain
link, the expected-key path and the package hygiene (no private key, no network, no
dependency on the repository it came from). Current state: **36/36**.

## Scope

v1 handles one format. No network, no server, no accounts, no DSSE/COSE/JWS, no GUI.
Roadmap and acceptance criteria — [SPEC.md](SPEC.md). License — MIT.
