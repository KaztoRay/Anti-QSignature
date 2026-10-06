# Anti-Quantum

**English** · [한국어](README.ko.md) · [日本語](README.ja.md)

Anti-Quantum is a research oriented smart contract security toolkit. It combines Solidity, Vyper, and Yul pattern scanning, bytecode fingerprints, policy fuzzing, Q# security models, and optional Foundry and Slither runs into JSON, HTML, Markdown, and SARIF reports.

## Features

- Scan a contract file or project and report review candidates with file locations and severity.
- Fingerprint contract bytecode and a reproducible source manifest.
- Fuzz authorization, nonce, guardian, freeze, and code integrity policies.
- Run Q# policy, upgrade, replay, ERC-4337, key rotation, guardian recovery, and Grover harnesses when QDK is available.
- Run Forge and Slither on a temporary project copy with `--external-tools`.
- Compare findings with a previous JSON baseline and apply a CI severity gate.

## Install

Requires Python 3.10 or later. Foundry and Slither are optional.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

The CLI remains `antiq`. The Python import path `anti_qsignature` and Q# namespace `AntiQSignature` remain stable for existing integrations.

## Scan

```bash
.venv/bin/antiq /absolute/path/to/contracts
.venv/bin/antiq /absolute/path/to/project --fuzz-cases 2000 --qsharp required --fail-on high
.venv/bin/antiq /absolute/path/to/project --external-tools --baseline reports/previous.json
```

Run `antiq` without a path for an interactive prompt. On a desktop, `--pick-file` and `--pick-dir` open a picker. Use `--qsharp off` to skip Q# or `--qsharp required` to fail when it cannot run. The default `auto` mode records Q# as unavailable and continues.

Reports are written to `reports/antiq-report.{json,html,md,sarif}` by default. Exit codes are `0` for success, `2` when findings meet `--fail-on`, and `1` for input or runtime errors.

Copy `.antiq.toml.example` to the scanned project's `.antiq.toml` to set exclusions, accepted rules, fuzz cases, Q# mode, external tools, and CI threshold. CLI options take precedence.

## Verify

```bash
forge test
PYTHONPATH=python .venv/bin/python -m unittest discover -s tests
.venv/bin/antiq . --qsharp required --fuzz-cases 512
```

## Scope and security limits

Pattern findings are review candidates, not confirmed vulnerabilities. Q# runs off chain to model attacks and policy behavior; it does not verify an EVM signature. The sample `AntiQSmartWallet` demonstrates ECDSA plus Merkle Lamport verification, but its calldata and gas costs make it a research prototype. `AntiQ4337Account` exposes a replaceable post quantum verifier interface; production deployment still needs a verified ML-DSA or SLH-DSA implementation or precompile adapter, EntryPoint integration tests, and an independent security audit. Guardian recovery currently exists as a Q# policy model, not an on chain module. Resource estimates describe the modeled Q# circuits, not a full secp256k1 Shor attack.

## License

[MIT](LICENSE) © 2026 Kazto.
