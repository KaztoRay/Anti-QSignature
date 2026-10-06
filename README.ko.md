# Anti-Quantum

[English](README.md) · **한국어** · [日本語](README.ja.md)

Anti-Quantum은 연구용 스마트 컨트랙트 보안 도구입니다. Solidity, Vyper, Yul 패턴 검사와 바이트코드 지문, 정책 퍼징, Q# 보안 모델, 선택적 Foundry·Slither 실행 결과를 JSON, HTML, Markdown, SARIF 보고서로 만듭니다.

## 주요 기능

- 단일 파일 또는 프로젝트를 검사하고 위치와 심각도를 포함한 검토 후보를 표시합니다.
- 바이트코드와 재현 가능한 소스 manifest의 SHA-256 지문을 생성합니다.
- 권한, nonce, 가디언, 동결, 코드 무결성 정책을 퍼징합니다.
- QDK가 있으면 Q# 정책·업그레이드·재실행·ERC-4337·키 회전·가디언 복구·Grover 하네스를 실행합니다.
- `--external-tools`로 프로젝트의 임시 복사본에서 Forge와 Slither를 실행합니다.
- 이전 JSON 보고서와 결과를 비교하고 CI 심각도 기준을 적용합니다.

## 설치

Python 3.10 이상이 필요합니다. Foundry와 Slither는 선택 사항입니다.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

CLI 명령은 `antiq`입니다. 기존 통합을 위해 Python import 경로 `anti_qsignature`와 Q# 네임스페이스 `AntiQSignature`는 유지합니다.

## 검사

```bash
.venv/bin/antiq /absolute/path/to/contracts
.venv/bin/antiq /absolute/path/to/project --fuzz-cases 2000 --qsharp required --fail-on high
.venv/bin/antiq /absolute/path/to/project --external-tools --baseline reports/previous.json
```

경로 없이 실행하면 대화형으로 입력할 수 있습니다. 데스크톱에서는 `--pick-file`, `--pick-dir`로 선택 창을 엽니다. `--qsharp off`는 Q#을 건너뛰고, `--qsharp required`는 실행 실패 시 오류를 반환합니다. 기본값 `auto`는 사용 불가 상태를 기록하고 계속 진행합니다.

기본 보고서 경로는 `reports/antiq-report.{json,html,md,sarif}`입니다. 종료 코드는 성공 `0`, `--fail-on` 기준 이상 발견 `2`, 입력 또는 실행 오류 `1`입니다.

검사 대상 프로젝트에 `.antiq.toml.example`을 `.antiq.toml`로 복사하면 제외 경로, 수용 규칙, 퍼징 횟수, Q# 모드, 외부 도구, CI 기준을 설정할 수 있습니다. CLI 옵션이 우선합니다.

## 검증

```bash
forge test
PYTHONPATH=python .venv/bin/python -m unittest discover -s tests
.venv/bin/antiq . --qsharp required --fuzz-cases 512
```

## 적용 범위와 보안 한계

패턴 검사 결과는 취약점 확정이 아닌 검토 후보입니다. Q#은 오프체인 공격 및 정책 모델이며 EVM 서명을 검증하지 않습니다. `AntiQSmartWallet`은 ECDSA와 Merkle Lamport 검증을 보여주는 연구용 프로토타입으로, calldata와 가스 비용이 큽니다. `AntiQ4337Account`에는 교체 가능한 양자내성 검증기 인터페이스가 있지만 운영 배포에는 검증된 ML-DSA 또는 SLH-DSA 구현이나 precompile 어댑터, EntryPoint 통합 테스트, 독립 보안 감사가 필요합니다. 가디언 복구는 현재 Q# 정책 모델이며 온체인 모듈은 아닙니다. 자원 추정치는 모델링된 Q# 회로 기준이며 전체 secp256k1 Shor 공격 추정치가 아닙니다.

## 라이선스

[MIT](LICENSE) © 2026 Kazto.
