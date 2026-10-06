# Anti-QSignature

Q# 양자 위협 분석, Solidity 정적 취약점 검사, 격리된 Foundry/Slither 실행 및 스마트 지갑 정책 퍼징을 하나의 보고서로 만드는 초기 MVP입니다.

## 현재 구현된 기능

- 사용자가 단일 `.sol` 파일 또는 전체 컨트랙트 프로젝트 경로를 지정
- Solidity/Yul/Vyper 소스의 위험 패턴과 정확한 줄 번호 보고
- Hardhat/Foundry JSON 산출물의 bytecode SHA-256 fingerprint 생성
- 소스 전체의 재현 가능한 manifest hash 생성
- nonce 재사용, 미승인 호출, PQ 승인 누락, 고액 guardian 우회, codehash 변조 정책 퍼징
- Q# Grover probe 실행 및 256비트 탐색 공간의 양자 보안 요약
- Q# 지갑·업그레이드·서명 도메인·ERC-4337·키 수명주기 정책 1,280상태 전수 검증
- Q# hardened/mutant differential harness와 Grover 반례 증폭 검증
- 7/12/16 큐비트 공격 라운드별 Quantum Resource Estimator 비교
- 선택한 프로젝트를 임시 디렉터리로 복사한 뒤 Forge fuzz와 Slither 실행
- 검색·필터·위험 점수 기반 HTML, JSON, Markdown 및 GitHub SARIF 보고서
- 이전 보고서 대비 신규·유지·해결 항목 비교 및 CI 심각도 품질 게이트
- 코드 무결성 attestation registry와 정책 kernel Solidity 예제
- 실제 실행 가능한 ECDSA + Merkle-Lamport 하이브리드 지갑 프로토타입
- Q# 트랜잭션 순서 하네스로 Lamport leaf 재사용과 동결 우회 전수검증
- ERC-4337 `validateUserOp` 계정과 교체 가능한 PQ verifier 인터페이스
- Q# ERC-4337 EntryPoint·sender·도메인·이중서명 256상태 전수검증
- `keyEpoch` 서명 도메인과 자기호출 제한을 적용한 PQ 키 회전 및 구세대 서명 폐기
- Q# PQ 키 회전·2-of-3 가디언 복구 정책 differential harness
- 실제 스캔 위험 비트마스크를 oracle로 구성하는 동적 Q# Grover 탐색

> 정적 규칙의 결과는 취약점 확정이 아니라 검토 후보입니다. 실제 배포 전에는 수동 감사와 체인별 PQ verifier 검증이 필요합니다.

`AntiQSmartWallet`의 Lamport 검증은 연구용으로 완전한 검증 경로를 보여주지만 calldata와 가스 비용이 큽니다. 현재 Foundry 측정에서 정상 실행은 약 267만 gas를 사용합니다. 운영 환경에서는 ML-DSA/SLH-DSA 네이티브 모듈 또는 체인 precompile으로 교체하는 것을 전제로 합니다.

## 설치

```bash
python3 -m venv .venv
PIP_CONFIG_FILE=/dev/null .venv/bin/python -m pip install -e .
```

## 경로를 직접 선택해 검사

경로를 인자로 지정합니다.

```bash
.venv/bin/antiq /absolute/path/to/contracts --fuzz-cases 1000
```

경로를 생략하면 터미널에서 파일 또는 프로젝트 경로를 입력할 수 있습니다.

```bash
.venv/bin/antiq
```

macOS/Linux 데스크톱 파일 선택기를 사용하려면 파일과 폴더 중 하나를 지정합니다.

```bash
.venv/bin/antiq --pick-file
.venv/bin/antiq --pick-dir
```

Forge와 Slither까지 실행하려면 다음 옵션을 사용합니다. 원본 프로젝트가 아니라 임시 복사본에서 실행됩니다.

```bash
.venv/bin/antiq /absolute/path/to/project \
  --external-tools \
  --fuzz-cases 2000 \
  --qsharp required \
  --fail-on high
```

이전 결과와 비교하려면 기존 JSON을 baseline으로 지정합니다.

```bash
.venv/bin/antiq /absolute/path/to/project \
  --baseline reports/previous.json \
  --exclude 'lib/**' \
  --exclude 'vendor/**'
```

팀 설정은 프로젝트 루트의 `.antiq.toml`에 저장할 수 있습니다. `.antiq.toml.example`을 복사한 뒤 제외 경로, 수용 규칙, fuzz 횟수와 CI 실패 기준을 조정합니다. CLI 옵션은 설정 파일보다 우선합니다.

```toml
[scan]
exclude = ["lib/**", "vendor/**"]
ignore_rules = ["AQ005"]
fail_on = "high"
fuzz_cases = 2000
qsharp = "required"
external_tools = true
```

결과는 기본적으로 다음 위치에 생성됩니다.

- `reports/antiq-report.json`
- `reports/antiq-report.html`
- `reports/antiq-report.md`
- `reports/antiq-report.sarif`

## 개발 검증

```bash
forge test
PYTHONPATH=python .venv/bin/python -m unittest discover -s tests
.venv/bin/antiq . --external-tools --fuzz-cases 512
```

## 중요한 범위 제한

Q#은 EVM 내부에서 실행되지 않습니다. 이 프로젝트에서 Q#은 공격자 모델, 동적 Grover 상태 탐색, 정책·업그레이드·트랜잭션 순서·ERC-4337·키 회전·가디언 복구 검증을 담당합니다. 실제 온체인 승인은 Solidity verifier 또는 체인/L2의 PQ precompile이 담당해야 합니다. `AntiQ4337Account`는 ERC-4337 계정 인터페이스, crypto-agile PQ verifier 경계, PQ 키 회전을 구현합니다. 가디언 복구는 현재 Q# 정책 모델이며 아직 온체인 복구 모듈은 아닙니다. 실제 운영 배포 전에는 공식 EntryPoint 통합 테스트와 표준 ML-DSA/SLH-DSA verifier 또는 precompile adapter가 필요합니다.
