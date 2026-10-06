# Anti-Quantum

[English](README.md) · [한국어](README.ko.md) · **日本語**

Anti-Quantum は研究向けのスマートコントラクトセキュリティツールです。Solidity、Vyper、Yul のパターン検査、バイトコードのフィンガープリント、ポリシーファジング、Q# セキュリティモデル、任意の Foundry・Slither 実行結果を JSON、HTML、Markdown、SARIF レポートにまとめます。

## 主な機能

- 単一ファイルまたはプロジェクトを検査し、場所と重大度を含む確認候補を報告します。
- バイトコードと再現可能なソース manifest の SHA-256 フィンガープリントを生成します。
- 認可、nonce、ガーディアン、凍結、コード整合性のポリシーをファジングします。
- QDK が利用可能な場合、Q# のポリシー、アップグレード、リプレイ、ERC-4337、鍵ローテーション、ガーディアン復旧、Grover のハーネスを実行します。
- `--external-tools` で一時コピー上の Forge と Slither を実行します。
- 以前の JSON レポートとの差分を表示し、CI の重大度基準を適用します。

## インストール

Python 3.10 以降が必要です。Foundry と Slither は任意です。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

CLI コマンドは `antiq` です。既存の連携を維持するため、Python import パス `anti_qsignature` と Q# 名前空間 `AntiQSignature` はそのままです。

## スキャン

```bash
.venv/bin/antiq /absolute/path/to/contracts
.venv/bin/antiq /absolute/path/to/project --fuzz-cases 2000 --qsharp required --fail-on high
.venv/bin/antiq /absolute/path/to/project --external-tools --baseline reports/previous.json
```

パスなしで実行すると対話形式で入力できます。デスクトップでは `--pick-file` と `--pick-dir` を利用できます。`--qsharp off` は Q# を省略し、`--qsharp required` は実行できない場合にエラーを返します。既定の `auto` は利用不可の状態を記録して処理を続けます。

出力先の既定値は `reports/antiq-report.{json,html,md,sarif}` です。終了コードは成功 `0`、`--fail-on` の基準に該当 `2`、入力または実行エラー `1` です。

対象プロジェクトで `.antiq.toml.example` を `.antiq.toml` にコピーすると、除外パス、許容するルール、ファジング回数、Q# モード、外部ツール、CI 基準を設定できます。CLI オプションが優先されます。

## 検証

```bash
forge test
PYTHONPATH=python .venv/bin/python -m unittest discover -s tests
.venv/bin/antiq . --qsharp required --fuzz-cases 512
```

## 適用範囲とセキュリティ上の制限

パターン検査の結果は確認候補であり、脆弱性の確定ではありません。Q# はオフチェーンの攻撃・ポリシーモデルであり、EVM 署名を検証しません。`AntiQSmartWallet` は ECDSA と Merkle Lamport 検証を示す研究用プロトタイプで、calldata とガスのコストが大きくなります。`AntiQ4337Account` は交換可能な耐量子署名検証インターフェースを備えますが、本番運用には検証済みの ML-DSA または SLH-DSA 実装か precompile アダプター、EntryPoint 統合テスト、独立したセキュリティ監査が必要です。ガーディアン復旧は現在 Q# ポリシーモデルのみで、オンチェーンモジュールではありません。リソース推定はモデル化した Q# 回路についての値であり、secp256k1 全体に対する Shor 攻撃の推定値ではありません。

## ライセンス

[MIT](LICENSE) © 2026 Kazto.
