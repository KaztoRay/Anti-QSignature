import tempfile
import unittest
from pathlib import Path

from anti_qsignature.fuzzer import run_policy_fuzz
from anti_qsignature.scanner import discover_files, scan_sources


class ScannerTests(unittest.TestCase):
    def test_detects_tx_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Unsafe.sol"
            source.write_text(
                "pragma solidity ^0.8.24; contract Unsafe { function x() external { require(tx.origin == msg.sender); } }"
            )
            files = discover_files(root)
            findings = scan_sources(files, root)
            self.assertTrue(any(item.rule_id == "AQ001" for item in findings))

    def test_reference_policy_fuzzer_has_no_counterexamples(self) -> None:
        report = run_policy_fuzz(1000, 7)
        self.assertEqual(report["invariant_failures"], 0)


if __name__ == "__main__":
    unittest.main()
