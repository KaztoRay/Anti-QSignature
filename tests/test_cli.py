import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from anti_qsignature.cli import choose_target, main


class CliInputTests(unittest.TestCase):
    def test_empty_interactive_target_is_rejected(self) -> None:
        with patch("builtins.input", return_value="  "):
            with self.assertRaisesRegex(ValueError, "target is required"):
                choose_target(None)

    def test_unsupported_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "notes.txt"
            file.write_text("example", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                choose_target(str(file))

    def test_invalid_fuzz_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "Safe.sol"
            file.write_text("contract Safe {}", encoding="utf-8")
            self.assertEqual(main([str(file), "--fuzz-cases", "0", "--qsharp", "off"]), 1)


if __name__ == "__main__":
    unittest.main()
