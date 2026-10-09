"""Exercise layout normalization without accepting changed symbol sizes or instructions."""

import contextlib
import importlib.util
import io
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("release_symbols", Path(__file__).with_name("release_symbols.py"))
if SPEC is None or SPEC.loader is None:
    raise ImportError("release_symbols.py is missing")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class ReleaseSymbolsTest(unittest.TestCase):
    """Keep source-layout tolerance distinct from actual machine-code changes."""

    def test_sizes_ignore_addresses_and_order(self):
        """Symbol movement must pass while a changed symbol size remains visible."""
        old = "  1000 8 T main.a\n  2000 16 D main.b\n"
        moved = "  4000 16 D main.b\n  3000 8 T main.a\n"
        self.assertEqual(PROOF.symbol_sizes(old), PROOF.symbol_sizes(moved))
        self.assertNotEqual(PROOF.symbol_sizes(old), PROOF.symbol_sizes(moved.replace("16 D", "24 D")))

    def test_disassembly_ignores_layout(self):
        """Headers, declarations, encoded relocations and branch addresses may move."""
        old = "TEXT main.a(SB) /src/a.go\n  a.go:10 0x1000 e801 CALL main.b(SB)\n  a.go:11 0x1002 eb01 JMP 0x1000\n  a.go:12 0x1004 8b01 MOVQ 123(IP), AX\n"
        moved = old.replace("a.go", "shared.go").replace(":10", ":50").replace("0x100", "0x400").replace("eb01", "eb02").replace("123(IP)", "456(IP)")
        self.assertEqual(PROOF.symbol_hashes(old), PROOF.symbol_hashes(moved))
        for changed in (moved.replace("main.b", "main.c"), moved.replace("MOVQ", "MOVL"), moved.replace("AX", "BX")):
            self.assertNotEqual(PROOF.symbol_hashes(old), PROOF.symbol_hashes(changed))

    def test_arm_address_pair_and_constants(self):
        """Normalize paired address operands without discarding ordinary constants."""
        old = "TEXT main.a(SB) a.go\n a.go:1 0x1000 abc ADRP 4096(PC), R1\n a.go:2 0x1004 def ADD $128, R1, R1\n a.go:3 0x1008 ghi ADD $128, R1, R1\n a.go:4 0x100c jkl MOVQ $0x80, AX\n"
        moved = old.replace("4096(PC)", "8192(PC)").replace("def ADD $128", "def ADD $256")
        self.assertEqual(PROOF.symbol_hashes(old), PROOF.symbol_hashes(moved))
        for changed in (moved.replace("ghi ADD $128", "ghi ADD $256"), moved.replace("$0x80", "$0x81")):
            self.assertNotEqual(PROOF.symbol_hashes(old), PROOF.symbol_hashes(changed))
        self.assertEqual(PROOF.symbol_sizes("100 U _import"), PROOF.symbol_sizes("200 U _import"))

    def test_comparison_exit_and_diagnostics(self):
        """Changed sizes, instructions and missing symbols must name the failure."""
        for new, expected in ((["9 T main.a"], {"main.a": "old"}), (["8 T main.a"], {"main.a": "new"}), (["8 T main.a"], {})):
            with patch.object(PROOF, "inspect", side_effect=[(["8 T main.a"], {"main.a": "old"}), (new, expected)]), patch.object(PROOF.subprocess, "run") as tool, contextlib.redirect_stdout(io.StringIO()) as output:
                tool.return_value.stdout = ""
                self.assertEqual(PROOF.main(["fixture", "base", "head"]), 1)
                self.assertIn("main.a", output.getvalue())
        with patch.object(PROOF, "inspect", return_value=(["8 T main.a"], {"main.a": "same"})), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROOF.main(["fixture", "base", "head"]), 0)
            self.assertIn("PASS fixture", output.getvalue())

    def test_line_metadata_sizes_only(self):
        """Line-table sizes may move, but their names and kinds remain required."""
        old = "100 16 R runtime.pclntab\n200 8 R runtime.epclntab"
        moved = "300 32 R runtime.pclntab\n400 24 R runtime.epclntab"
        self.assertEqual(PROOF.symbol_sizes(old), PROOF.symbol_sizes(moved))
        for changed in (moved.replace("R runtime.pclntab", "D runtime.pclntab"), moved.replace("runtime.epclntab", "runtime.other")):
            self.assertNotEqual(PROOF.symbol_sizes(old), PROOF.symbol_sizes(changed))

    def test_missing_and_invalid_output(self):
        """Unsupported tool output cannot silently produce an empty passing proof."""
        for text in ("", "unexpected", "TEXT main.a(SB) a.go\nmalformed"):
            with self.assertRaises(ValueError):
                PROOF.symbol_hashes(text)
        with self.assertRaises(ValueError):
            PROOF.symbol_sizes("unexpected")


if __name__ == "__main__":
    unittest.main()
