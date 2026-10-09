#!/usr/bin/env python3
"""Compare Go symbol sizes and normalized disassembly, not release binary bytes."""

import difflib
import hashlib
import re
import subprocess
import sys


def symbol_sizes(text):
    """Discard symbol addresses while retaining names, kinds and sizes."""
    result = []
    for line in text.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 3 and fields[1] == "U":
            result.append("U " + fields[2])  # Mach-O imports have no size column.
        elif len(fields) == 4:
            # Mach-O sizes include line tables and inferred padding, not instructions.
            if fields[3] in ("runtime.pclntab", "runtime.epclntab"):
                fields[1] = "<source-layout>"
            result.append(" ".join(fields[1:]))
        else:
            raise ValueError(f"unexpected nm line: {line}")
    return sorted(result)


def symbol_hashes(text):
    """Hash instructions per symbol without source locations or layout operands."""
    symbols = {}
    name = None
    instructions = []
    page_register = None
    for line in text.splitlines():
        if line.startswith("TEXT "):
            if name is not None:
                symbols[name] = hashlib.sha256("\n".join(instructions).encode()).hexdigest()
            name = line.split("(SB)", 1)[0][5:]
            instructions = []
            page_register = None
        elif line.strip():
            # objdump columns are source location, address, encoded bytes, assembly.
            fields = line.split(None, 3)
            if name is None or len(fields) != 4:
                raise ValueError(f"unexpected objdump line: {line}")
            instruction = fields[3].strip()
            # ARM64 address materialization spans ADRP and its following instruction.
            if page_register is not None:
                instruction = re.sub(r"^(ADD \$)[0-9]+(, " + page_register + r", " + page_register + r")$", r"\1<offset>\2", instruction)
                instruction = re.sub(r"-?[0-9]+\(" + page_register + r"\)", "<offset>(" + page_register + ")", instruction)
            page = re.fullmatch(r"ADRP -?[0-9]+\(PC\), (R[0-9]+)", instruction)
            page_register = page.group(1) if page else None
            instruction = re.sub(r"(?<![\w$])0x[0-9a-fA-F]+(?![\w(])", "<address>", instruction)
            instruction = re.sub(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)\((IP|PC)\)", r"<offset>(\1)", instruction)
            instruction = re.sub(r"\+[0-9]+\(SB\)", "+<offset>(SB)", instruction)
            instructions.append(instruction)
    if name is not None:
        symbols[name] = hashlib.sha256("\n".join(instructions).encode()).hexdigest()
    if not symbols:
        raise ValueError("no disassembled symbols")
    return symbols


def inspect(binary):
    """Bound Go inspection tools and fail closed on unsupported output."""
    def output(tool, *args):
        """Capture one bounded tool invocation, including its failure diagnostics."""
        return subprocess.run(
            ["go", "tool", tool, *args, binary], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        ).stdout

    return symbol_sizes(output("nm", "-size", "-sort", "name")), symbol_hashes(output("objdump"))


def main(args):
    """Print differing symbols and return nonzero for either comparison failure."""
    if len(args) != 3:
        raise ValueError("usage: release_symbols.py NAME BASE HEAD")
    name, old, new = args
    print(f"NOTICE {name}: runtime.pclntab/runtime.epclntab source-line metadata sizes are normalized; names and kinds remain checked")
    old_sizes, old_hashes = inspect(old)
    new_sizes, new_hashes = inspect(new)
    failed = False
    if old_sizes != new_sizes:
        failed = True
        for entry in sorted(set(old_sizes) ^ set(new_sizes)):
            print(f"FAIL {name} symbol/size: {entry}")
    for symbol in sorted(old_hashes.keys() | new_hashes.keys()):
        if old_hashes.get(symbol) != new_hashes.get(symbol):
            failed = True
            print(f"FAIL {name} disassembly: {symbol} base={old_hashes.get(symbol, 'missing')} head={new_hashes.get(symbol, 'missing')}")
            # Show the actual instruction changes, not just opaque digest differences.
            dumps = []
            for binary in (old, new):
                dump = subprocess.run(["go", "tool", "objdump", "-s", "^" + re.escape(symbol) + "$", binary], check=True, capture_output=True, text=True, timeout=180).stdout
                dumps.append([re.sub(r"0x[0-9a-fA-F]+", "<address>", line.split(None, 3)[3]) for line in dump.splitlines() if line.strip() and not line.startswith("TEXT ")])
            print("\n".join(difflib.unified_diff(*dumps, fromfile="base", tofile="head", n=1)))
    if not failed:
        print(f"PASS {name} symbol sizes and normalized per-symbol disassembly ({len(new_hashes)} symbols)")
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL symbol inspection: {error}", file=sys.stderr)
        sys.exit(1)
