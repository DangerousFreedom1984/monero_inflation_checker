#!/usr/bin/env python3
"""MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

fcmp_tool.py - the FCMP++ command line.

    verify-tx   run the complete verification on one transaction
                (membership + SAL + Bulletproof+ + commitment balance)
    scan        walk a testnet chain and verify every FCMP++ transaction in it

Everything runs on this repo's own pure-Python code: the arithmetic circuit in
mic/fcmp/{circuit,gadgets}.py, the Generalized-Bulletproofs engine in
mic/fcmp/gbp.py, and the transaction machinery in mic/txlib/. A node, when used,
is only a data source. Both commands are thin wrappers over mic/tools/scan.py.

Run `python fcmp_tool.py <command> --help` for per-command options.
"""

import argparse
import json
import os


# --------------------------------------------------------------------------- #
#  verify-tx
# --------------------------------------------------------------------------- #


def cmd_verify_tx(args):
    """Verify one transaction given as a raw blob (.hex) or a decoded JSON file."""
    from mic.fcmp import PARAMS_FILE
    from mic.tools import scan as _scan

    with open(args.file) as f:
        raw = f.read().strip()

    blob_hex, tx_json = None, None
    if args.file.endswith(".json") or raw.lstrip().startswith("{"):
        tx_json = json.loads(raw)
        if args.blob:
            with open(args.blob) as f:
                blob_hex = f.read().strip()
    else:
        blob_hex = raw
        try:
            tx_json = _scan.tx_json_from_blob(bytes.fromhex(blob_hex))
        except Exception as e:
            raise SystemExit(f"cannot parse {args.file} as a transaction blob: {e}")

    root_hex = args.tree_root
    if root_hex is None:
        # a sibling <file>.root holding the tree root as hex
        guess = os.path.splitext(args.file)[0] + ".root"
        if os.path.exists(guess):
            root_hex = open(guess).read().strip()
            print(f"[root] using {guess}")
    if root_hex is None:
        raise SystemExit(
            "--tree-root <hex> is required: the curve-tree root the tx's reference "
            "block commits to, or a sibling <file>.root holding it as hex"
        )

    params = _scan.load_params(args.params or PARAMS_FILE)
    checks = tuple(c.strip() for c in args.checks.split(",") if c.strip())

    result = _scan.verify_tx(
        tx_json, blob_hex, bytes.fromhex(root_hex), params,
        checks=checks, txid=args.txid,
    )
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(_scan.format_result(result, indent=""))
        print()
        print("RESULT:", "VALID" if result["ok"] else
              ("INVALID" if result.get("any_fail") else "INCOMPLETE"))
    return 0 if result["ok"] else 1


# --------------------------------------------------------------------------- #
#  argument parsing
# --------------------------------------------------------------------------- #


def build_parser():
    p = argparse.ArgumentParser(
        prog="fcmp_tool.py",
        description=__doc__.split("\n\n", 1)[1].split("Run `python")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    # -- verify-tx -------------------------------------------------------
    v = sub.add_parser("verify-tx", help="fully verify one FCMP++ transaction")
    v.add_argument("file", help="raw tx blob (.hex) or decoded tx JSON (.json)")
    v.add_argument("--tree-root", default=None, metavar="HEX",
                   help="curve-tree root the tx's reference block commits to")
    v.add_argument("--blob", default=None, metavar="FILE",
                   help="raw blob to pair with a .json input (needed for the SAL check)")
    v.add_argument("--txid", default=None, help="transaction id, for the report header")
    v.add_argument("--checks", default="membership,sal,bp,balance",
                   help="comma-separated subset of: membership, sal, bp, balance")
    v.add_argument("--params", default=None, help="path to input_params.txt")
    v.add_argument("--json", action="store_true", help="print the result as JSON")

    # -- scan ------------------------------------------------------------
    from mic.tools import scan as _scan

    s = sub.add_parser("scan", help="verify every FCMP++ transaction on a testnet chain")
    _scan.build_parser(s)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.command == "verify-tx":
        return cmd_verify_tx(args)

    if args.command == "scan":
        from mic.tools import scan as _scan
        return _scan.run(args)

    raise SystemExit(f"unknown command {args.command!r}")


if __name__ == "__main__":
    raise SystemExit(main())
