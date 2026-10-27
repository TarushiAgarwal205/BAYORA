"""Explicit operator commands for audit checkpoint bootstrap and recovery."""

import argparse
import sys

from backend.audit_store import AuditStore
from backend.config import AUDIT_CHECKPOINT_KEY, AUDIT_CHECKPOINT_PATH, AUDIT_DB_PATH


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap = subparsers.add_parser(
        "bootstrap", help="anchor an existing locally verified audit chain"
    )
    bootstrap.add_argument(
        "--approve-current-history", action="store_true",
        help="acknowledge that pre-checkpoint history and any prior tail loss cannot be proven",
    )
    recover = subparsers.add_parser(
        "recover", help="approve one locally verified unanchored revision"
    )
    recover.add_argument(
        "--approve-unanchored-revision", action="store_true",
        help="confirm the unanchored revision and its external-operation outcome were reviewed",
    )
    args = parser.parse_args(argv)
    store = AuditStore(
        AUDIT_DB_PATH,
        checkpoint_path=AUDIT_CHECKPOINT_PATH,
        checkpoint_key=AUDIT_CHECKPOINT_KEY,
    )
    try:
        if args.command == "bootstrap":
            if not args.approve_current_history:
                parser.error("bootstrap requires --approve-current-history")
            store.initialize(allow_checkpoint_bootstrap=True)
            print(
                "Checkpoint established for the current verified chain. "
                "History before this checkpoint is not independently verified."
            )
        else:
            result = store.recover_checkpoint(
                approve_unanchored_revision=args.approve_unanchored_revision
            )
            print(result["reason"])
    except Exception as error:
        print(f"Audit checkpoint operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
