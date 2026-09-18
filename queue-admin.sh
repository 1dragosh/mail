#!/bin/bash
set -euo pipefail

action="${1:-}"

case "$action" in
    flush)
        postqueue -f
        ;;
    delete)
        qid="${2:-}"
        if ! printf '%s' "$qid" | grep -qE '^[A-Za-z0-9]{6,32}$'; then
            echo "bad queue id" >&2
            exit 1
        fi
        postsuper -d "$qid"
        ;;
    delete-all)
        postsuper -d ALL
        ;;
    *)
        echo "usage: queue-admin.sh flush|delete <qid>|delete-all" >&2
        exit 1
        ;;
esac
