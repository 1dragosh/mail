#!/bin/bash
set -euo pipefail

SRC="/opt/mailmanager/sender_access.txt"
DST="/etc/postfix/sender_access"

if [ ! -f "$SRC" ]; then
    echo "missing $SRC" >&2
    exit 1
fi

install -o root -g root -m 644 "$SRC" "$DST"
postmap "$DST"

if ! postconf smtpd_sender_restrictions | grep -q sender_access; then
    postconf -e "smtpd_sender_restrictions = check_sender_access hash:$DST"
fi

postfix check
systemctl reload postfix
echo "applied"
