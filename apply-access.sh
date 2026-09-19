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

if ! postconf -h smtpd_recipient_restrictions | grep -q sender_access; then
    CUR=$(postconf -h smtpd_recipient_restrictions)
    if echo "$CUR" | grep -q reject_unauth_destination; then
        postconf -e "smtpd_recipient_restrictions = ${CUR/reject_unauth_destination/reject_unauth_destination, check_sender_access hash:$DST}"
    else
        postconf -e "smtpd_recipient_restrictions = check_sender_access hash:$DST, $CUR"
    fi
fi

postfix check
systemctl reload postfix
echo "applied"
