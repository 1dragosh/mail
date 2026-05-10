#!/bin/bash
set -euo pipefail

DOMAIN="$1"
KEY_DIR="/etc/opendkim/keys/$DOMAIN"
KEY_TABLE="/etc/opendkim/KeyTable"
SIGNING_TABLE="/etc/opendkim/SigningTable"

if [ -f "$KEY_DIR/mail.private" ]; then
    exit 0
fi

mkdir -p "$KEY_DIR"
opendkim-genkey -b 2048 -d "$DOMAIN" -D "$KEY_DIR" -s mail
chown opendkim:opendkim "$KEY_DIR" "$KEY_DIR/mail.private" "$KEY_DIR/mail.txt"
chmod 755 "$KEY_DIR"
chmod 640 "$KEY_DIR/mail.private"
chmod 644 "$KEY_DIR/mail.txt"

KEYTABLE_ENTRY="mail._domainkey.$DOMAIN $DOMAIN:mail:$KEY_DIR/mail.private"
SIGNING_ENTRY="*@$DOMAIN mail._domainkey.$DOMAIN"

grep -qF "$KEYTABLE_ENTRY" "$KEY_TABLE" || echo "$KEYTABLE_ENTRY" >> "$KEY_TABLE"
grep -qF "$SIGNING_ENTRY" "$SIGNING_TABLE" || echo "$SIGNING_ENTRY" >> "$SIGNING_TABLE"

systemctl reload opendkim
