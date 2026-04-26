#!/bin/bash
# Ruleaza DUPA ce ai obtinut certificatul SSL si ai configurat PostfixAdmin
# Adauga domeniul si primul admin prin CLI (optional, poti face din UI)

set -euo pipefail

MAIL_HOSTNAME="mail.example.com"   # same as setup.sh
MAIL_DOMAIN="example.com"          # same as setup.sh
ADMIN_EMAIL="admin@example.com"    # adresa de admin PostfixAdmin
ADMIN_PASS="schimba-parola-asta"

echo "Rulezi PostfixAdmin CLI setup..."

cd /var/www/postfixadmin

php scripts/postfixadmin-cli.php \
    setup \
    --superadmin 1 \
    --email "${ADMIN_EMAIL}" \
    --password "${ADMIN_PASS}"

php scripts/postfixadmin-cli.php \
    domain add \
    --domain "${MAIL_DOMAIN}" \
    --description "Main domain" \
    --aliases 1000 \
    --mailboxes 0

echo ""
echo "Admin creat: ${ADMIN_EMAIL}"
echo "Acceseaza: https://${MAIL_HOSTNAME}"
echo ""
echo "Din UI poti acum adauga aliases (forwarding rules):"
echo "  Virtual List -> Add Alias"
echo "  Address: orice@${MAIL_DOMAIN}"
echo "  Forward to: orice@gmail.com (sau orice alta adresa)"
