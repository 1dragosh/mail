#!/bin/bash
set -euo pipefail

MAIL_HOSTNAME="mail.cerberustext.com"
MAIL_DOMAIN="cerberustext.com"
ADMIN_EMAIL="dragos@waits.ro"

DB_NAME="postfixadmin"
DB_USER="postfix"
DB_PASS=$(openssl rand -hex 20)
POSTFIXADMIN_VERSION="3.3.13"
POSTFIXADMIN_DIR="/var/www/postfixadmin"
PHP_VER="8.3"

echo "============================================"
echo "  Mail Server Setup"
echo "  Hostname : $MAIL_HOSTNAME"
echo "  Domain   : $MAIL_DOMAIN"
echo "  Admin    : $ADMIN_EMAIL"
echo "============================================"
echo ""
echo "  DB_PASS (salveaza-l!): $DB_PASS"
echo ""

echo "$DB_PASS" > /root/.mailserver_db_pass
chmod 600 /root/.mailserver_db_pass

apt-get update
apt-get install -y \
    postfix postfix-mysql \
    mariadb-server \
    nginx \
    "php${PHP_VER}-fpm" "php${PHP_VER}-mysql" "php${PHP_VER}-imap" \
    "php${PHP_VER}-mbstring" "php${PHP_VER}-xml" "php${PHP_VER}-curl" \
    "php${PHP_VER}-intl" "php${PHP_VER}-zip" \
    certbot python3-certbot-nginx \
    postsrsd \
    wget curl unzip

DEBIAN_FRONTEND=noninteractive debconf-set-selections <<< "postfix postfix/mailname string $MAIL_HOSTNAME"
DEBIAN_FRONTEND=noninteractive debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure postfix

echo "$MAIL_HOSTNAME" > /etc/mailname

systemctl enable mariadb
systemctl start mariadb

mysql -u root <<SQLEOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

wget -q -O /tmp/postfixadmin.tgz \
    "https://github.com/postfixadmin/postfixadmin/archive/postfixadmin-${POSTFIXADMIN_VERSION}.tar.gz"
mkdir -p "$POSTFIXADMIN_DIR"
tar -xzf /tmp/postfixadmin.tgz -C /tmp
cp -r "/tmp/postfixadmin-postfixadmin-${POSTFIXADMIN_VERSION}/." "$POSTFIXADMIN_DIR/"
mkdir -p "$POSTFIXADMIN_DIR/templates_c"
chown -R www-data:www-data "$POSTFIXADMIN_DIR"
chmod -R 750 "$POSTFIXADMIN_DIR"

cat > "$POSTFIXADMIN_DIR/config.local.php" <<PHPEOF
<?php
\$CONF['configured'] = true;
\$CONF['setup_password'] = '';
\$CONF['default_language'] = 'en';
\$CONF['database_type'] = 'mysqli';
\$CONF['database_host'] = 'localhost';
\$CONF['database_user'] = '${DB_USER}';
\$CONF['database_password'] = '${DB_PASS}';
\$CONF['database_name'] = '${DB_NAME}';
\$CONF['mail_server'] = '${MAIL_HOSTNAME}';
\$CONF['domain_path'] = 'NO';
\$CONF['domain_in_mailbox'] = 'YES';
\$CONF['aliases'] = '1000';
\$CONF['virtual_domains'] = '50';
\$CONF['footer'] = 'NO';
\$CONF['show_footer_text'] = 'NO';
\$CONF['emailcheck_resolve_domain'] = 'YES';
\$CONF['alias_control'] = 'YES';
\$CONF['alias_control_admin'] = 'YES';
\$CONF['used_quotas'] = 'NO';
\$CONF['new_quota_table'] = 'NO';
\$CONF['virtual_vacation'] = 'NO';
\$CONF['sendmail'] = 'NO';
\$CONF['smtp_server'] = 'localhost';
\$CONF['smtp_port'] = '25';
PHPEOF

PHP_SOCK="/var/run/php/php${PHP_VER}-fpm.sock"

cat > /etc/nginx/sites-available/postfixadmin <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${MAIL_HOSTNAME};
    root ${POSTFIXADMIN_DIR}/public;
    index index.php;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include fastcgi_params;
        fastcgi_pass unix:${PHP_SOCK};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    location ~ /\. {
        deny all;
    }

    location ~* \.(tpl|tpl\.php)\$ {
        deny all;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/postfixadmin /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

mkdir -p /etc/postfix/mysql

cat > /etc/postfix/mysql/virtual-domains.cf <<MEOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT domain FROM domain WHERE domain='%s' AND active='1' AND backupmx='0'
MEOF

cat > /etc/postfix/mysql/virtual-aliases.cf <<MEOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT goto FROM alias WHERE address='%s' AND active='1'
MEOF

cat > /etc/postfix/mysql/virtual-aliases-domain.cf <<MEOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = localhost
dbname = ${DB_NAME}
query = SELECT CONCAT(goto) FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' AND alias.address = CONCAT('%u', '@', alias_domain.target_domain) AND alias.active = 1 AND alias_domain.active='1'
MEOF

chmod 640 /etc/postfix/mysql/*.cf
chown root:postfix /etc/postfix/mysql/*.cf

cat > /etc/postfix/main.cf <<EOF
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

smtpd_tls_cert_file = /etc/letsencrypt/live/${MAIL_HOSTNAME}/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/${MAIL_HOSTNAME}/privkey.pem
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

smtpd_relay_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    defer_unauth_destination

myhostname = ${MAIL_HOSTNAME}
myorigin = /etc/mailname
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

virtual_alias_domains = mysql:/etc/postfix/mysql/virtual-domains.cf
virtual_alias_maps =
    mysql:/etc/postfix/mysql/virtual-aliases.cf,
    mysql:/etc/postfix/mysql/virtual-aliases-domain.cf

sender_canonical_maps = tcp:localhost:10001
sender_canonical_classes = envelope_sender
recipient_canonical_maps = tcp:localhost:10002
recipient_canonical_classes = envelope_recipient, header_recipient

local_transport = error:local mail delivery is disabled
EOF

SRS_SECRET=$(openssl rand -hex 20)
echo "$SRS_SECRET" > /etc/postsrsd.secret
chmod 600 /etc/postsrsd.secret

POSTSRSD_DEFAULT="/etc/default/postsrsd"
if [ -f "$POSTSRSD_DEFAULT" ]; then
    sed -i "s/^SRS_DOMAIN=.*/SRS_DOMAIN=${MAIL_DOMAIN}/" "$POSTSRSD_DEFAULT" || true
fi

cat > /etc/postsrsd.conf <<SRSEOF
srs-domain=${MAIL_DOMAIN}
srs-secret=/etc/postsrsd.secret
forward-port=10001
reverse-port=10002
SRSEOF

if getent passwd postsrsd > /dev/null 2>&1; then
    chown postsrsd:postsrsd /etc/postsrsd.secret
fi

systemctl enable nginx "php${PHP_VER}-fpm" postfix
systemctl restart nginx "php${PHP_VER}-fpm"

systemctl enable postsrsd || true
systemctl restart postsrsd || echo "postsrsd nu a pornit inca - se va porni dupa SSL"

echo ""
echo "============================================"
echo "  Instalare completa!"
echo "============================================"
echo ""
echo "PASUL 1 - DNS (fa asta ACUM daca nu ai facut):"
echo "  A   mail.cerberustext.com -> 152.53.226.144"
echo "  MX  cerberustext.com      -> mail.cerberustext.com  (prio 10)"
echo ""
echo "PASUL 2 - SSL (dupa ce DNS propagat):"
echo "  sudo certbot --nginx -d mail.cerberustext.com"
echo ""
echo "PASUL 3 - Restart postfix dupa SSL:"
echo "  sudo systemctl restart postfix postsrsd"
echo ""
echo "PASUL 4 - PostfixAdmin setup:"
echo "  https://mail.cerberustext.com/setup.php"
echo ""
echo "DB_PASS salvat in /root/.mailserver_db_pass"
