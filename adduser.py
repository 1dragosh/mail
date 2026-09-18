import os
import sys
import mysql.connector
from passlib.hash import pbkdf2_sha256

DB_PASS = os.environ["DB_PASS"]

if len(sys.argv) != 3:
    print("usage: adduser.py <username> <password>")
    raise SystemExit(1)

username = sys.argv[1].strip()
password = sys.argv[2]

if not username or len(password) < 8:
    print("username required, password must be at least 8 characters")
    raise SystemExit(1)

conn = mysql.connector.connect(
    host="127.0.0.1", user="postfix", password=DB_PASS, database="postfixadmin"
)
cur = conn.cursor()
cur.execute(
    "CREATE TABLE IF NOT EXISTS ui_users ("
    "id INT AUTO_INCREMENT PRIMARY KEY,"
    "username VARCHAR(255) NOT NULL UNIQUE,"
    "password_hash VARCHAR(255) NOT NULL,"
    "created DATETIME NOT NULL,"
    "last_login DATETIME NULL,"
    "active TINYINT(1) DEFAULT 1"
    ")"
)
cur.execute(
    "INSERT INTO ui_users (username, password_hash, created, active) "
    "VALUES (%s, %s, NOW(), 1) "
    "ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), active=1",
    (username, pbkdf2_sha256.hash(password)),
)
try:
    cur.execute("DELETE FROM ui_sessions WHERE username=%s", (username,))
except mysql.connector.Error:
    pass
conn.commit()
cur.close()
conn.close()
print("ok: " + username)
