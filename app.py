import email as stdlib_email
import html as _html
import imaplib
import os
import re
import secrets
import smtplib
import subprocess
import time
import httpx
import mysql.connector
from collections import defaultdict
from contextlib import asynccontextmanager
from email.header import decode_header as _decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from fastapi import FastAPI, Request, Form, Cookie, Header, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from passlib.hash import md5_crypt, pbkdf2_sha256
from pydantic import BaseModel

MAIL_SERVER = os.environ["MAIL_SERVER"]
SERVER_IP = os.environ["SERVER_IP"]
DB_PASS = os.environ["DB_PASS"]
MASTER_PASS = os.environ["MASTER_PASS"]
SECRET = os.environ["SECRET"]
MAIL_BASE = os.environ.get("MAIL_BASE", "/var/mail/vhosts")
INBOXROAD_URL = os.environ.get("INBOXROAD_URL", "https://webapi.inboxroad.com/api/v1")
INBOXROAD_KEY = os.environ.get("INBOXROAD_KEY", "")
STREAMS = ("transactional", "marketing")

_login_attempts = defaultdict(list)
_pending_keys = {}


def check_login_rate(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < 300]
    if len(_login_attempts[ip]) >= 10:
        raise HTTPException(429, "Too many login attempts. Try again in 5 minutes.")
    _login_attempts[ip].append(now)


def db():
    return mysql.connector.connect(
        host="127.0.0.1", user="postfix", password=DB_PASS, database="postfixadmin"
    )


@asynccontextmanager
async def lifespan(app):
    conn = db()
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
        "CREATE TABLE IF NOT EXISTS ui_sessions ("
        "token VARCHAR(64) NOT NULL PRIMARY KEY,"
        "username VARCHAR(255) NOT NULL,"
        "created DATETIME NOT NULL,"
        "expires DATETIME NOT NULL,"
        "INDEX (expires)"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS sender_rules ("
        "id INT AUTO_INCREMENT PRIMARY KEY,"
        "pattern VARCHAR(255) NOT NULL UNIQUE,"
        "action VARCHAR(16) NOT NULL DEFAULT 'REJECT',"
        "note VARCHAR(255) NOT NULL DEFAULT '',"
        "active TINYINT(1) NOT NULL DEFAULT 1,"
        "created DATETIME NOT NULL"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS bounce_log ("
        "id INT AUTO_INCREMENT PRIMARY KEY,"
        "qid VARCHAR(32) NOT NULL,"
        "recipient VARCHAR(320) NOT NULL,"
        "sender VARCHAR(320) NOT NULL DEFAULT '',"
        "status VARCHAR(16) NOT NULL,"
        "dsn VARCHAR(16) NOT NULL DEFAULT '',"
        "reason VARCHAR(500) NOT NULL DEFAULT '',"
        "seen_at DATETIME NOT NULL,"
        "UNIQUE KEY uq_event (qid, recipient, status),"
        "INDEX (recipient), INDEX (seen_at)"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS suppression ("
        "recipient VARCHAR(320) NOT NULL PRIMARY KEY,"
        "dsn VARCHAR(16) NOT NULL DEFAULT '',"
        "reason VARCHAR(500) NOT NULL DEFAULT '',"
        "source VARCHAR(16) NOT NULL DEFAULT 'auto',"
        "created DATETIME NOT NULL"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS marketing_log ("
        "id INT AUTO_INCREMENT PRIMARY KEY,"
        "message_id VARCHAR(255) NOT NULL DEFAULT '',"
        "recipient VARCHAR(320) NOT NULL,"
        "sender VARCHAR(320) NOT NULL DEFAULT '',"
        "subject VARCHAR(500) NOT NULL DEFAULT '',"
        "provider VARCHAR(32) NOT NULL DEFAULT 'inboxroad',"
        "status VARCHAR(16) NOT NULL,"
        "detail VARCHAR(500) NOT NULL DEFAULT '',"
        "sent_at DATETIME NOT NULL,"
        "INDEX (recipient), INDEX (sent_at)"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS kv_state ("
        "k VARCHAR(64) NOT NULL PRIMARY KEY,"
        "v VARCHAR(255) NOT NULL DEFAULT ''"
        ")"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS api_keys ("
        "id INT AUTO_INCREMENT PRIMARY KEY,"
        "name VARCHAR(255) NOT NULL,"
        "key_value VARCHAR(255) NOT NULL UNIQUE,"
        "created DATETIME NOT NULL,"
        "active TINYINT(1) DEFAULT 1"
        ")"
    )
    conn.commit()
    cur.close()
    conn.close()
    yield


app = FastAPI(title="Mail Manager", docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)
templates = Jinja2Templates(directory="/opt/mailmanager/templates")


def hash_pw(pw):
    return md5_crypt.hash(pw)


def _count_dir(path):
    try:
        return len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
    except OSError:
        return 0


def maildir_stats(username):
    base = os.path.join(MAIL_BASE, username)
    unread = _count_dir(os.path.join(base, "new"))
    read = _count_dir(os.path.join(base, "cur"))
    sent = _count_dir(os.path.join(base, ".Sent", "new")) + _count_dir(os.path.join(base, ".Sent", "cur"))
    return {"received": unread + read, "unread": unread, "sent": sent}


def _dkim_value(domain):
    txt_path = f"/etc/opendkim/keys/{domain}/mail.txt"
    try:
        raw = open(txt_path).read()
        parts = re.findall(r'"([^"]+)"', raw)
        return "".join(parts)
    except Exception:
        return ""


def _generate_dkim(domain):
    result = subprocess.run(
        ["sudo", "/opt/mailmanager/gen-dkim.sh", domain],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "gen-dkim.sh failed")


def dns_for(domain):
    records = [
        {"type": "MX", "name": "@", "value": MAIL_SERVER, "prio": "10", "ttl": "3600"},
        {"type": "TXT", "name": "@", "value": f"v=spf1 a:{MAIL_SERVER} ~all", "prio": "-", "ttl": "3600"},
        {"type": "TXT", "name": "_dmarc", "value": f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}", "prio": "-", "ttl": "3600"},
    ]
    dkim = _dkim_value(domain)
    if dkim:
        records.append({"type": "TXT", "name": "mail._domainkey", "value": dkim, "prio": "-", "ttl": "3600"})
    return records


def session_user(token):
    if not token:
        return ""
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT u.username FROM ui_sessions s JOIN ui_users u ON u.username=s.username "
        "WHERE s.token=%s AND s.expires > NOW() AND u.active=1",
        (token,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row["username"] if row else ""


MAIL_LOG = os.environ.get("MAIL_LOG", "/var/log/mail.log")

_STATUS_RE = re.compile(r"status=(sent|deferred|bounced|expired)")
_QID_RE = re.compile(r"postfix/[a-z]+\[[0-9]+\]: ([0-9A-F]{6,}):")
_TO_RE = re.compile(r"to=<([^>]*)>")
_REASON_RE = re.compile(r"status=(?:deferred|bounced|expired) \((.*)\)\s*$")
_RBL_RE = re.compile(r"blocked using ([a-z0-9.\-]+)", re.I)
_REJECT_RE = re.compile(r"NOQUEUE: (reject|reject_warning): RCPT from ([^\[]*)\[([0-9a-f.:]+)\]")


def run_cmd(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def read_mail_log(max_lines=40000):
    try:
        with open(MAIL_LOG, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            chunk = min(size, max_lines * 200)
            fh.seek(size - chunk)
            data = fh.read().decode("utf-8", "replace")
        return data.splitlines()[-max_lines:]
    except Exception:
        return []


def queue_summary():
    out = run_cmd(["postqueue", "-p"])
    if not out.strip():
        return {"available": False, "count": 0, "size_kb": 0, "entries": []}
    items = []
    total = 0
    size_kb = 0
    tail = out.strip().splitlines()[-1]
    m = re.search(r"--\s*([0-9]+)\s*Kbytes in\s*([0-9]+)\s*Request", tail)
    if m:
        size_kb = int(m.group(1))
        total = int(m.group(2))
    block = []
    for line in out.splitlines():
        if not line.strip():
            if block:
                items.append(parse_queue_block(block))
                block = []
            continue
        if line.startswith("-") or line.startswith("Mail queue"):
            continue
        block.append(line)
    if block:
        items.append(parse_queue_block(block))
    items = [i for i in items if i.get("id")]
    return {"available": True, "count": total or len(items), "size_kb": size_kb, "entries": items[:60]}


def parse_queue_block(block):
    head = block[0].split()
    qid = head[0].rstrip("*!") if head else ""
    sender = head[-1] if len(head) > 3 else ""
    when = " ".join(head[2:6]) if len(head) > 6 else ""
    reason = ""
    rcpt = ""
    for line in block[1:]:
        t = line.strip()
        if t.startswith("(") and t.endswith(")"):
            reason = t[1:-1]
        elif "@" in t:
            rcpt = t
    return {"id": qid, "sender": sender, "when": when, "rcpt": rcpt, "reason": reason}


def log_health():
    lines = read_mail_log()
    if not lines:
        return {"available": False}
    final = {}
    counts = defaultdict(int)
    reasons = defaultdict(int)
    rbl = defaultdict(int)
    rejects = []
    bounces = []
    for line in lines:
        m = _STATUS_RE.search(line)
        if m:
            qid = _QID_RE.search(line)
            if qid:
                final[qid.group(1)] = m.group(1)
            else:
                counts[m.group(1)] += 1
            if m.group(1) in ("deferred", "bounced", "expired"):
                rm = _REASON_RE.search(line)
                if rm:
                    reasons[shorten_reason(rm.group(1))] += 1
                if m.group(1) == "bounced" and len(bounces) < 40:
                    tm = _TO_RE.search(line)
                    bounces.append({
                        "when": " ".join(line.split()[:1]),
                        "to": tm.group(1) if tm else "",
                        "reason": shorten_reason(rm.group(1)) if rm else "",
                    })
        rj = _REJECT_RE.search(line)
        if rj:
            bl = _RBL_RE.search(line)
            key = bl.group(1) if bl else "other"
            rbl[key] += 1
            if len(rejects) < 60:
                rejects.append({
                    "when": " ".join(line.split()[:1]),
                    "mode": "would block" if rj.group(1) == "reject_warning" else "blocked",
                    "host": rj.group(2).strip() or "-",
                    "ip": rj.group(3),
                    "list": key,
                })
    for status in final.values():
        counts[status] += 1
    sent = counts.get("sent", 0)
    failed = counts.get("deferred", 0) + counts.get("bounced", 0) + counts.get("expired", 0)
    total = sent + failed
    return {
        "available": True,
        "sent": sent,
        "deferred": counts.get("deferred", 0),
        "bounced": counts.get("bounced", 0),
        "expired": counts.get("expired", 0),
        "retry_lines": len(lines),
        "fail_pct": round(100.0 * failed / total, 1) if total else 0.0,
        "reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:10],
        "rbl": sorted(rbl.items(), key=lambda kv: -kv[1]),
        "rejects": list(reversed(rejects))[:40],
        "bounces": list(reversed(bounces))[:25],
        "lines_scanned": len(lines),
    }


def shorten_reason(text):
    t = re.sub(r"\s+", " ", text).strip()
    t = re.sub(r"\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b", "IP", t)
    t = re.sub(r"<[^>]*>", "<addr>", t)
    for pat, label in (
        (r"Connection timed out", "Connection timed out"),
        (r"Host or domain name not found|Name service error", "Host not found"),
        (r"User unknown|Unknown user|does not exist|Recipient address rejected", "Recipient unknown"),
        (r"spam|blocked|blacklist|reputation", "Rejected as spam"),
        (r"Insufficient system resources", "Remote out of resources"),
        (r"certificate|TLS", "TLS problem"),
    ):
        if re.search(pat, t, re.I):
            return label
    return t[:70]


def domain_mail_health(domains):
    rows = []
    for d in domains:
        name = d["domain"] if isinstance(d, dict) else d
        if name == "ALL":
            continue
        rows.append({
            "domain": name,
            "dkim_local": bool(_dkim_value(name)),
            "dkim_dns": txt_has(f"mail._domainkey.{name}", "v=DKIM1"),
            "spf": txt_has(name, "v=spf1"),
            "dmarc": txt_has(f"_dmarc.{name}", "v=DMARC1"),
        })
    return rows


def txt_has(name, needle):
    out = run_cmd(["dig", "+short", "+time=2", "+tries=1", name, "TXT"], timeout=6)
    return needle.lower() in out.lower()


_FROM_RE = re.compile(r"postfix/[a-z]+\[[0-9]+\]: ([0-9A-F]{6,}): from=<([^>]*)>")
_DSN_RE = re.compile(r"dsn=([0-9]\.[0-9]+\.[0-9]+)")
NO_SUCH_ADDRESS = re.compile(r"^5\.1\.[0-9]+$")
_MONTHS = {}


def ingest_mail_log():
    lines = read_mail_log()
    if not lines:
        return {"scanned": 0, "events": 0, "suppressed": 0}
    senders = {}
    events = []
    for line in lines:
        f = _FROM_RE.search(line)
        if f:
            senders[f.group(1)] = f.group(2).strip()
            continue
        m = _STATUS_RE.search(line)
        if not m or m.group(1) not in ("bounced", "deferred", "expired"):
            continue
        qid = _QID_RE.search(line)
        to = _TO_RE.search(line)
        if not qid or not to:
            continue
        dsn = _DSN_RE.search(line)
        reason = _REASON_RE.search(line)
        events.append({
            "qid": qid.group(1),
            "recipient": to.group(1)[:320],
            "sender": senders.get(qid.group(1), "")[:320],
            "status": m.group(1),
            "dsn": dsn.group(1) if dsn else "",
            "reason": (reason.group(1) if reason else "")[:500],
            "when": log_line_time(line),
        })
    if not events:
        return {"scanned": len(lines), "events": 0, "suppressed": 0}

    conn = db()
    cur = conn.cursor()
    stored = 0
    for e in events:
        cur.execute(
            "INSERT IGNORE INTO bounce_log "
            "(qid, recipient, sender, status, dsn, reason, seen_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (e["qid"], e["recipient"], e["sender"], e["status"], e["dsn"], e["reason"], e["when"]),
        )
        stored += cur.rowcount

    suppressed = 0
    for e in events:
        if e["status"] != "bounced" or not NO_SUCH_ADDRESS.match(e["dsn"]):
            continue
        if not e["sender"]:
            continue
        cur.execute(
            "INSERT IGNORE INTO suppression (recipient, dsn, reason, source, created) "
            "VALUES (%s,%s,%s,'auto',NOW())",
            (e["recipient"], e["dsn"], e["reason"]),
        )
        suppressed += cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return {"scanned": len(lines), "events": stored, "suppressed": suppressed}


def log_line_time(line):
    head = line.split()[0] if line else ""
    m = re.match(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})", head)
    if m:
        return m.group(1) + " " + m.group(2)
    return time.strftime("%Y-%m-%d %H:%M:%S")


def kv_get(key):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT v FROM kv_state WHERE k=%s", (key,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else ""


def kv_set(key, value):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO kv_state (k, v) VALUES (%s,%s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
        (key, str(value)[:255]),
    )
    conn.commit()
    cur.close()
    conn.close()


def inboxroad_headers():
    return {"Authorization": "Basic " + INBOXROAD_KEY, "Content-Type": "application/json"}


def inboxroad_send(sender, recipient, subject, text_body, html_body, extra_headers):
    if not INBOXROAD_KEY:
        return "", "INBOXROAD_KEY is not set on this server"
    payload = {
        "from_email": sender,
        "to_email": recipient,
        "subject": subject or "",
        "text": text_body or "",
        "html": html_body or "",
    }
    if extra_headers:
        payload["headers"] = extra_headers
    try:
        r = httpx.post(
            INBOXROAD_URL.rstrip("/") + "/messages/",
            json=payload,
            headers=inboxroad_headers(),
            timeout=30,
        )
    except Exception as e:
        return "", str(e)
    try:
        data = r.json() if r.content else {}
    except Exception:
        data = {}
    if r.status_code in (200, 201, 202):
        return str(data.get("message_id") or data.get("id") or ""), ""
    detail = data.get("detail") or data.get("message") or r.text
    return "", "HTTP %s %s" % (r.status_code, str(detail)[:200])


def inboxroad_fetch(path, cursor_key):
    last = kv_get(cursor_key)
    params = {"order": "asc"}
    if last:
        params["last_id"] = last
    r = httpx.get(
        INBOXROAD_URL.rstrip("/") + path,
        params=params,
        headers=inboxroad_headers(),
        timeout=30,
    )
    r.raise_for_status()
    data = r.json() if r.content else {}
    rows = data.get("results", data) if isinstance(data, dict) else data
    return rows if isinstance(rows, list) else []


def inboxroad_row_email(row):
    for k in ("recipient", "email", "to_email", "to", "address"):
        v = row.get(k)
        if v:
            return str(v).strip().lower()
    return ""


def poll_inboxroad_events():
    if not INBOXROAD_KEY:
        return 0, 0
    bounced = 0
    complained = 0
    conn = db()
    cur = conn.cursor()
    for path, cursor_key, status, dsn, hard in (
        ("/bounces", "ir_bounce_last_id", "bounced", "", True),
        ("/fbl", "ir_fbl_last_id", "complaint", "", True),
    ):
        try:
            rows = inboxroad_fetch(path, cursor_key)
        except Exception:
            continue
        for row in rows:
            rcpt = inboxroad_row_email(row)
            if not rcpt:
                continue
            rid = str(row.get("id") or row.get("bounce_id") or "")
            reason = str(row.get("reason") or row.get("description") or row.get("status") or "")[:500]
            code = str(row.get("code") or row.get("dsn") or dsn)[:16]
            cur.execute(
                "INSERT IGNORE INTO bounce_log "
                "(qid, recipient, sender, status, dsn, reason, seen_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,NOW())",
                ("ir-" + rid, rcpt, str(row.get("from_email") or "")[:320], status, code, reason),
            )
            if hard and is_hard_inboxroad(status, code, reason):
                cur.execute(
                    "INSERT INTO suppression (recipient, dsn, reason, source, created) "
                    "VALUES (%s,%s,%s,'inboxroad',NOW()) "
                    "ON DUPLICATE KEY UPDATE reason=VALUES(reason)",
                    (rcpt, code, reason),
                )
            if status == "bounced":
                bounced += 1
            else:
                complained += 1
            if rid:
                kv_set(cursor_key, rid)
    conn.commit()
    cur.close()
    conn.close()
    return bounced, complained


def is_hard_inboxroad(status, code, reason):
    if status == "complaint":
        return True
    if NO_SUCH_ADDRESS.match(code.strip()):
        return True
    return bool(re.search(r"\b5\.1\.[0-9]+\b", reason))


def marketing_summary(limit=25):
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT status, COUNT(*) n FROM marketing_log "
        "WHERE sent_at >= NOW() - INTERVAL 7 DAY GROUP BY status"
    )
    totals = {r["status"]: r["n"] for r in cur.fetchall()}
    cur.execute(
        "SELECT recipient, sender, subject, status, detail, sent_at "
        "FROM marketing_log ORDER BY id DESC LIMIT %s",
        (limit,),
    )
    recent = cur.fetchall()
    cur.execute(
        "SELECT COUNT(*) n FROM bounce_log WHERE qid LIKE 'ir-%' "
        "AND seen_at >= NOW() - INTERVAL 7 DAY"
    )
    events = cur.fetchone()["n"]
    cur.close()
    conn.close()
    return {
        "sent": totals.get("sent", 0),
        "failed": totals.get("failed", 0),
        "events": events,
        "recent": recent,
        "configured": bool(INBOXROAD_KEY),
    }


def suppressed_recipients(addresses):
    wanted = [a.strip().lower() for a in addresses if a and a.strip()]
    if not wanted:
        return set()
    conn = db()
    cur = conn.cursor()
    marks = ",".join(["%s"] * len(wanted))
    cur.execute("SELECT recipient FROM suppression WHERE LOWER(recipient) IN (" + marks + ")", wanted)
    hits = {r[0].lower() for r in cur.fetchall()}
    cur.close()
    conn.close()
    return hits


def suppression_list(limit=200):
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT recipient, dsn, reason, source, created FROM suppression "
        "ORDER BY created DESC LIMIT %s",
        (limit,),
    )
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS n FROM suppression")
    total = cur.fetchone()["n"]
    cur.close()
    conn.close()
    return rows, total


ACCESS_FILE = os.environ.get("ACCESS_FILE", "/opt/mailmanager/sender_access.txt")
ACCESS_ACTIONS = ("REJECT", "DISCARD", "OK")
_PATTERN_OK = re.compile(r"^[A-Za-z0-9._@+-]{3,255}$")


def sender_rules():
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, pattern, action, note, active, created FROM sender_rules ORDER BY pattern")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def write_access_map():
    rows = sender_rules()
    lines = []
    for r in rows:
        if not r["active"]:
            continue
        note = re.sub(r"[\r\n]", " ", r["note"])[:120]
        if r["action"] == "OK":
            note = ""
        lines.append((r["pattern"] + "\t" + r["action"] + " " + note).rstrip())
    try:
        with open(ACCESS_FILE, "w") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as e:
        return False, "cannot write " + ACCESS_FILE + ": " + str(e)
    out = run_cmd(["sudo", "/opt/mailmanager/apply-access.sh"], timeout=40)
    if "applied" not in out:
        return False, (out.strip()[-200:] or "apply-access.sh produced no output, check its sudo rule")
    return True, ""


def queue_bounce_ids():
    q = queue_summary()
    ids = []
    for it in q.get("entries", []):
        sender = (it.get("sender") or "").strip()
        if sender in ("", "MAILER-DAEMON"):
            ids.append(it["id"])
    return ids


def ui_auth(auth):
    user = session_user(auth)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


def api_auth(authorization):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.removeprefix("Bearer ")
    if token == SECRET:
        return
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM api_keys WHERE key_value=%s AND active=1", (token,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, error: int = 0):
    return templates.TemplateResponse(request, "login.html", {"error": error})


@app.post("/login")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.headers.get("x-real-ip", request.client.host)
    check_login_rate(ip)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT username, password_hash FROM ui_users WHERE username=%s AND active=1",
        (username.strip(),),
    )
    row = cur.fetchone()
    ok = False
    if row:
        try:
            ok = pbkdf2_sha256.verify(password, row["password_hash"])
        except Exception:
            ok = False
    token = ""
    if ok:
        token = secrets.token_urlsafe(32)
        w = conn.cursor()
        w.execute("DELETE FROM ui_sessions WHERE expires <= NOW()")
        w.execute(
            "INSERT INTO ui_sessions (token, username, created, expires) "
            "VALUES (%s, %s, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY))",
            (token, row["username"]),
        )
        w.execute("UPDATE ui_users SET last_login=NOW() WHERE username=%s", (row["username"],))
        conn.commit()
        w.close()
    cur.close()
    conn.close()
    if not ok:
        return RedirectResponse("/login?error=1", status_code=303)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie("auth", token, httponly=True, secure=True, samesite="lax", max_age=86400 * 30)
    return r


@app.get("/logout")
async def logout(auth: str | None = Cookie(default=None)):
    if auth:
        conn = db()
        cur = conn.cursor()
        cur.execute("DELETE FROM ui_sessions WHERE token=%s", (auth,))
        conn.commit()
        cur.close()
        conn.close()
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie("auth")
    return r


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    auth: str | None = Cookie(default=None),
    tab: str = "domains",
    msg: str = "",
    dns: str = "",
    new_key: str = "",
    reveal: str = "",
):
    if not session_user(auth):
        return RedirectResponse("/login", status_code=303)

    if reveal:
        new_key = _pending_keys.pop(reveal, "")

    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT domain, description, active FROM domain WHERE domain != 'ALL' ORDER BY domain")
    domains = cur.fetchall()
    cur.execute("SELECT m.username, m.name, m.domain, m.active, a.goto FROM mailbox m LEFT JOIN alias a ON a.address=m.username AND a.active=1 ORDER BY m.domain, m.username")
    mailboxes = cur.fetchall()
    for m in mailboxes:
        m.update(maildir_stats(m["username"]))
    cur.execute(
        "SELECT address, goto, domain, active FROM alias "
        "WHERE address NOT LIKE '@%%' ORDER BY domain, address"
    )
    aliases = cur.fetchall()
    cur.execute("SELECT id, name, key_value, created FROM api_keys WHERE active=1 ORDER BY created DESC")
    api_keys = cur.fetchall()
    cur.close()
    conn.close()

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "domains": domains,
            "mailboxes": mailboxes,
            "aliases": aliases,
            "api_keys": api_keys,
            "tab": tab,
            "msg": msg,
            "new_key": new_key,
            "dns_domain": dns,
            "dns_records": dns_for(dns) if dns else [],
            "mail_server": MAIL_SERVER,
            "server_ip": SERVER_IP,
        },
    )


@app.get("/health", response_class=HTMLResponse)
async def health_page(request: Request, auth: str | None = Cookie(default=None), msg: str = ""):
    user = session_user(auth)
    if not user:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT domain FROM domain WHERE domain != 'ALL' ORDER BY domain")
    domains = cur.fetchall()
    cur.close()
    conn.close()
    try:
        ingest_mail_log()
    except Exception:
        pass
    try:
        poll_inboxroad_events()
    except Exception:
        pass
    supp_rows, supp_total = suppression_list()
    return templates.TemplateResponse(
        request,
        "health.html",
        {
            "user": user,
            "msg": msg,
            "queue": queue_summary(),
            "log": log_health(),
            "domains": domain_mail_health(domains),
            "mail_log": MAIL_LOG,
            "suppressed": supp_rows,
            "suppressed_total": supp_total,
            "rules": sender_rules(),
            "marketing": marketing_summary(),
        },
    )


@app.post("/health/unsuppress")
async def unsuppress(recipient: str = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM suppression WHERE recipient=%s", (recipient.strip(),))
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/health?msg=Removed+from+suppression+list", status_code=303)


@app.post("/health/rules/add")
async def rule_add(
    pattern: str = Form(...),
    action: str = Form("REJECT"),
    note: str = Form(""),
    auth: str | None = Cookie(default=None),
):
    ui_auth(auth)
    clean = pattern.strip().lower().lstrip("@")
    if not _PATTERN_OK.match(clean):
        return RedirectResponse("/health?msg=Rejected:+not+a+valid+domain+or+address", status_code=303)
    if action not in ACCESS_ACTIONS:
        action = "REJECT"
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sender_rules (pattern, action, note, active, created) "
        "VALUES (%s,%s,%s,1,NOW()) "
        "ON DUPLICATE KEY UPDATE action=VALUES(action), note=VALUES(note), active=1",
        (clean, action, note.strip()[:255]),
    )
    conn.commit()
    cur.close()
    conn.close()
    ok, detail = write_access_map()
    return RedirectResponse(
        "/health?msg=" + ("Rule+applied" if ok else "Saved+but+Postfix+refused:+" + detail[:80]),
        status_code=303,
    )


@app.post("/health/rules/remove")
async def rule_remove(rule_id: int = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM sender_rules WHERE id=%s", (rule_id,))
    conn.commit()
    cur.close()
    conn.close()
    ok, detail = write_access_map()
    return RedirectResponse(
        "/health?msg=" + ("Rule+removed" if ok else "Removed+but+Postfix+refused:+" + detail[:80]),
        status_code=303,
    )


@app.post("/health/queue-delete-bounces")
async def queue_delete_bounces(auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    ids = queue_bounce_ids()
    for qid in ids:
        run_cmd(["sudo", "/opt/mailmanager/queue-admin.sh", "delete", qid], timeout=20)
    return RedirectResponse(
        "/health?msg=Deleted+" + str(len(ids)) + "+undeliverable+bounce(s)", status_code=303
    )


@app.post("/health/queue-delete-all")
async def queue_delete_all(confirm: str = Form(""), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    if confirm.strip().upper() != "DELETE":
        return RedirectResponse("/health?msg=Type+DELETE+to+empty+the+queue", status_code=303)
    run_cmd(["sudo", "/opt/mailmanager/queue-admin.sh", "delete-all"], timeout=60)
    return RedirectResponse("/health?msg=Queue+emptied", status_code=303)


@app.post("/health/queue-flush")
async def queue_flush(auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    run_cmd(["postqueue", "-f"], timeout=30)
    return RedirectResponse("/health?msg=Queue+flush+requested", status_code=303)


@app.post("/domains/add")
async def add_domain(
    domain: str = Form(...),
    description: str = Form(""),
    auth: str | None = Cookie(default=None),
):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO domain "
        "(domain, description, aliases, mailboxes, maxquota, quota, transport, backupmx, created, modified, active) "
        "VALUES (%s, %s, 1000, 0, 0, 0, 'virtual', 0, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE active=1, description=%s, modified=NOW()",
        (domain, description, description),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(f"/?tab=domains&dns={domain}&msg=Domain+added", status_code=303)


@app.post("/domains/delete")
async def delete_domain(domain: str = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE alias SET active=0 WHERE domain=%s", (domain,))
    cur.execute("UPDATE mailbox SET active=0 WHERE domain=%s", (domain,))
    cur.execute("UPDATE domain SET active=0 WHERE domain=%s", (domain,))
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=domains&msg=Domain+deleted", status_code=303)


@app.post("/mailboxes/add")
async def add_mailbox(
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(""),
    forward_to: str = Form(""),
    auth: str | None = Cookie(default=None),
):
    ui_auth(auth)
    parts = email.split("@")
    if len(parts) != 2:
        return RedirectResponse("/?tab=mailboxes&msg=Invalid+email", status_code=303)
    local, domain = parts
    maildir = f"{email}/"
    pw_hash = hash_pw(password)
    goto = email
    if forward_to.strip():
        extra = [f.strip() for f in forward_to.split(",") if f.strip()]
        goto = ",".join([email] + extra)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mailbox "
        "(username, password, name, maildir, local_part, domain, created, modified, active) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 1)",
        (email, pw_hash, name or local, maildir, local, domain),
    )
    cur.execute(
        "INSERT INTO alias (address, goto, domain, created, modified, active) "
        "VALUES (%s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE goto=%s, modified=NOW()",
        (email, goto, domain, goto),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=mailboxes&msg=Mailbox+created", status_code=303)


@app.post("/mailboxes/delete")
async def delete_mailbox(email: str = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE mailbox SET active=0 WHERE username=%s", (email,))
    cur.execute("UPDATE alias SET active=0 WHERE address=%s", (email,))
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=mailboxes&msg=Mailbox+deleted", status_code=303)


@app.post("/aliases/add")
async def add_alias(
    address: str = Form(...),
    forward_to: str = Form(...),
    auth: str | None = Cookie(default=None),
):
    ui_auth(auth)
    parts = address.split("@")
    if len(parts) != 2:
        return RedirectResponse("/?tab=aliases&msg=Invalid+address", status_code=303)
    local, domain = parts
    forwards = [f.strip() for f in forward_to.split(",") if f.strip()]
    goto = ",".join([address] + forwards)
    pw_hash = hash_pw(secrets.token_urlsafe(16))
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mailbox "
        "(username, password, name, maildir, local_part, domain, created, modified, active) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE active=1, modified=NOW()",
        (address, pw_hash, local, f"{address}/", local, domain),
    )
    cur.execute(
        "INSERT INTO alias (address, goto, domain, created, modified, active) "
        "VALUES (%s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE goto=%s, modified=NOW(), active=1",
        (address, goto, domain, goto),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=aliases&msg=Alias+created", status_code=303)


@app.post("/aliases/delete")
async def delete_alias(address: str = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE alias SET active=0 WHERE address=%s", (address,))
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=aliases&msg=Alias+deleted", status_code=303)


@app.post("/apikeys/create")
async def create_api_key(name: str = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    key = secrets.token_urlsafe(32)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO api_keys (name, key_value, created, active) VALUES (%s, %s, NOW(), 1)",
        (name, key),
    )
    conn.commit()
    cur.close()
    conn.close()
    token = secrets.token_urlsafe(16)
    _pending_keys[token] = key
    return RedirectResponse(f"/?tab=apikeys&reveal={token}&msg=API+key+created", status_code=303)


@app.post("/apikeys/delete")
async def delete_api_key(key_id: int = Form(...), auth: str | None = Cookie(default=None)):
    ui_auth(auth)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE api_keys SET active=0 WHERE id=%s", (key_id,))
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/?tab=apikeys&msg=API+key+deleted", status_code=303)


@app.get("/login-as/{email:path}")
async def login_as(email: str, request: Request, auth: str | None = Cookie(default=None)):
    if not session_user(auth):
        return RedirectResponse("/login", status_code=303)
    ua = request.headers.get("user-agent", "Mozilla/5.0")
    headers = {"Host": MAIL_SERVER, "User-Agent": ua}
    async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
        r1 = await client.get("https://127.0.0.1/wm/", headers=headers)
        match = re.search(r'"request_token":"([^"]+)"', r1.text)
        if not match:
            raise HTTPException(500, "Could not fetch Roundcube token")
        token = match.group(1)
        r2 = await client.post(
            "https://127.0.0.1/wm/?_task=login&_action=login",
            headers=headers,
            data={"_token": token, "_task": "login", "_action": "login",
                  "_user": f"{email}*admin", "_pass": MASTER_PASS},
            cookies=r1.cookies,
        )
    if r2.status_code not in (301, 302, 303) or "roundcube_sessauth" not in r2.cookies:
        raise HTTPException(500, "Roundcube login failed")
    new_sessid = r2.cookies["roundcube_sessid"]
    new_sessauth = r2.cookies["roundcube_sessauth"]
    html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Opening webmail...</title></head>
<body><script>window.location.replace('/wm/');</script></body></html>"""
    resp = HTMLResponse(html)
    for name in ("roundcube_sessid", "roundcube_sessauth"):
        resp.delete_cookie(name, path="/")
        resp.delete_cookie(name, path="/", domain=MAIL_SERVER)
    resp.set_cookie("roundcube_sessid", new_sessid, httponly=True, secure=True, samesite="lax", path="/")
    resp.set_cookie("roundcube_sessauth", new_sessauth, httponly=True, secure=True, samesite="lax", path="/")
    return resp


class DomainIn(BaseModel):
    domain: str
    description: str = ""


class MailboxIn(BaseModel):
    email: str
    password: str
    name: str = ""
    forward_to: list[str] = []


class AliasIn(BaseModel):
    address: str
    forward_to: list[str]


@app.get("/api/domains")
async def api_list_domains(authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT domain, description, active FROM domain WHERE domain != 'ALL' ORDER BY domain")
    result = cur.fetchall()
    cur.close()
    conn.close()
    return result


@app.post("/api/domains", status_code=201)
async def api_add_domain(body: DomainIn, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO domain "
        "(domain, description, aliases, mailboxes, maxquota, quota, transport, backupmx, created, modified, active) "
        "VALUES (%s, %s, 1000, 0, 0, 0, 'virtual', 0, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE active=1, description=%s, modified=NOW()",
        (body.domain, body.description, body.description),
    )
    conn.commit()
    cur.close()
    conn.close()
    try:
        _generate_dkim(body.domain)
    except Exception:
        pass
    return {"domain": body.domain, "description": body.description, "active": True, "dns_records": dns_for(body.domain)}


@app.post("/api/domains/{domain}/dkim", status_code=200)
async def api_generate_dkim(domain: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    try:
        _generate_dkim(domain)
    except Exception as e:
        raise HTTPException(500, f"DKIM generation failed: {e}")
    dkim = _dkim_value(domain)
    if not dkim:
        raise HTTPException(500, "DKIM key generated but could not be read")
    return {"domain": domain, "selector": "mail", "dkim": dkim}


@app.get("/api/domains/{domain}/dns")
async def api_domain_dns(domain: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    return {"domain": domain, "dns_records": dns_for(domain)}


@app.delete("/api/domains/{domain}")
async def api_delete_domain(domain: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE domain SET active=0 WHERE domain=%s", (domain,))
    conn.commit()
    cur.close()
    conn.close()
    return {"deleted": domain}


@app.get("/api/domains/{domain}/stats")
async def api_domain_stats(domain: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM mailbox WHERE domain=%s AND active=1", (domain,))
    mailboxes = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS cnt FROM alias WHERE domain=%s AND active=1 AND address NOT LIKE '@%%'", (domain,))
    alias_count = cur.fetchone()["cnt"]
    cur.close()
    conn.close()
    totals = {"received": 0, "unread": 0, "sent": 0}
    per_mailbox = []
    for m in mailboxes:
        s = maildir_stats(m["username"])
        per_mailbox.append({"email": m["username"], **s})
        totals["received"] += s["received"]
        totals["unread"] += s["unread"]
        totals["sent"] += s["sent"]
    return {
        "domain": domain,
        "mailboxes": len(mailboxes),
        "aliases": alias_count,
        **totals,
        "per_mailbox": per_mailbox,
    }


@app.get("/api/mailboxes")
async def api_list_mailboxes(authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT m.username, m.name, m.domain, m.active, a.goto FROM mailbox m LEFT JOIN alias a ON a.address=m.username AND a.active=1 ORDER BY m.domain, m.username")
    result = cur.fetchall()
    cur.close()
    conn.close()
    return result


@app.post("/api/mailboxes", status_code=201)
async def api_add_mailbox(body: MailboxIn, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    parts = body.email.split("@")
    if len(parts) != 2:
        raise HTTPException(400, "Invalid email")
    local, domain = parts
    pw_hash = hash_pw(body.password)
    goto = body.email
    if body.forward_to:
        goto = ",".join([body.email] + body.forward_to)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mailbox "
        "(username, password, name, maildir, local_part, domain, created, modified, active) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 1)",
        (body.email, pw_hash, body.name or local, f"{body.email}/", local, domain),
    )
    cur.execute(
        "INSERT INTO alias (address, goto, domain, created, modified, active) "
        "VALUES (%s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE goto=%s, modified=NOW()",
        (body.email, goto, domain, goto),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"email": body.email, "forward_to": body.forward_to, "created": True}


def _decode_str(value):
    if not value:
        return ""
    parts = _decode_header(value)
    result = []
    for bval, charset in parts:
        if isinstance(bval, bytes):
            result.append(bval.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(bval)
    return "".join(result)


def _clean_text(text):
    text = re.sub(r'[\u00ad\u034f\u200b-\u200f\u2028\u2029\ufeff]', '', text)
    text = _html.unescape(text)
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _parse_imap_msg(uid, raw):
    msg = stdlib_email.message_from_bytes(raw)
    body = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            if ct == "text/plain" and not body:
                try:
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
            elif ct == "text/html" and not body_html:
                try:
                    body_html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
    else:
        try:
            raw_body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                body_html = raw_body
            else:
                body = raw_body
        except Exception:
            pass
    if not body and body_html:
        body = re.sub(r'<[^>]+>', ' ', body_html)
        body = re.sub(r'\s+', ' ', body).strip()
    return {
        "uid": uid.decode() if isinstance(uid, bytes) else str(uid),
        "from": _decode_str(msg.get("From", "")),
        "to": _decode_str(msg.get("To", "")),
        "subject": _decode_str(msg.get("Subject", "(no subject)")),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "body": _clean_text(body[:5000]),
        "body_html": body_html[:80000],
    }


@app.get("/api/mailboxes/{email}/messages")
async def api_list_messages(
    email: str,
    folder: str = "INBOX",
    page: int = 1,
    per_page: int = 25,
    authorization: str | None = Header(default=None),
):
    api_auth(authorization)
    try:
        imap = imaplib.IMAP4("127.0.0.1", 143)
        imap.login(f"{email}*admin", MASTER_PASS)
        imap.select(folder)
        _, data = imap.search(None, "ALL")
        uids = data[0].split() if data[0] else []
        total = len(uids)
        uids_page = list(reversed(uids))[(page - 1) * per_page: page * per_page]
        messages = []
        for uid in uids_page:
            try:
                _, msg_data = imap.fetch(uid, "(RFC822)")
                if msg_data and msg_data[0]:
                    messages.append(_parse_imap_msg(uid, msg_data[0][1]))
            except Exception:
                pass
        imap.logout()
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"email": email, "folder": folder, "total": total, "page": page, "per_page": per_page, "messages": messages}


@app.delete("/api/mailboxes/{email}/messages/{uid}")
async def api_delete_message(
    email: str,
    uid: str,
    folder: str = "INBOX",
    authorization: str | None = Header(default=None),
):
    api_auth(authorization)
    try:
        imap = imaplib.IMAP4("127.0.0.1", 143)
        imap.login(f"{email}*admin", MASTER_PASS)
        imap.select(folder)
        imap.store(uid.encode(), "+FLAGS", "\\Deleted")
        imap.expunge()
        imap.logout()
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"deleted": uid}


@app.delete("/api/mailboxes/{email:path}")
async def api_delete_mailbox(email: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE mailbox SET active=0 WHERE username=%s", (email,))
    cur.execute("UPDATE alias SET active=0 WHERE address=%s", (email,))
    conn.commit()
    cur.close()
    conn.close()
    return {"deleted": email}


@app.get("/api/mailboxes/{email:path}/stats")
async def api_mailbox_stats(email: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    return {"email": email, **maildir_stats(email)}


@app.get("/api/aliases")
async def api_list_aliases(authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT address, goto, domain, active FROM alias "
        "WHERE address NOT LIKE '@%%' ORDER BY domain, address"
    )
    result = cur.fetchall()
    cur.close()
    conn.close()
    for row in result:
        row["forward_to"] = [f.strip() for f in row["goto"].split(",") if f.strip() and f.strip() != row["address"]]
    return result


@app.post("/api/aliases", status_code=201)
async def api_add_alias(body: AliasIn, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    parts = body.address.split("@")
    if len(parts) != 2:
        raise HTTPException(400, "Invalid address")
    local, domain = parts
    goto = ",".join([body.address] + body.forward_to)
    pw_hash = hash_pw(secrets.token_urlsafe(16))
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mailbox "
        "(username, password, name, maildir, local_part, domain, created, modified, active) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE active=1, modified=NOW()",
        (body.address, pw_hash, local, f"{body.address}/", local, domain),
    )
    cur.execute(
        "INSERT INTO alias (address, goto, domain, created, modified, active) "
        "VALUES (%s, %s, %s, NOW(), NOW(), 1) "
        "ON DUPLICATE KEY UPDATE goto=%s, modified=NOW(), active=1",
        (body.address, goto, domain, goto),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"address": body.address, "forward_to": body.forward_to, "active": True, "created": True}


@app.delete("/api/aliases/{address:path}")
async def api_delete_alias(address: str, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE alias SET active=0 WHERE address=%s", (address,))
    conn.commit()
    cur.close()
    conn.close()
    return {"deleted": address}


class SendEmailIn(BaseModel):
    from_email: str
    to: list[str]
    subject: str
    body: str
    body_html: str = ""
    reply_to_id: str = ""
    unsubscribe_url: str = ""
    stream: str = "transactional"


@app.post("/api/send", status_code=200)
async def api_send_email(body: SendEmailIn, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    stream = body.stream.strip().lower() or "transactional"
    if stream not in STREAMS:
        raise HTTPException(400, "stream must be one of: " + ", ".join(STREAMS))
    if stream == "marketing" and not INBOXROAD_KEY:
        raise HTTPException(503, "marketing stream unavailable: INBOXROAD_KEY is not set")
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM mailbox WHERE username=%s AND active=1", (body.from_email,))
    if not cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(400, "from_email not a valid active mailbox")
    cur.close()
    conn.close()

    blocked = suppressed_recipients(body.to)
    targets = [t for t in body.to if t.strip().lower() not in blocked]
    if not targets:
        raise HTTPException(
            422,
            "every recipient is on the suppression list after a hard bounce: "
            + ", ".join(sorted(blocked)),
        )

    if body.body_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body.body, "plain", "utf-8"))
        msg.attach(MIMEText(body.body_html, "html", "utf-8"))
    else:
        msg = MIMEText(body.body, "plain", "utf-8")

    msg["From"] = body.from_email
    msg["To"] = ", ".join(targets)
    msg["Subject"] = body.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=body.from_email.split("@")[1])
    if body.reply_to_id:
        msg["In-Reply-To"] = body.reply_to_id
        msg["References"] = body.reply_to_id
    if body.unsubscribe_url:
        u = body.unsubscribe_url.strip()
        if not u.startswith("https://"):
            raise HTTPException(400, "unsubscribe_url must be https")
        msg["List-Unsubscribe"] = "<" + u + ">"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    raw = msg.as_bytes()

    if stream == "marketing":
        extra = {}
        if msg.get("List-Unsubscribe"):
            extra["List-Unsubscribe"] = msg["List-Unsubscribe"]
            extra["List-Unsubscribe-Post"] = msg["List-Unsubscribe-Post"]
        conn = db()
        cur = conn.cursor()
        accepted = []
        failed = []
        for rcpt in targets:
            mid, err = inboxroad_send(
                body.from_email, rcpt, body.subject, body.body, body.body_html, extra
            )
            cur.execute(
                "INSERT INTO marketing_log "
                "(message_id, recipient, sender, subject, provider, status, detail, sent_at) "
                "VALUES (%s,%s,%s,%s,'inboxroad',%s,%s,NOW())",
                (mid, rcpt, body.from_email, body.subject[:500],
                 "sent" if not err else "failed", err[:500]),
            )
            if err:
                failed.append(rcpt + ": " + err)
            else:
                accepted.append(rcpt)
        conn.commit()
        cur.close()
        conn.close()
        if not accepted:
            raise HTTPException(502, "Inboxroad refused every recipient: " + "; ".join(failed))
        return {
            "sent": True,
            "stream": "marketing",
            "provider": "inboxroad",
            "from": body.from_email,
            "to": accepted,
            "failed": failed,
        }

    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=10) as smtp:
            smtp.sendmail(body.from_email, targets, raw)
    except Exception as e:
        raise HTTPException(500, f"SMTP error: {e}")

    try:
        imap = imaplib.IMAP4("127.0.0.1", 143)
        imap.login(f"{body.from_email}*admin", MASTER_PASS)
        imap.select()
        imap.create("Sent")
        imap.append("Sent", "\\Seen", None, raw)
        imap.logout()
    except Exception:
        pass

    return {
        "sent": True,
        "stream": "transactional",
        "provider": "postfix",
        "from": body.from_email,
        "to": targets,
        "message_id": msg["Message-ID"],
    }
