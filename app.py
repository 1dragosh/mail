import os
import re
import secrets
import smtplib
import time
import httpx
import mysql.connector
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from fastapi import FastAPI, Request, Form, Cookie, Header, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from passlib.hash import md5_crypt
from pydantic import BaseModel

MAIL_SERVER = os.environ["MAIL_SERVER"]
SERVER_IP = os.environ["SERVER_IP"]
DB_PASS = os.environ["DB_PASS"]
MASTER_PASS = os.environ["MASTER_PASS"]
SECRET = os.environ["SECRET"]
MAIL_BASE = os.environ.get("MAIL_BASE", "/var/mail/vhosts")

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


def dns_for(domain):
    return [
        {"type": "MX", "name": "@", "value": MAIL_SERVER, "prio": "10", "ttl": "3600"},
        {"type": "TXT", "name": "@", "value": f"v=spf1 a:{MAIL_SERVER} ~all", "prio": "-", "ttl": "3600"},
        {"type": "TXT", "name": "_dmarc", "value": f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}", "prio": "-", "ttl": "3600"},
    ]


def ui_auth(auth):
    if auth != SECRET:
        raise HTTPException(status_code=302, headers={"Location": "/login"})


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
async def login_post(request: Request, password: str = Form(...)):
    ip = request.headers.get("x-real-ip", request.client.host)
    check_login_rate(ip)
    if password != SECRET:
        return RedirectResponse("/login?error=1", status_code=303)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie("auth", SECRET, httponly=True, secure=True, samesite="lax", max_age=86400 * 30)
    return r


@app.get("/logout")
async def logout():
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
    if auth != SECRET:
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
    if auth != SECRET:
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
    return {"domain": body.domain, "description": body.description, "active": True, "dns_records": dns_for(body.domain)}


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


@app.post("/api/send", status_code=200)
async def api_send_email(body: SendEmailIn, authorization: str | None = Header(default=None)):
    api_auth(authorization)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM mailbox WHERE username=%s AND active=1", (body.from_email,))
    if not cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(400, "from_email not a valid active mailbox")
    cur.close()
    conn.close()

    if body.body_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body.body, "plain", "utf-8"))
        msg.attach(MIMEText(body.body_html, "html", "utf-8"))
    else:
        msg = MIMEText(body.body, "plain", "utf-8")

    msg["From"] = body.from_email
    msg["To"] = ", ".join(body.to)
    msg["Subject"] = body.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=body.from_email.split("@")[1])
    if body.reply_to_id:
        msg["In-Reply-To"] = body.reply_to_id
        msg["References"] = body.reply_to_id

    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=10) as smtp:
            smtp.sendmail(body.from_email, body.to, msg.as_string())
    except Exception as e:
        raise HTTPException(500, f"SMTP error: {e}")

    return {"sent": True, "from": body.from_email, "to": body.to, "message_id": msg["Message-ID"]}
