import os, sqlite3, secrets, time
from datetime import datetime
from pathlib import Path
import urllib.parse

from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from google_auth_oauthlib.flow import Flow
from dotenv import load_dotenv
from google.oauth2 import id_token
import requests as httpx      # for HTTP calls (Safe Browsing API)
from google.auth.transport import requests as google_requests  # for OAuth token verification

# --- Google Safe Browsing Setup ---
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

# --- Simple Local Domain Blocklist (family filter) ---
BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"
BLOCKLIST_CACHE = set()
BLOCKLIST_LAST_LOAD = 0

def load_blocklist(force_reload=False):
    """Download and cache the blocklist every 24 hours."""
    global BLOCKLIST_LAST_LOAD, BLOCKLIST_CACHE
    now = time.time()
    if not force_reload and now - BLOCKLIST_LAST_LOAD < 86400 and BLOCKLIST_CACHE:
        return  # reuse cached version
    try:
        print("Loading blocklist...")
        txt = httpx.get(BLOCKLIST_URL, timeout=10).text
        new_set = set()
        for line in txt.splitlines():
            if line.startswith("0.0.0.0 "):
                domain = line.split()[1].strip().lower()
                new_set.add(domain)
        BLOCKLIST_CACHE = new_set
        BLOCKLIST_LAST_LOAD = now
        print(f"Loaded {len(BLOCKLIST_CACHE)} domains into blocklist.")
    except Exception as e:
        print(f"Warning: Could not load blocklist ({e})")

def domain_in_blocklist(url: str) -> bool:
    """Check if the domain or any of its parents appear in the blocklist."""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    # Remove port if present
    domain = domain.split(":")[0]
    return any(domain == b or domain.endswith("." + b) for b in BLOCKLIST_CACHE)

def is_url_safe(url: str) -> bool:
    """
    Combined safety check using:
    - Google Safe Browsing (malware, phishing, scams)
    - Local blocklist (adult/unwanted content)
    """
    # Ensure URL has a valid scheme
    if not url.lower().startswith(("http://", "https://")):
        return False

    # --- 1️⃣ Local Blocklist Check ---
    load_blocklist()
    if domain_in_blocklist(url):
        print(f"[BLOCKLIST] {url} flagged.")
        return False

    # --- 2️⃣ Google Safe Browsing Check ---
    if not SAFE_BROWSING_API_KEY:
        print("Warning: Safe Browsing API key not configured. Skipping malware check.")
        return True  # Don't block if key missing

    body = {
        "client": {"clientId": "jdoc.cc", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = httpx.post(SAFE_BROWSING_URL, json=body, timeout=5)
        data = response.json()
        if "matches" in data:
            print(f"[SAFE BROWSING] {url} flagged as unsafe.")
            return False
    except Exception as e:
        print(f"Safe Browsing check failed: {e}")
        # Fail open: don’t block unless confirmed
        return True

    return True

def load_allowed_users():
    file_path = Path(__file__).parent / "allowed_users.txt"
    if not file_path.exists():
        return set()
    with open(file_path, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

load_dotenv()

app = FastAPI(title="jdoc.cc")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

templates = Jinja2Templates(directory="templates")

conn = sqlite3.connect("urls.db", check_same_thread=False)
conn.execute("""
CREATE TABLE IF NOT EXISTS access_keys (
    key TEXT PRIMARY KEY,
    assigned_to TEXT,
    created_at REAL
)
""")
conn.execute("""
CREATE TABLE IF NOT EXISTS urls (
    slug TEXT PRIMARY KEY,
    target TEXT,
    clicks INTEGER DEFAULT 0,
    created_at REAL,
    last_accessed REAL,
    created_by TEXT
)
""")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app.mount("/static", StaticFiles(directory="static"), name="static")

# OAuth Flow setup
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uris": ["https://jdoc.cc/auth/callback"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    },
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"]
)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if "email" not in request.session:
        return templates.TemplateResponse("index.html", {"request": request, "authenticated": False})
    return templates.TemplateResponse("index.html", {"request": request, "authenticated": True, "email": request.session["email"]})

@app.get("/login")
def login():
    flow.redirect_uri = "https://jdoc.cc/auth/callback"
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")
    return RedirectResponse(auth_url)


@app.get("/auth/callback")
def callback(request: Request):
    flow.redirect_uri = "https://jdoc.cc/auth/callback"
    flow.fetch_token(authorization_response=str(request.url))

    credentials = flow.credentials
    token_info = id_token.verify_oauth2_token(
        credentials.id_token,
        google_requests.Request(),
        GOOGLE_CLIENT_ID
    )

    email = token_info["email"].lower()

    # Load the latest allowed users on each login
    allowed_users = load_allowed_users()

    if email not in allowed_users:
        return HTMLResponse(
            "<h2 style='font-family:sans-serif;color:#dc2626;text-align:center;margin-top:3rem;'>"
            "Access Denied: Your account is not authorized to use this service.</h2>",
            status_code=403
        )

    # Authorized — continue as normal
    request.session["email"] = email
    request.session["name"] = token_info.get("name", "")
    request.session["picture"] = token_info.get("picture", "")

    return RedirectResponse("/")

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

@app.post("/shorten")
def shorten(request: Request, url: str = Form(...), slug: str = Form(None)):
    if "email" not in request.session:
        return RedirectResponse("/")

    # ✅ Check if URL is safe
    if not is_url_safe(url):
        return {"error": "This URL has been flagged as unsafe."}

    email = request.session["email"]
    slug = slug or secrets.token_urlsafe(4)[:6]
    now = time.time()

    conn.execute("""
        INSERT OR REPLACE INTO urls (slug, target, clicks, created_at, last_accessed, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (slug, url, 0, now, None, email))
    conn.commit()

    return {"short_url": f"https://jdoc.cc/{slug}"}

@app.get("/{slug}")
def redirect(slug: str):
    cur = conn.execute("SELECT target, clicks FROM urls WHERE slug=?", (slug,))
    row = cur.fetchone()
    if not row:
        return HTMLResponse("404: link not found", status_code=404)
    conn.execute("UPDATE urls SET clicks=?, last_accessed=? WHERE slug=?", (row[1] + 1, time.time(), slug))
    conn.commit()
    return RedirectResponse(row[0])

@app.get("/my/links")
def get_my_links(request: Request):
    if "email" not in request.session:
        return RedirectResponse("/")
    email = request.session["email"]

    cur = conn.execute("""
        SELECT slug, target, clicks, created_at
        FROM urls
        WHERE created_by = ?
        ORDER BY created_at DESC
    """, (email,))
    rows = cur.fetchall()

    links = [
        {
            "slug": slug,
            "short_url": f"https://jdoc.cc/{slug}",
            "target": target,
            "clicks": clicks,
            "created_at": datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M:%S")
        }
        for slug, target, clicks, created_at in rows
    ]
    return links

@app.delete("/delete/{slug}")
def delete_link(slug: str, request: Request):
    if "email" not in request.session:
        return {"error": "Not authorized"}

    email = request.session["email"]
    conn.execute("DELETE FROM urls WHERE slug = ? AND created_by = ?", (slug, email))
    conn.commit()
    return {"status": "deleted"}

