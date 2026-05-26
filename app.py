import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for


load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "accounts.sqlite3")


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("APP_SECRET", "dev-only-change-me")

    oauth = OAuth(app)
    register_oauth_clients(oauth)

    @app.before_request
    def ensure_db():
        init_db()

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            accounts=list_accounts(),
            providers=provider_status(),
            provider_configs=list_provider_configs(),
        )

    @app.post("/admin/login")
    def admin_login():
        configured_password = os.environ.get("ADMIN_PASSWORD")
        if configured_password:
            if request.form.get("password") != configured_password:
                flash("Invalid password.", "error")
                return redirect(url_for("index"))
        session["admin"] = True
        return redirect(url_for("index"))

    @app.post("/admin/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/bridge/<provider>")
    def bridge(provider):
        if provider not in configured_providers():
            abort(404)
        configured_token = os.environ.get("BRIDGE_LINK_TOKEN", "")
        provided_token = request.args.get("t", "")
        if not configured_token or not secrets.compare_digest(configured_token, provided_token):
            abort(401)
        session["bridge"] = True
        return redirect(url_for("connect", provider=provider))

    @app.get("/connect/<provider>")
    @bridge_or_admin_required
    def connect(provider):
        client = get_client(oauth, provider)
        redirect_uri = callback_url(provider)

        if provider == "google":
            return client.authorize_redirect(
                redirect_uri,
                access_type="offline",
                prompt="consent",
                include_granted_scopes="true",
            )

        return client.authorize_redirect(redirect_uri)

    @app.get("/callback/<provider>")
    @bridge_or_admin_required
    def callback(provider):
        client = get_client(oauth, provider)
        token = client.authorize_access_token()
        profile = fetch_profile(provider, token)

        upsert_account(
            provider=provider,
            external_id=profile["id"],
            email=profile["email"],
            name=profile.get("name") or profile["email"],
            token=token,
        )
        session.pop("bridge", None)
        flash(f"Connected {profile['email']}.", "success")
        return redirect(url_for("index"))

    @app.post("/disconnect/<int:account_id>")
    @admin_required
    def disconnect(account_id):
        delete_account(account_id)
        flash("Account disconnected locally. Revoke access in the provider console if needed.", "success")
        return redirect(url_for("index"))

    @app.post("/settings/<provider>")
    @admin_required
    def save_provider_config(provider):
        if provider not in configured_providers():
            abort(404)
        client_id = request.form.get("client_id", "").strip()
        client_secret = request.form.get("client_secret", "").strip()
        if not client_id or not client_secret:
            flash("Client ID and Client Secret are required.", "error")
            return redirect(url_for("index"))
        upsert_provider_config(provider, client_id, client_secret)
        flash(f"{provider.title()} OAuth configured. You can connect it now.", "success")
        return redirect(url_for("index"))

    @app.get("/api/accounts/<provider>/token")
    @agent_api_required
    def account_token(provider):
        if provider not in configured_providers():
            abort(404)
        account = latest_account(provider)
        if not account:
            return {"error": f"No {provider} account connected."}, 404
        token = decrypt_token(account["encrypted_token"])
        if not token:
            return {"error": "Stored token cannot be decrypted."}, 500
        return {
            "provider": account["provider"],
            "email": account["email"],
            "name": account["name"],
            "external_id": account["external_id"],
            "token": token,
        }

    @app.get("/health")
    def health():
        return {"ok": True}

    return app


def register_oauth_clients(oauth):
    init_db()
    for provider in configured_providers():
        register_provider_client(oauth, provider)


def register_provider_client(oauth, provider):
    credentials = provider_credentials(provider)
    if not credentials:
        return

    client_id = credentials["client_id"]
    client_secret = credentials["client_secret"]

    if provider == "google":
        oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"
            },
        )
        return

    if provider == "microsoft":
        tenant = os.environ.get("MICROSOFT_TENANT", "common")
        oauth.register(
            name="microsoft",
            client_id=client_id,
            client_secret=client_secret,
            access_token_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            authorize_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            api_base_url="https://graph.microsoft.com/v1.0/",
            client_kwargs={"scope": "openid email profile offline_access User.Read Mail.Read"},
        )
        return

    oauth.register(
        name="github",
        client_id=client_id,
        client_secret=client_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email repo"},
    )


def get_client(oauth, provider):
    if provider not in configured_providers():
        abort(404)
    if not oauth.create_client(provider):
        register_provider_client(oauth, provider)
    client = oauth.create_client(provider)
    if not client:
        flash(f"{provider.title()} OAuth is not configured yet.", "error")
        abort(400)
    return client


def callback_url(provider):
    base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
    return f"{base_url}{url_for('callback', provider=provider)}"


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            flash("Log in first.", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


def bridge_or_admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin") or session.get("bridge"):
            return view(*args, **kwargs)
        flash("Open the secure bridge link first.", "error")
        return redirect(url_for("index"))

    return wrapped


def agent_api_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        configured_key = os.environ.get("AGENT_API_KEY")
        provided_key = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not configured_key or provided_key != configured_key:
            abort(401)
        return view(*args, **kwargs)

    return wrapped


def configured_providers():
    return {"google", "microsoft", "github"}


def provider_status():
    return {provider: bool(provider_credentials(provider)) for provider in configured_providers()}


def fetch_profile(provider, token):
    if provider == "google":
        response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {token['access_token']}"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        return {"id": data["sub"], "email": data["email"], "name": data.get("name")}

    if provider == "microsoft":
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {token['access_token']}"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        email = data.get("mail") or data.get("userPrincipalName")
        return {"id": data["id"], "email": email, "name": data.get("displayName")}

    profile_response = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token['access_token']}", "Accept": "application/vnd.github+json"},
        timeout=15,
    )
    profile_response.raise_for_status()
    profile = profile_response.json()

    email = profile.get("email")
    if not email:
        email_response = requests.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {token['access_token']}", "Accept": "application/vnd.github+json"},
            timeout=15,
        )
        email_response.raise_for_status()
        emails = email_response.json()
        primary = next((item for item in emails if item.get("primary")), None)
        email = (primary or emails[0]).get("email") if emails else f"{profile['login']}@users.noreply.github.com"

    return {"id": str(profile["id"]), "email": email, "name": profile.get("name") or profile["login"]}


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS connected_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                external_id TEXT NOT NULL,
                email TEXT NOT NULL,
                name TEXT,
                encrypted_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider, external_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_provider_configs (
                provider TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                encrypted_client_secret TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def cipher():
    key = os.environ.get("TOKEN_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("TOKEN_ENCRYPTION_KEY is required before connecting accounts.")
    return Fernet(key.encode())


def encrypt_token(token):
    return cipher().encrypt(json.dumps(token).encode()).decode()


def decrypt_token(encrypted):
    try:
        return json.loads(cipher().decrypt(encrypted.encode()).decode())
    except InvalidToken:
        return None


def encrypt_secret(secret):
    return cipher().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted):
    try:
        return cipher().decrypt(encrypted.encode()).decode()
    except InvalidToken:
        return None


def env_provider_credentials(provider):
    prefix = provider.upper()
    client_id = os.environ.get(f"{prefix}_CLIENT_ID")
    client_secret = os.environ.get(f"{prefix}_CLIENT_SECRET")
    if client_id and client_secret:
        return {"client_id": client_id, "client_secret": client_secret, "source": "environment"}
    return None


def provider_credentials(provider):
    credentials = env_provider_credentials(provider)
    if credentials:
        return credentials

    with db() as conn:
        row = conn.execute(
            """
            SELECT client_id, encrypted_client_secret
            FROM oauth_provider_configs
            WHERE provider = ?
            """,
            (provider,),
        ).fetchone()

    if not row:
        return None

    client_secret = decrypt_secret(row["encrypted_client_secret"])
    if not client_secret:
        return None
    return {"client_id": row["client_id"], "client_secret": client_secret, "source": "database"}


def upsert_provider_config(provider, client_id, client_secret):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO oauth_provider_configs
                (provider, client_id, encrypted_client_secret, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(provider) DO UPDATE SET
                client_id = excluded.client_id,
                encrypted_client_secret = excluded.encrypted_client_secret,
                updated_at = excluded.updated_at
            """,
            (provider, client_id, encrypt_secret(client_secret), now),
        )


def list_provider_configs():
    configs = {}
    for provider in configured_providers():
        credentials = provider_credentials(provider)
        configs[provider] = {
            "configured": bool(credentials),
            "source": credentials["source"] if credentials else None,
            "client_id": credentials["client_id"] if credentials else "",
        }
    return configs


def upsert_account(provider, external_id, email, name, token):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO connected_accounts
                (provider, external_id, email, name, encrypted_token, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, external_id) DO UPDATE SET
                email = excluded.email,
                name = excluded.name,
                encrypted_token = excluded.encrypted_token,
                updated_at = excluded.updated_at
            """,
            (provider, external_id, email, name, encrypt_token(token), now, now),
        )


def list_accounts():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, provider, external_id, email, name, created_at, updated_at
            FROM connected_accounts
            ORDER BY updated_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def latest_account(provider):
    with db() as conn:
        row = conn.execute(
            """
            SELECT provider, external_id, email, name, encrypted_token, updated_at
            FROM connected_accounts
            WHERE provider = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (provider,),
        ).fetchone()
    return dict(row) if row else None


def delete_account(account_id):
    with db() as conn:
        conn.execute("DELETE FROM connected_accounts WHERE id = ?", (account_id,))


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5050")), debug=True)
