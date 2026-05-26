# OAuth Account Hub

Small Flask app to connect multiple Google and Microsoft email accounts using OAuth. It stores connected accounts in SQLite and encrypts OAuth tokens at rest.

## Run locally

```bash
cd /workspace/oauth-account-hub
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Paste the generated value into `TOKEN_ENCRYPTION_KEY` in `.env`, set `APP_SECRET`, then run:

```bash
flask --app app run --host 0.0.0.0 --port 5050
```

## OAuth redirect URLs

Set the provider redirect URLs to:

```text
http://localhost:5050/callback/google
http://localhost:5050/callback/microsoft
```

For deployment, set `BASE_URL` to the public HTTPS URL and use:

```text
https://your-domain.example/callback/google
https://your-domain.example/callback/microsoft
```

## Google setup

1. Create OAuth credentials in Google Cloud Console.
2. App type: Web application.
3. Add the redirect URL above.
4. Enable Gmail API if you want mailbox access.
5. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

Current scopes:

```text
openid email profile https://www.googleapis.com/auth/gmail.readonly
```

## Microsoft setup

1. Register an app in Microsoft Entra admin center.
2. Add the redirect URL above under Web platform.
3. Create a client secret.
4. Set `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, and optionally `MICROSOFT_TENANT`.

Current scopes:

```text
openid email profile offline_access User.Read Mail.Read
```

## Security notes

- Do not commit `.env` or `accounts.sqlite3`.
- Set `ADMIN_PASSWORD` before exposing this app publicly.
- Tokens are encrypted using `TOKEN_ENCRYPTION_KEY`; losing the key makes stored tokens unreadable.
- Disconnect removes local tokens only. Provider-side access should also be revoked from Google/Microsoft security settings when needed.
