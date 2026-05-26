# OAuth Account Hub

Small Flask app to connect multiple Google, Microsoft, and GitHub accounts using OAuth. It stores connected accounts in SQLite and encrypts OAuth tokens at rest.

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
http://localhost:5050/callback/github
```

For deployment, set `BASE_URL` to the public HTTPS URL and use:

```text
https://oauth-hub.apps.railpush.com/callback/google
https://oauth-hub.apps.railpush.com/callback/microsoft
https://oauth-hub.apps.railpush.com/callback/github
```

## Bridge links

Set `BRIDGE_LINK_TOKEN` and send Sergio provider-specific bridge links instead of asking for provider credentials in the UI:

```text
https://oauth-hub.apps.railpush.com/bridge/google?t=<BRIDGE_LINK_TOKEN>
https://oauth-hub.apps.railpush.com/bridge/microsoft?t=<BRIDGE_LINK_TOKEN>
```

The bridge link starts the provider login and the callback stores the encrypted OAuth token locally.

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

## GitHub setup

1. Create an OAuth App in GitHub Developer settings.
2. Homepage URL: `https://oauth-hub.apps.railpush.com`
3. Authorization callback URL: `https://oauth-hub.apps.railpush.com/callback/github`
4. Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.

Current scopes:

```text
read:user user:email repo
```

The app also exposes `GET /api/accounts/github/token` for agent use. It requires:

```text
Authorization: Bearer <AGENT_API_KEY>
```

## Security notes

- Do not commit `.env` or `accounts.sqlite3`.
- Set `ADMIN_PASSWORD` before exposing this app publicly.
- Set `BRIDGE_LINK_TOKEN` before sending direct bridge links.
- Set `AGENT_API_KEY` to a long random value before using agent token access.
- Tokens are encrypted using `TOKEN_ENCRYPTION_KEY`; losing the key makes stored tokens unreadable.
- Disconnect removes local tokens only. Provider-side access should also be revoked from Google/Microsoft security settings when needed.
