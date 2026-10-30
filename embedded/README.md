# HMACShield - Secure OTP Authentication & Threat Monitoring

This is a C++17 console implementation of the project described in the supplied DA1:

`master secret -> HKDF-SHA256 session key -> HMAC-SHA256 -> dynamic truncation -> 6-digit OTP`

Each login creates a cryptographically random salt and session ID. Verification accepts the current 60-second step and exactly one previous step to tolerate a time-window boundary. A privacy-preserving in-memory replay cache prevents a successfully used session OTP from being accepted again. Failed attempts receive exponential backoff, and three failures for one username within five minutes lock it for five minutes.

## Prerequisites

- CMake 3.16+
- A C++17 compiler (Visual Studio Build Tools, MinGW-w64, or GCC/Clang)
- OpenSSL development files (OpenSSL 3.x recommended)

## Windows setup (Visual Studio Build Tools)

Install CMake and OpenSSL first. Open **PowerShell as Administrator**, then run:

```powershell
choco install cmake openssl.light -y
```

Close and reopen VS Code after installation so its terminal receives the updated PATH. Then build from this project folder:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"
cmake --build build --config Release
```

If OpenSSL was installed to a different directory, replace the `OPENSSL_ROOT_DIR` value with that installation folder.

Alternatively, on Windows with vcpkg:

```powershell
vcpkg install openssl:x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

On Linux/Ubuntu:

```bash
sudo apt install build-essential cmake libssl-dev
cmake -S . -B build
cmake --build build
```

## Run

Set a 32-byte-or-longer master secret outside source control. In PowerShell:

```powershell
$env:OTP_MASTER_SECRET = "replace-this-with-a-long-random-secret-kept-private"
.\build\Release\secure_otp.exe       # Visual Studio generator
```

For a short classroom demonstration only, append `--demo-secret`. This supplies a fixed, public development secret and must not be used for real authentication.

```powershell
.\build\Release\secure_otp.exe --demo-secret
```

For non-demo use, create an encrypted secret once and then use it. The file uses AES-256-GCM; its encryption key is derived from your passphrase using PBKDF2-HMAC-SHA256 (600,000 iterations).

```powershell
.\build\Release\secure_otp.exe --create-encrypted-secret master_secret.enc
.\build\Release\secure_otp.exe --encrypted-secret master_secret.enc
```

The application displays the OTP because this is a local software implementation. A production deployment would deliver it over a separate trusted channel and store the master secret in a secure element, OS key store, or secrets manager.

## Security properties

- HKDF follows RFC 5869 Extract and Expand using HMAC-SHA256.
- A new random salt and session identifier create a distinct key for each authentication request.
- OTP generation uses HOTP-style dynamic truncation of an HMAC-SHA256 digest.
- Verification uses a constant-time comparison, a current/previous time-step window, and an in-memory replay blacklist keyed by an HMAC fingerprint rather than the raw OTP.
- Failed attempts have exponential backoff (1, 2, 4 seconds...) and three failures for one username within five minutes lock that username for five minutes.
- The screen shows a four-character session verification anchor derived from the random session ID.
- Master-key, derived-key, salt, session-ID, and temporary cryptographic buffers are wiped with `OPENSSL_cleanse()` when no longer needed; AES-GCM encrypted master-secret files are supported.

`authentication.log` is created in the current directory at runtime and is intentionally excluded from Git.

## Flask web application

The `webapp` folder contains the HMACShield browser interface for the same custom HKDF-SHA256/HMAC-SHA256 OTP design. It uses a responsive dark navy and blue security-console layout. In local `APP_MODE=demo`, OTPs are shown on the verification page for classroom demonstrations and are labeled as local demo codes. If email is configured, codes are sent by SMTP instead. They are not sent by SMS.

```powershell
cd webapp
py -m pip install -r requirements.txt
py app.py
```

Open `http://127.0.0.1:5000`. Create a local account, then sign in with its email and password. The admin sign-in is at `/admin`; configure `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH` in `webapp/.env`.

Security challenges, consumed OTP fingerprints, failed-attempt events, progressive delays, and five-minute account lockouts are stored in SQLite. The app creates the added tables automatically at startup and preserves existing user/activity tables. Set `DATABASE_PATH` to select the database location. The admin portal includes a monitoring dashboard that polls recorded backend events every five seconds, with searchable and filterable event history. Its four bounded security simulations call the same verifier used by login and can affect the selected account's lockout state. They are available only in demo mode on localhost. Simulations do not target external services.

### Real-time behavior and restart state

- Event rows are written by backend registration, password sign-in, OTP verification, OTP expiry/replay checks, rate limiting, account lockout, logout, and simulation actions. Dashboard totals and charts are queried from those SQLite rows; they are not seeded UI counters.
- The administrator monitor fetches `/admin/monitor-data` every five seconds without reloading the page. That JSON route is administrator-protected and returns the newest 100 events plus computed totals. Search and category filters operate on that returned event set. If the request fails, the page shows a reconnecting status and retries on the next interval.
- OTP expiry is enforced in `verify_challenge_code` against the persisted challenge issue time. The browser countdown is only a display; a POST containing an expired code is still rejected and logged by the server.
- User records, activity audit rows, challenge records (including challenge salt/session ID), consumed-token fingerprints, and account backoff/lockout deadlines persist in SQLite across process restarts.
- Flask login/admin identity, CSRF token, and active challenge ID are carried in a signed browser cookie rather than a server-side session table. That cookie remains valid after restart only when the same `FLASK_SECRET_KEY` is used.
- The derived OTP session key is calculated when needed and is not stored. `OTP_MASTER_SECRET` and `FLASK_SECRET_KEY` are loaded into process memory. Set stable values in `.env`: if either is omitted, the app generates a temporary key at startup. A changed OTP master key makes outstanding challenges unverifiable; a changed Flask key invalidates browser sessions. Completed audit history and lockout data remain in SQLite.
- The simulation mutex exists only in the current process. The supplied Procfile runs one Gunicorn worker; local simulations are also restricted to localhost and `APP_MODE=demo`. Production mode hides the simulator. Do not scale demo simulations across multiple worker processes.
- Audit event details contain event names and safe explanatory text, not OTPs or cryptographic key material. Demo OTPs are shown only on the local verification page. SMTP email delivery is optional when configured; this project does not implement SMS delivery.

### Step-by-step real-time demonstration

1. From `embedded/webapp`, run `Copy-Item .env.example .env`. Generate two independent keys by running `py -c "import secrets; print(secrets.token_urlsafe(48))"` twice; put one in `FLASK_SECRET_KEY` and the other in `OTP_MASTER_SECRET` in `.env`. Set `APP_MODE=demo`, choose `ADMIN_USERNAME`, and create an admin password hash with `py -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-chosen-admin-password'))"`. Put the hash in `ADMIN_PASSWORD_HASH`. Keep `EMAIL_ENABLED=false` for the local code display demo. Do not commit `.env`.
2. Start the app with `py -m pip install -r requirements.txt` followed by `py app.py`. Open `http://127.0.0.1:5000`, create two throwaway local accounts, and use `/admin` to sign in as the configured administrator. Keep a browser tab on `/admin/monitoring`.
3. **Successful authentication:** sign in as the first account, use the six-digit local demo code on the verification screen, and confirm the account dashboard opens. The monitor should show the backend-recorded OTP verification and successful login within five seconds, without refreshing the admin page.
4. **Invalid OTP and rate limiting:** sign in again and submit a different six-digit value. The app records a failed OTP. Submit again before the displayed retry delay ends to produce a rate-limited event. The server enforces the delay even if a request is submitted manually.
5. **Server-enforced expiry:** request a fresh code and wait until the countdown reaches zero. Submit the code anyway. The server rejects it, redirects back to sign-in with an expiry message, and records an `Expired OTP` event.
6. **Replay and bounded lockout:** in the admin sidebar, open **Attack Simulation**. Select the second throwaway account and run **Replay detection**; the same challenge is accepted once and rejected on reuse. Then run **Bounded brute force** against that throwaway account. It makes no more than five wrong-code checks and exercises the normal progressive delay/lockout verifier. The simulator can lock that selected demo account for five minutes.
7. **Challenge isolation:** use separate browser profiles for the two accounts. Request one code in each profile. Submit the first account's code in the second profile; it must fail there, while the second account's own code remains valid in its own session. A newly issued challenge for the same account and purpose supersedes its older active challenge.
8. **Event explorer:** open **Security Events** in the admin sidebar. Search by the demo account name and filter by success, failed authentication, expired OTP, replay, rate limiting, lockout, or simulation. Generate another event in a separate tab and watch the list and metrics update on the next five-second poll.
9. **Restart persistence:** stop Flask with `Ctrl+C`, then run `py app.py` again without changing `.env` or `DATABASE_PATH`. Sign back in if needed. Users, audit rows, consumed OTP replay fingerprints, and lockout state remain. A pending, unexpired challenge remains verifiable only when the same `OTP_MASTER_SECRET` is configured; browser sessions remain valid only when the same `FLASK_SECRET_KEY` is configured.

For an automated restart check and the other security cases, run the regression command below. The restart test launches two separate Python processes against a unique temporary SQLite file with stable test keys; it does not use the project's live database.

### Environment settings

Copy `webapp/.env.example` to `webapp/.env` for local use. Keep that file private. `APP_MODE=demo` enables the local simulator and classroom OTP display. For SMTP delivery, fill in the `SMTP_*` and `EMAIL_FROM` settings and set `EMAIL_ENABLED=true`. Set a stable random `OTP_MASTER_SECRET` and `FLASK_SECRET_KEY`, each at least 32 characters. Do not put credentials or plaintext OTPs in source control or logs.

### Deploying

Deploy the `webapp` directory to a Python WSGI host such as Render. The included `Procfile` starts Gunicorn. Configure these environment values in the host dashboard:

- `APP_MODE=production` (disables all simulation controls and requires stable secrets)
- `FLASK_SECRET_KEY` and `OTP_MASTER_SECRET` (random values, at least 32 characters each)
- `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH`
- `DATABASE_PATH` pointing to the host's persistent disk, for example `/var/data/users.sqlite3`
- SMTP settings and `EMAIL_ENABLED=true` if the deployment should email OTPs

Generate an admin password hash locally with `py -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('replace-with-your-admin-password'))"`, then set the output as `ADMIN_PASSWORD_HASH`. Do not use or publish the example password. Attach a persistent disk at the path used by `DATABASE_PATH` so accounts and security events survive redeploys. The production app requires HTTPS; secure cookies are enabled automatically for `APP_MODE=production`. Run the web service with the host's assigned port and do not enable Flask debug mode.

Generate each application secret with `py -c "import secrets; print(secrets.token_urlsafe(48))"` and store it only in the host's protected environment settings. Reuse the same keys across restarts and instances that share the database.

### Web app regression tests

From the repository root, install the development requirement and run:

```powershell
py -m pip install -r embedded/webapp/requirements-dev.txt
py -m pytest embedded/webapp/tests -q -p no:cacheprovider
```

The tests exercise the custom OTP verifier, challenge isolation and expiry, replay protection, progressive backoff and lockout, CSRF, monitoring statistics, and local-only simulation access.

