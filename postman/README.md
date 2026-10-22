# Postman Collection

Importable Postman artifacts for the RegistrationLoginProject backend.

| File | Purpose |
| :--- | :--- |
| `RegistrationLogin.postman_collection.json` | The collection (schema v2.1.0) covering every public, authenticated and recovery endpoint. |
| `RegistrationLogin.postman_environment.json` | The matching local environment. Contains **placeholders only** - no real credentials. |

---

## Import

1. Open Postman and choose **Import**.
2. Drag in `RegistrationLogin.postman_collection.json` and `RegistrationLogin.postman_environment.json`
   (or use **Import > Link** with the local file paths).
3. Select the environment **RegistrationLoginProject - Local** from the environment picker in the
   top-right corner. Without it, every `{{variable}}` resolves to an empty string.
4. Make sure the backend is running (`.\mvnw.cmd spring-boot:run`) and that `baseUrl` points at it.

---

## Request flow

The requests are grouped into three folders that mirror the access level of each endpoint.

### 1. Public

| Request | Method | Path | Auth |
| :--- | :--- | :--- | :---: |
| Health Check | `GET` | `/status` | No |
| Register User | `POST` | `/api/auth/register` | No |
| Login | `POST` | `/api/auth/login` | No |
| Logout | `POST` | `/api/auth/logout` | Optional |

### 2. Authenticated

| Request | Method | Path | Auth |
| :--- | :--- | :--- | :---: |
| Get Profile | `GET` | `/api/auth/profile` | **Bearer** |
| Change Password | `PUT` | `/api/auth/change-password` | **Bearer** |

### 3. Password Recovery

| Request | Method | Path | Auth |
| :--- | :--- | :--- | :---: |
| Forgot Password | `POST` | `/api/auth/forgot-password` | No |
| Verify OTP | `POST` | `/api/auth/verify-otp` | No |
| Reset Password | `POST` | `/api/auth/reset-password` | No |

The collection uses the `/api/auth` prefix. Every endpoint is also reachable on the trainer paths
(`/api/reg`, `/api/login`) and the legacy paths (`/api/auth/...`) - see the REST API Reference in
the repository `README.md`.

---

## Automatic variable handling

The test scripts keep the environment in sync so most requests need no manual editing:

| Variable | Written by | Read by |
| :--- | :--- | :--- |
| `token` | **Login** | the collection-level Bearer auth used by Get Profile / Change Password / Logout |
| `tokenType` | **Login** | informational (`Bearer`) |
| `resetToken` | **Verify OTP** | **Reset Password** |
| `token` / `resetToken` | cleared by **Logout** / **Reset Password** | - |

Everything else (`baseUrl`, `fullName`, `email`, `mobileNumber`, `password`, `newPassword`) is a
plain input you set in the environment.

---

## The one manual step: the OTP

The 6-digit OTP **is never returned by the API** - that is a deliberate security property, not a
missing feature. To complete the recovery flow:

1. Run **Forgot Password**.
2. Open the inbox of the **e-mail address on the account** and copy the 6-digit code.
3. Paste it into the `otpCode` environment variable.
4. Run **Verify OTP** - it stores the single-use reset token automatically.
5. Run **Reset Password**.

The OTP is valid for **5 minutes** and allows **3** verification attempts. Requesting a new OTP
invalidates the previous one.

Both recovery endpoints are **rate limited** (5 requests and 10 verification attempts per
account per 15 minutes, plus 30 calls per client address). A breach is answered with **HTTP 429
Too Many Requests** and a `Retry-After` header - wait for the window to pass and try again.

> The OTP is **only** delivered by e-mail - this application has no SMS delivery. If you entered
> a mobile number as the identifier, the code still goes to the e-mail address on the account.

If no e-mail arrives, check the backend log for the reason code (`SMTP_NOT_CONFIGURED`,
`SMTP_NO_SENDER`, `SMTP_SEND_FAILED`) - see the repository `README.md`. For local testing without a
Google account, set `OTP_DELIVERY_MODE=console` in `.env` and restart the backend; the OTP is then
printed to the server log.

---

## Running the collection as a suite

Use **Collection Runner** (the collection's *Run* button). Note that the recovery folder cannot
run unattended because the OTP has to be read from the inbox - run **Forgot Password** and
**Verify OTP** manually, then run the rest with the runner.

---

## Secrets

This directory contains **no secrets**. The environment file uses obvious placeholders
(`test.user@example.com`, `Password@123`). Do not commit a real environment file with live
credentials - keep it out of version control if you customise it.
