# REG-LOG — Backend

Spring Boot 3.4 REST API for a registration-and-login system with e-mail OTP password recovery,
JWT authentication and a MySQL persistence layer.

This repository contains the **backend only**. The React client lives in the companion
repository **[REG-LOG-Frontend-app](https://github.com/ReshmaJava5752/REG-LOG-Frontend-app)**.

---

## Features

| Area | Detail |
| :--- | :--- |
| Registration | Full name, e-mail (unique) and optional 10-digit mobile number. Passwords are stored as BCrypt hashes. |
| Login | Sign in with an e-mail address **or** a mobile number. Returns a signed JWT. |
| Password policy | Minimum 8 characters with one uppercase, one lowercase, one digit and one special character from `@$!%*?&#`. Enforced on the backend *and* mirrored in the UI. |
| Password recovery | A 6-digit one-time code is e-mailed, then exchanged for a single-use reset token. |
| JWT authentication | HS256-signed bearer tokens with a configurable lifetime. Every protected endpoint is verified by a filter. |
| Persistent sessions | A revoked token stays revoked across a backend restart and across multiple instances. |
| Token revocation | Logout, password change and password reset revoke the affected sessions. |
| Account-enumeration resistance | The recovery endpoints answer identically for registered and unknown addresses. |
| Rate limiting | Fixed-window limits on recovery requests, verification attempts and calls per client address. |
| Validation | Bean Validation on every request DTO, with a single consistent error envelope. |
| Account locking | A failed login attempt count is tracked per account and the account is temporarily locked. |

---

## Technology

| | |
| :--- | :--- |
| Language | Java 21 (builds and runs on newer JDKs) |
| Framework | Spring Boot 3.4.2 |
| Security | Spring Security 6 · JJWT 0.12.6 · BCrypt |
| Persistence | Spring Data JPA / Hibernate 6 (`ddl-auto=none`) |
| Database | MySQL 8.0+ |
| Mail | Spring Mail (Gmail SMTP with STARTTLS on port 587) |
| Build | Maven 3.9.9 — the wrapper is included, so **no local Maven install is required** |
| Tests | JUnit 5 + Mockito + Spring Security Test |

---

## Repository layout

```
.
├── .env.example                   # Template with placeholder values - copy to .env
├── .mvn/wrapper/                  # Maven wrapper (jar + properties)
├── mvnw / mvnw.cmd                # Cross-platform Maven wrapper scripts
├── pom.xml                        # Maven build definition
├── database/                      # Schema and migration scripts (DDL only - no user data)
│   ├── fresh_install.sql
│   ├── phase2_migration.sql
│   ├── phase3_migration.sql
│   ├── phase3_sessions_migration.sql
│   └── phase4_otp_hashing_migration.sql
├── postman/                       # Importable Postman collection + environment
└── src/
    ├── main/java/com/example/registrationlogin/
    │   ├── config/                # Spring Security + CORS configuration
    │   ├── controller/            # AuthController - the REST API
    │   ├── dto/                   # Request/response records with validation
    │   ├── entity/                # User, PasswordResetOtp, UserSession
    │   ├── exception/             # Global exception handling
    │   ├── repository/            # Spring Data JPA repositories
    │   ├── security/              # JWT filter, token utils, revocation list
    │   ├── service/               # Business logic (users, e-mail, OTP, sessions)
    │   └── util/                  # Password policy, OTP/Token hashing
    ├── main/resources/
    │   └── application.properties # Configuration - reads every secret from the environment
    └── test/java/                 # 135 automated tests
```

---

## Requirements

* **JDK 21 or newer** — set `JAVA_HOME` to your JDK installation.
* **MySQL 8.0+** running locally (or a reachable instance).
* **A Gmail account with an App Password** — only needed if you want real e-mail delivery.
  See [Gmail SMTP](#gmail-smtp-setup) below, or use `OTP_DELIVERY_MODE=console` to print the
  code in the server log instead.

Maven does **not** have to be installed — the wrapper downloads the pinned version
(3.9.9) on first use and verifies it against a pinned SHA-256 checksum.

---

## Quick start

### 1. Configure the secrets

```powershell
copy .env.example .env
```

Open `.env` and fill in at least `DB_PASSWORD` and `JWT_SECRET`. `.env` is git-ignored and is
never committed.

> The backend loads `.env` automatically through `spring.config.import`. Real environment
> variables always take precedence over the values in the file.

### 2. Create the database schema

```powershell
mysql -u root -p < database\fresh_install.sql
```

`fresh_install.sql` creates the `registration_db` database and all three tables. It is
idempotent — it never drops a table or a column.

### 3. Run the backend

```powershell
.\mvnw.cmd spring-boot:run
```

The API is then available on <http://localhost:8080>. Verify it:

```powershell
curl http://localhost:8080/status
```

### 4. Run the tests

```powershell
.\mvnw.cmd test
```

---

## Commands

| Purpose | Command |
| :--- | :--- |
| Run the application | `.\mvnw.cmd spring-boot:run` |
| Compile and package | `.\mvnw.cmd clean package` |
| Run the tests | `.\mvnw.cmd test` |
| Run a single test class | `.\mvnw.cmd test -Dtest=UserServiceTest` |
| Clean the build output | `.\mvnw.cmd clean` |

`.\mvnw` (no extension) is the equivalent script for macOS and Linux.

---

## Configuration

Every credential is read from an **environment variable**. No secret is stored in the source code,
in `application.properties`, or in any committed file.

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DB_URL` | JDBC connection string | `jdbc:mysql://localhost:3306/registration_db?...` |
| `DB_USERNAME` | MySQL user | `root` |
| `DB_PASSWORD` | MySQL password | *(required)* |
| `JWT_SECRET` | JWT signing secret, 32+ characters for HS256 | *(required)* |
| `SMTP_HOST` | SMTP host | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_PROTOCOL` | SMTP protocol | `smtp` |
| `SMTP_USERNAME` | Gmail address used to authenticate and send | *(required for e-mail delivery)* |
| `SMTP_PASSWORD` | **Google App Password** — not the account password | *(required for e-mail delivery)* |
| `SMTP_FROM` | "From" address on the OTP mail | falls back to `SMTP_USERNAME` |
| `OTP_DELIVERY_MODE` | `smtp` or `console` | `smtp` |
| `OTP_HMAC_SECRET` | Secret used to fingerprint reset codes | falls back to `JWT_SECRET` |
| `OTP_ALLOW_CONSOLE_LOGGING` | Allows the console mode to print the code to the log | `false` |

The values in `.env.example` are placeholders (`your_mysql_password_here`,
`your_256_bit_or_longer_secret_key_here`, …). Replace them — never commit the real ones.

### Gmail SMTP setup

Gmail requires an **App Password** for SMTP clients:

1. Enable **2-Step Verification** on the Google account.
2. Create an App Password at <https://myaccount.google.com/apppasswords> (16 characters).
3. Put the address and the App Password into `.env`:

   ```properties
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your.address@gmail.com
   SMTP_PASSWORD=your_16_character_app_password
   SMTP_FROM=your.address@gmail.com
   ```

4. Keep the account password out of this project — only the App Password belongs here.

The backend uses **STARTTLS on port 587** and **requires** it: the connection fails rather than
silently falling back to clear text.

Without a Gmail account, set `OTP_DELIVERY_MODE=console` and `OTP_ALLOW_CONSOLE_LOGGING=true`
in `.env` to print the reset code in the server log. That mode is for local development only and
is never suitable for a deployment.

---

## Database schema

`spring.jpa.hibernate.ddl-auto=none` means **Hibernate never alters the schema** — the SQL
scripts in `database/` own it.

| Table | Purpose |
| :--- | :--- |
| `users` | Accounts: `full_name`, `email`, `password` (BCrypt hash), `mobile_number`, `created_at`, `updated_at`. |
| `password_reset_otps` | The reset-code **fingerprint**, its expiry, the attempt counter and the single-use reset token. |
| `sessions` | One row per issued login token, so a revoked token stays revoked. |

### Migrations

| Script | When to run it |
| :--- | :--- |
| `database/fresh_install.sql` | A brand-new database. Creates the database and all three tables. |
| `database/phase2_migration.sql` | An existing database that predates `mobile_number` and the OTP table. |
| `database/phase3_migration.sql` | An existing database that predates `updated_at`. |
| `database/phase3_sessions_migration.sql` | An existing database that predates the `sessions` table. |
| `database/phase4_otp_hashing_migration.sql` | Converts stored OTP codes to the fingerprint format. |

Every script is idempotent.

> **The scripts in `database/` contain schema only.** They never contain user records, e-mail
> addresses or password hashes. Real database dumps are excluded by `.gitignore`.

---

## REST API reference

Every endpoint answers on the `/api/auth` prefix, on the shorter `/api` prefix, and on the
root-level path. For example `POST /api/auth/register`, `POST /api/register` and `POST /register`
are the same endpoint.

| Method | Endpoint | Description | Auth | Request body |
| :--- | :--- | :--- | :---: | :--- |
| `GET` | `/status` | Health check | No | — |
| `POST` | `/register` | Register a new user | No | `{"fullName":"John Doe","email":"john@example.com","mobileNumber":"9876543210","password":"Password@123","confirmPassword":"Password@123"}` |
| `POST` | `/login` | Sign in with e-mail or mobile number | No | `{"identifier":"john@example.com","password":"Password@123"}` |
| `POST` | `/logout` | Revoke the current token | Optional | — (send `Authorization: Bearer <token>`) |
| `POST` | `/forgot-password` | Request a 6-digit reset OTP | No | `{"identifier":"john@example.com"}` |
| `POST` | `/verify-otp` | Verify the OTP, receive a reset token | No | `{"identifier":"john@example.com","otpCode":"123456"}` |
| `POST` | `/reset-password` | Set a new password with the reset token | No | `{"identifier":"john@example.com","resetToken":"…","newPassword":"NewPassword@123","confirmPassword":"NewPassword@123"}` |
| `PUT` | `/change-password` | Change the password while signed in | **Yes** | `{"currentPassword":"Password@123","newPassword":"NewPassword@123","confirmPassword":"NewPassword@123"}` |
| `GET` | `/profile` | Read the signed-in account | **Yes** | — |

### Response envelope

Every endpoint uses the same envelope:

```json
{ "success": true, "message": "Login successful!", "data": { } }
```

`data` is `null` for endpoints without a payload. A validation failure answers with HTTP 400 and
a field-to-message map in `data`:

```json
{
  "success": false,
  "message": "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character",
  "data": { "password": "Password must be at least 8 characters long and …" }
}
```

---

## Security design

| Concern | How it is handled |
| :--- | :--- |
| Password storage | BCrypt via `BCryptPasswordEncoder` — the plain password is never stored or logged. |
| JWT signing | HS256 with `JWT_SECRET` from the environment. Never a literal in the source. |
| Token revocation | `TokenBlacklistService` plus persistent session rows; logout, password change and password reset revoke the affected tokens. |
| Raw token storage | The `sessions` table stores a **SHA-256 fingerprint** of the token. The `jwt_token` column stays `NULL`. |
| OTP storage | The reset code is stored as an **HMAC-SHA256 fingerprint** with domain separation — never in plain text, so a database dump cannot be brute forced against the 1 000 000 possible codes. |
| OTP delivery | The code is never returned by the API. It only leaves the server over e-mail. |
| Account enumeration | The recovery endpoints answer identically for known and unknown identifiers, with the same status, message and timing. |
| Rate limiting | Fixed windows: 5 recovery requests and 10 verification attempts per account per 15 minutes, plus 30 calls per client address. A breach answers HTTP 429 with a `Retry-After` header. |
| Brute force | Failed logins are counted per account and the account is temporarily locked. |
| Session state | Stateless — `SessionCreationPolicy.STATELESS`, so there is no server-side session to hijack. |
| CSRF | Disabled deliberately: the API is stateless and authenticates with a bearer token, not with cookies. |
| CORS | Restricted to the configured origins. |
| SQL injection | Prevented by Spring Data JPA parameter binding. |

See [`SECURITY.md`](SECURITY.md) for the full security policy.

---

## Configuration reference

Key settings in `src/main/resources/application.properties`:

| Property | Default | Meaning |
| :--- | :--- | :--- |
| `app.jwt.expiration-ms` | `86400000` | Token lifetime in milliseconds (24 hours). |
| `app.otp.expiry-minutes` | `5` | How long a reset code stays valid. |
| `app.otp.max-attempts` | `3` | Verification attempts allowed per code. |
| `app.otp.delivery-mode` | `smtp` | `smtp` sends the code, `console` prints it. |
| `app.otp.allow-console-logging` | `false` | Safety switch for the console mode. |
| `app.otp.rate-limit.*` | see file | Fixed-window limits for the recovery flow. |
| `app.session.enabled` | `true` | Persistent session tracking. |
| `app.session.purge-cron` | `0 0 * * * *` | When expired session rows are removed. |

> The `app.jwt.secret` and `app.otp.hmac-secret` properties fall back to a
> `CHANGE_ME_IN_PRODUCTION` placeholder when the environment variable is missing, so the
> application can start without a configuration file. **Always set `JWT_SECRET` in a real
> deployment** — a known signing secret would allow anyone to mint valid tokens.

---

## Postman collection

`postman/` contains an importable collection covering every public, authenticated and recovery
endpoint, plus a matching environment. See [`postman/README.md`](postman/README.md).

```powershell
# import both files through Postman > Import, then select the environment
```

The environment file contains placeholders only (`test.user@example.com`, `Password@123`) and
no real credentials.

---

## Notes and known limitations

* **The OTP is delivered by e-mail only.** There is no SMS provider integration. A mobile number
  is collected on the account, but a code can never be sent to a phone number — it always goes to
  the e-mail address on the account.
* **A Gmail account is required for real e-mail delivery.** Without `SMTP_USERNAME` /
  `SMTP_PASSWORD` the OTP cannot be sent. Use `OTP_DELIVERY_MODE=console` for local testing.
* **`sessions` is a required table.** If it is missing, the application logs the problem and
  falls back to the in-memory revocation list for the remainder of its uptime. Run
  `database/phase3_sessions_migration.sql` (or `fresh_install.sql`) to create it.
* **Tokens issued before persistent sessions were enabled** are honoured until their own JWT
  expiry, so enabling the feature does not force existing users to sign in again.

---

## Related repository

* **Frontend** — [REG-LOG-Frontend-app](https://github.com/ReshmaJava5752/REG-LOG-Frontend-app)
  (React 19 + Vite). It proxies `/api` to `http://localhost:8080` in development.
