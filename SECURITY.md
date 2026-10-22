# Security Policy

## Reporting a vulnerability

If you find a security issue in this project, please report it privately rather than opening a
public issue. Use GitHub's **Security > Advisories > Report a vulnerability** button on the
repository, or contact the maintainer directly.

Please do not include real credentials, personal data or working exploits in a public issue.

---

## How this project handles secrets

This repository is published for review. It must never contain a working credential.

| Rule | How it is enforced |
| :--- | :--- |
| No secret is committed | Every credential is read from an environment variable. `application.properties` only contains `${VAR:placeholder}` references. |
| `.env` is never tracked | `.env`, `.env.*` and `*.env` are ignored; only `.env.example` is committed. |
| `.env.example` holds placeholders only | Values such as `your_mysql_password_here` and `your_256_bit_or_longer_secret_key_here`. |
| Real connection strings are not committed | `spring.datasource.url` and `spring.datasource.username` default to a local development instance and are overridable through `DB_URL` and `DB_USERNAME`. |
| Database dumps are never committed | `*.dump`, `*backup*.sql` and `database_backup/` are ignored. The tracked scripts in `database/` contain **schema only** — no `INSERT` statements, no user records, no password hashes. |
| Private keys and certificates are never committed | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` and related patterns are ignored. |
| Logs are never committed | `*.log` and `logs/` are ignored. |
| The Postman environment holds placeholders only | `test.user@example.com`, `Password@123`; the token variables are empty. |

If you add a configuration value that is sensitive, put it in `.env` and add the matching
variable to `.env.example` with a placeholder.

---

## Security design

The application is a stateless REST API that authenticates with bearer tokens.

| Control | Implementation |
| :--- | :--- |
| Password hashing | BCrypt (`BCryptPasswordEncoder`). The plain password is never stored, logged or returned. |
| Password policy | Minimum 8 characters with an uppercase letter, a lowercase letter, a digit and a special character from `@$!%*?&#`. Enforced server-side, not only in the UI. |
| Token signing | HS256 JWT signed with `JWT_SECRET` from the environment. |
| Token lifetime | `app.jwt.expiration-ms`, 24 hours by default. |
| Token revocation | Logout, password change and password reset revoke the affected tokens. A revoked token is rejected with HTTP 401 on the next request. |
| Session persistence | Each login writes a session row holding a **SHA-256 fingerprint** of the token. The raw token is never written to the database. |
| OTP handling | The 6-digit reset code is stored as an **HMAC-SHA256 fingerprint** with domain separation — never in plain text — so a leaked table cannot be brute forced over the 1 000 000 possible codes. |
| OTP delivery | The code is never returned by the API. It leaves the server only over e-mail. |
| Account enumeration | The recovery endpoints answer identically for registered and unknown identifiers — same status, same message, same shape. |
| Rate limiting | Fixed windows: 5 recovery requests and 10 verification attempts per account per 15 minutes, plus 30 calls per client address. A breach answers HTTP 429 with a `Retry-After` header. |
| Brute-force protection | Failed logins are counted per account; the account is temporarily locked. |
| Transport security | Gmail SMTP over **STARTTLS** on port 587, and STARTTLS is *required* — the connection fails rather than silently downgrading. |
| Injection | Spring Data JPA parameter binding; no string-concatenated SQL. |
| Input validation | Bean Validation on every request DTO with a single consistent error envelope. |
| CORS | Restricted to the configured origins. |
| CSRF | Disabled on purpose: the API is stateless and authenticates with a bearer token rather than with cookies, so a cross-site request cannot ride on an ambient credential. |

---

## Deployment notes

Two defaults exist only so that the application can start without a configuration file. **Both
must be overridden in any real deployment:**

| Property | Placeholder default | Action |
| :--- | :--- | :--- |
| `app.jwt.secret` | `CHANGE_ME_IN_PRODUCTION_CHANGE_ME_IN_PRODUCTION` | Set `JWT_SECRET` to a random value of 32+ characters. A known signing secret would let anyone mint valid tokens. |
| `app.otp.hmac-secret` | falls back to `app.jwt.secret` | Set `OTP_HMAC_SECRET` if the reset codes need a separate secret. |

Also make sure:

* `OTP_ALLOW_CONSOLE_LOGGING` stays `false` — it allows the reset code to be written to the log.
* `OTP_DELIVERY_MODE` stays `smtp` outside local development.
* `spring.jpa.show-sql` is switched off in production if SQL statements should not be logged.
* The database account used by the application has only the privileges it needs.

---

## Scope

This project is a training/portfolio application. It is not hardened for hostile public
internet traffic. The items above are the deliberate security properties of the code; the
deployment checklist above is what turns them into a safe deployment.
