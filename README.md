# StudyWorld Platform

Secure account foundation built with Spring Boot 3.5 and Angular 20. The application delivers registration with email verification, MFA-protected authentication, password lifecycle management, and a minimal SPA for user self-service.

## Tech Stack

- **Backend**: Spring Boot 3.5.6, Java 21, Spring Security, JDBC + PostgreSQL, JWT, TOTP MFA
- **Frontend**: Angular 20.3, Standalone components, RxJS, Font Awesome
- **Infrastructure**: Docker Compose Postgres service, SQL bootstrap scripts

## Getting Started

### Prerequisites

- Java 21 runtime
- Maven (wrapper provided)
- Node.js 18+ (Angular CLI installs locally via `npx`)
- Docker (for running PostgreSQL quickly)

### Database

```bash
cd database
docker compose up -d
```

This boots PostgreSQL with schema and seed scripts from `schema.sql` / `data.sql`.

### Backend

Configure `src/main/resources/application.yml` as needed (Resend email, JWT secret, frontend URL, datasource).

Run the API:

```bash
./mvnw spring-boot:run
```

Key endpoints (prefixed with `/api`):

- `POST /auth/register` – create account (email verification required)
- `GET /auth/verify?token=...` – confirm email
- `POST /auth/login` – authenticate via Spring Security workflow (MFA challenge when enabled)
- `POST /auth/mfa/verify` – resolve MFA challenge
- `POST /auth/password-reset/request` + `POST /auth/password-reset/confirm`
- `GET /profile` / `PUT /profile` – manage profile, password, picture
- `POST /mfa/setup` / `POST /mfa/enable` / `DELETE /mfa` – TOTP lifecycle

Accounts remain locked for 15 minutes after six failed attempts, and passwords expire after 90 days.

### Frontend

```bash
cd frontend
npm install
npm start
```

Angular app runs at `http://localhost:4200`, aligned with `app.frontend-url`.

Features include login with MFA hand-off, registration, verification feedback, reset flows, and a profile dashboard.

## Development Notes

- JWT signing secret must be a Base64-encoded 512-bit key; update `app.jwt.secret` before production.
- Email sending uses Resend over HTTPS only (no SMTP, no mocks). The app fails fast if not configured.
  - Required env vars:
    - `APP_MAIL_FROM` (e.g., `support@studiwelt.com`) — must be a verified Resend sender/domain
    - `APP_MAIL_FROM_NAME` (display name)
    - `APP_RESEND_API_KEY` (Resend API key)
- Tokens are persisted to allow logout and force rotation on refresh.
- MFA uses TOTP (RFC 6238) with QR provisioning (Google Authenticator compatible).

## Testing

Maven & Angular tests were not executed in this environment because a Java runtime is unavailable. Once JDK 21 is installed you can run:

```bash
./mvnw test
cd frontend && npm test
```

## Project Structure

```
backend (Spring Boot)
└─ src/main/java/com/studyworld
   ├─ config/           // security, JWT, property binding
   ├─ auth/             // controllers, DTOs, service
   ├─ user/             // domain + JDBC repositories
   ├─ token/            // JWT, verification, reset tokens
   ├─ mfa/              // TOTP service + controller
   ├─ profile/          // profile API layer
   └─ common/           // error handling, mapping
frontend (Angular)
└─ src/app
   ├─ core/             // auth/profile services, guards, interceptor
   ├─ features/auth     // login, register, verify, reset screens
   ├─ features/profile  // profile & MFA management
   └─ features/dashboard
```

## Next Steps

- Add integration tests (registration, login, MFA, reset) and component/unit tests for Angular flows.
- Consider introducing flyway/liquibase migrations as schema evolves.
- Harden refresh-token reuse detection and rate-limit verification/resend endpoints.

## Deploy to Railway

- The repo includes a `Dockerfile` and binds to the `PORT` environment variable, making it compatible with Railway out of the box.
- Steps:
  - Create a new Railway project and select this repository.
  - Add a PostgreSQL service in Railway and link it to this service.
  - In Variables, set:
    - `SPRING_DATASOURCE_URL` (Railway provides this when you link Postgres; prefer `jdbc:postgresql://...` form)
    - `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD`
    - Resend email settings: `APP_MAIL_FROM`, `APP_MAIL_FROM_NAME`, `APP_RESEND_API_KEY`
    - `APP_JWT_SECRET` (Base64-encoded 512-bit key; override the default)
    - Optionally `APP_FRONTEND_URL` to your deployed frontend URL
  - Deploy. Railway builds the Docker image and runs: `java -Dserver.port=$PORT -jar app.jar`.

Notes:
- Railway blocks outbound SMTP. This backend uses Resend’s HTTPS API only.
- The default profile reads configuration from environment variables. Local development can continue using `application-dev.yml` with `SPRING_PROFILES_ACTIVE=dev`.
- Ensure the database URL uses the `jdbc:postgresql://` format. If Railway only provides a `postgresql://` URL, convert it to `jdbc:postgresql://` and keep the same host, port, db, user, and password.
