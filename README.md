# PhishMeNot: Suspicious Link and Phishing Checker

IT342-G01 Systems Integration and Architecture 1 — individual project by Raphael Jude A. Alvarado.

PhishMeNot is a web-based phishing link checker. This repository currently contains:

- **Increment 1 – User Accounts and Authentication:** account creation, sign-in/sign-out and
  role-based dashboards for the two roles in the SRS (General User and Administrator).
- **Increment 2 – User Profile and Password Management:** email + password accounts alongside Google,
  profile management, change password, and forgot/reset password by email.

| Layer    | Technology                                                                   |
|----------|------------------------------------------------------------------------------|
| Frontend | ReactJS 18 + Vite, React Router                                              |
| Backend  | Java 21, Spring Boot 3.4 (Web, Security, OAuth2 Client, Data JPA, Validation) |
| Database | MySQL 8                                                                      |
| Identity | Google OAuth 2.0 / OpenID Connect, or email + password (BCrypt)              |
| Email    | Any SMTP server (e.g. Gmail) via Spring Mail, for password reset links        |

## Increment 1 features

### 1. User account creation
In Increment 1 accounts were Google-only (SRS FR-020, FR-021), created automatically on a user's
**first Google sign-in**. Increment 2 adds email + password registration (see below).

- **Required fields are validated** (`GoogleProfile`, Bean Validation): Google account id, a valid
  email address, a name, and a **Google-verified email**. If any of these fail, no account is
  created and the login page shows an error.
- **No duplicate accounts:** users are looked up by `google_id`; `google_id` and `email` are both
  unique keys in the `users` table, and an email already linked to a different Google account is
  rejected (`account_conflict`).
- **Stored in MySQL** in the `users` table (ERD, Figure 1): `user_id, google_id, email, name,
  profile_picture_url, role, created_at, last_login_at`.
- **Credentials:** for Google accounts, Google checks the password, so PhishMeNot never receives
  it. Secrets (OAuth client secret, DB and SMTP passwords) are read from environment variables (NFR-007).
- **Role assignment:** new accounts get the `USER` role (General User). Administrators get `ADMIN`
  directly in the database (FR-046), or through the optional `ADMIN_EMAILS` setting (applied at
  sign-in, so it also promotes an account that already exists).

### 2. Login and logout
- The login page has a **Sign in with Google** button (`/oauth2/authorization/google`). Google's
  account chooser is always shown (`prompt=select_account`), so after signing out you can sign in
  with a different Google account.
- Spring Security runs the OAuth 2.0 authorization-code flow and checks the ID token.
- **Error messages** cover a cancelled sign-in, an unverified email, missing profile data, an email
  already linked to another account, and generic failures (`?error=<code>` on `/login`).
- **Sessions:** server-side HTTP session with an `HttpOnly`, `SameSite=Lax` cookie (`Secure` in
  production), a 30-minute idle timeout, and a new session id after login (session-fixation
  protection). State-changing requests need a CSRF token (`XSRF-TOKEN` cookie → `X-XSRF-TOKEN`
  header).
- **Logout:** `POST /api/auth/logout` invalidates the session and deletes the session cookie.
- **Protected pages and endpoints:** unauthenticated API calls return `401`. The React
  `ProtectedRoute` sends guests to `/login`.

### 3. Role-based dashboards
| Role           | Dashboard after login | Navigation                              | API access                       |
|----------------|-----------------------|-----------------------------------------|----------------------------------|
| General User   | `/dashboard`          | Dashboard                               | `/api/me`, `/api/user/**`        |
| Administrator  | `/admin`              | Admin Dashboard, Users, My Account      | everything above + `/api/admin/**` |

- **Administrator dashboard:** account statistics (total users, general users, administrators, new
  users in the last 7 days), the newest accounts, and a searchable, paginated list of all users.
- **Backend enforcement:** URL rules in `SecurityConfig` plus `@PreAuthorize("hasRole('ADMIN')")` on
  `AdminService`. A General User calling an admin endpoint gets **HTTP 403** (NFR-006).
- **Frontend enforcement:** `ProtectedRoute roles={[...]}` sends users without the right role to
  a 403 page.

## Increment 2 features

> **SRS change:** the approved SRS listed email/password sign-in as *Won't Have* (FR-028) and said
> the database stores no passwords (FR-022, NFR-005). Increment 2 requires password management, so
> those items are superseded: users may now also register with an email and password. Passwords are
> only ever stored as BCrypt hashes.

### 1. Email + password accounts
- **Register** at `/register` (name, email, password, confirm password). Inputs are validated on
  the client and again on the server (Bean Validation). Password policy: 8–72 characters with at
  least one letter and one number (`@StrongPassword`).
- Passwords are hashed with **BCrypt** (random salt) before storage in `users.password_hash`.
- **One account per email.** An email already registered (with Google or a password) is rejected
  with a clear message rather than merged, so nobody can pre-register someone else's email and later
  take over their Google sign-in. `ADMIN_EMAILS` is never applied to password sign-ups, because their
  email has not been verified.
- **Sign in** on `/login` with email + password (`POST /api/auth/login`). It creates the same kind of
  server session as Google sign-in (new session id on login), and wrong credentials get one generic
  message, "Invalid email or password."

### 2. User profile management
- **Profile page** (`/profile`, for every signed-in user and admin): shows name, email, role,
  sign-in methods, member since and last sign-in.
- **Edit** the name and profile picture URL. Validated: name required (max 150); picture URL optional,
  `https://` only (max 500), so no `javascript:` or mixed-content images. Saved to the `users` table.
- **Only your own profile:** `PUT /api/me/profile` has no user id in the URL or body. The account
  always comes from the session, and extra fields such as `id` or `email` are ignored. Email
  cannot be changed.
- Google sign-in no longer overwrites a name the user edited.

### 3. Change password
- On the Profile page (`PUT /api/me/password`). It requires the **current password**, and the new
  password must meet the policy, match its confirmation, and differ from the current one.
- The hash is replaced, so the **old password stops working** immediately. The session id is
  renewed, and any outstanding reset links are cancelled.
- Google-only accounts have no password to change, so the page tells them to use Forgot password
  to create one.

### 4. Forgot / reset password
- **"Forgot password?"** link on the login page leads to `/forgot-password`, where you enter your email.
- The backend creates a random 256-bit token and stores only its **SHA-256 hash** in
  `password_reset_tokens`. The token **expires in 30 minutes** and is **single-use**; requesting a
  new link cancels older ones.
- The link (`/reset-password?token=…`) is **emailed** over SMTP. The response is the same whether or
  not the email exists, so it does not reveal which emails are registered.
- On the reset page the user enters and confirms a new password. It is validated, then hashed with
  BCrypt, and the token is marked used.
- **Without SMTP settings** (local development) the link is written to the backend log instead,
  in a line starting with `Password reset link for`.

## Increment 1 submission checklist

Status: **complete**. Git tag: `increment-1`. Every requirement below is implemented in this commit.

| Requirement | Where it is implemented |
|---|---|
| Account creation (Google sign-in), field validation | `backend/.../auth/UserAccountService.java`, `backend/.../auth/GoogleProfile.java` |
| No duplicate accounts | Unique keys in `backend/.../user/User.java` + checks in `UserAccountService.java` |
| Stored in MySQL | `backend/.../user/User.java`, `backend/.../user/UserRepository.java`, `application.properties` |
| No password storage (SRS FR-022, NFR-005) | Google verifies credentials. *(Superseded in Increment 2: passwords are stored as BCrypt hashes.)* |
| Role assignment (USER / ADMIN) | `backend/.../user/Role.java`, `UserAccountService.java`, `ADMIN_EMAILS` |
| Login interface + error messages | `frontend/src/pages/LoginPage.jsx`, `backend/.../auth/LoginFailureHandler.java` |
| Secure sessions, CSRF, logout | `backend/.../config/SecurityConfig.java`, `frontend/src/api.js`, `frontend/src/auth/AuthContext.jsx` |
| Protected pages and endpoints | `SecurityConfig.java` (401/403), `frontend/src/components/ProtectedRoute.jsx` |
| Role-based redirect after login | `backend/.../auth/LoginSuccessHandler.java` |
| Role-based dashboards + navigation | `frontend/src/pages/UserDashboard.jsx`, `AdminDashboard.jsx`, `AdminUsers.jsx`, `frontend/src/components/Layout.jsx` |
| Backend RBAC | `SecurityConfig.java` URL rules + `@PreAuthorize` in `backend/.../admin/AdminService.java` |
| Tests | `backend/src/test/java/...` (17 tests: registration, duplicates, validation, 401/403, logout) |

`backend/...` = `backend/src/main/java/edu/cit/alvarado/phishmenot`.

## Increment 2 submission checklist

| Requirement | Where it is implemented |
|---|---|
| View and edit own profile, validated, saved to DB | `frontend/src/pages/ProfilePage.jsx`, `backend/.../user/ProfileController.java`, `ProfileService.java` |
| No changes to other users' profiles | `ProfileController` uses the session's account only (`CurrentUserService`), no id parameter |
| Forgot Password on the login page | `frontend/src/pages/LoginPage.jsx`, `ForgotPasswordPage.jsx` |
| Secure identity verification / recovery | Emailed link to the account's address: `backend/.../auth/PasswordResetMailer.java` |
| Expiring, single-use token | `backend/.../auth/PasswordResetToken.java` (SHA-256 hash, 30 min, `used_at`), `LocalAuthService.java` |
| Hash new passwords | BCrypt `PasswordEncoder` in `backend/.../config/SecurityConfig.java` |
| Change password with current-password check | `ProfileService.changePassword`, Profile page |
| Validate + confirm new password | `@StrongPassword` (`backend/.../auth/StrongPassword.java`), confirm checks in services and pages |
| Old password no longer works | Hash replaced; covered by `PasswordAndProfileTest` |
| Increment 1 still works | Google sign-in, sessions, RBAC unchanged; all Increment 1 tests pass |
| Tests | `backend/src/test/java/.../PasswordAndProfileTest.java` (13 tests) + 17 from Increment 1 |
| Completion report | `docs/Increment-2-Completion-Report.pdf` |

## API

| Method | Path                               | Access        | Description                                  |
|--------|------------------------------------|---------------|----------------------------------------------|
| GET    | `/oauth2/authorization/google`     | Public        | Start Google sign-in                         |
| GET    | `/login/oauth2/code/google`        | Public        | OAuth callback (handled by Spring Security)  |
| POST   | `/api/auth/logout`                 | Signed in     | End the session (needs CSRF header) → 204    |
| POST   | `/api/auth/register`               | Public        | Create an email + password account → 201     |
| POST   | `/api/auth/login`                  | Public        | Email + password sign-in (starts session)    |
| POST   | `/api/auth/forgot-password`        | Public        | Email a reset link (same reply for any email)|
| POST   | `/api/auth/reset-password`         | Public        | Set a new password with a reset token        |
| GET    | `/api/me`                          | Signed in     | Current user's profile and role              |
| PUT    | `/api/me/profile`                  | Signed in     | Update own name / picture URL                |
| PUT    | `/api/me/password`                 | Signed in     | Change own password (needs current password) |
| GET    | `/api/user/dashboard`              | USER, ADMIN   | General User dashboard data                  |
| GET    | `/api/admin/dashboard`             | ADMIN         | Account statistics + newest accounts         |
| GET    | `/api/admin/users?query=&page=&size=` | ADMIN      | Search / page through all users              |
| GET    | `/api/health`                      | Public        | Liveness check                               |

## Project structure

```
backend/                         Spring Boot REST API
  src/main/java/edu/cit/alvarado/phishmenot/
    auth/      Google sign-in, email+password register/login, forgot/reset password, reset tokens, mailer, /api/me
    admin/     Administrator dashboard + user list (ADMIN only)
    user/      User entity, Role enum, repository, General User dashboard, profile + change password
    config/    SecurityConfig (OAuth2 login, sessions, CSRF, CORS, RBAC), app properties
    common/    Error handling, health endpoint
  src/main/resources/schema-mysql.sql   One-line upgrade of the Increment 1 users table (google_id → nullable)
  src/test/    Integration tests (registration, duplicates, validation, 401/403, logout, passwords, profile)
frontend/                        React + Vite single-page app
  src/auth/        AuthContext (session state, logout)
  src/components/  ProtectedRoute (role guard), Layout (role-based navigation), tables
  src/pages/       Login, Register, Forgot/Reset password, Profile, User dashboard, Admin pages, 403, 404
docs/                            Increment completion reports
```

## Setup and execution

### Prerequisites
- JDK 21
- Node.js 20+ (LTS) and npm
- MySQL 8 (or MariaDB) running locally
- A Google Cloud project with an OAuth 2.0 Client ID

### 1. Create the Google OAuth client
1. Open Google Cloud Console → **APIs & Services → OAuth consent screen**, and configure it
   (External, add yourself as a test user).
2. Go to **Credentials → Create credentials → OAuth client ID → Web application**.
3. **Authorized JavaScript origins:** `http://localhost:5173`
4. **Authorized redirect URIs:** `http://localhost:8080/login/oauth2/code/google`
5. Copy the client ID and client secret.

### 2. Prepare MySQL
The database is created automatically (`createDatabaseIfNotExist=true`), and Hibernate creates the
`users` table on first start. You only need a MySQL user that is allowed to create it, for example:

```sql
CREATE DATABASE IF NOT EXISTS phishmenot;
CREATE USER 'phishmenot'@'localhost' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON phishmenot.* TO 'phishmenot'@'localhost';
```

### 3. Run the backend (port 8080)
Set the environment variables (see `backend/.env.example`), then start Spring Boot.

macOS / Linux:
```bash
cd backend
export GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=xxxx
export DB_USERNAME=phishmenot
export DB_PASSWORD=change-me
export ADMIN_EMAILS=your.admin.email@gmail.com   # optional
./mvnw spring-boot:run
```

Windows (PowerShell):
```powershell
cd backend
$env:GOOGLE_CLIENT_ID="xxxx.apps.googleusercontent.com"
$env:GOOGLE_CLIENT_SECRET="xxxx"
$env:DB_USERNAME="phishmenot"
$env:DB_PASSWORD="change-me"
$env:ADMIN_EMAILS="your.admin.email@gmail.com"
.\mvnw.cmd spring-boot:run
```

In IntelliJ IDEA you can put the same variables in the run configuration's *Environment variables*.

| Variable               | Default                                            | Purpose                                    |
|------------------------|----------------------------------------------------|--------------------------------------------|
| `GOOGLE_CLIENT_ID`     | — (required)                                       | Google OAuth client id                     |
| `GOOGLE_CLIENT_SECRET` | — (required)                                       | Google OAuth client secret                 |
| `DB_URL`               | `jdbc:mysql://localhost:3306/phishmenot?createDatabaseIfNotExist=true&serverTimezone=UTC` | MySQL JDBC URL |
| `DB_USERNAME`          | `root`                                             | MySQL user                                 |
| `DB_PASSWORD`          | empty                                              | MySQL password                             |
| `FRONTEND_URL`         | `http://localhost:5173`                            | Where to redirect after login; CORS origin |
| `ADMIN_EMAILS`         | empty                                              | Comma-separated emails that get ADMIN at sign-in |
| `COOKIE_SECURE`        | `false`                                            | Set `true` when served over HTTPS          |
| `PORT`                 | `8080`                                             | Backend port                               |
| `SPRING_MAIL_HOST`     | — (optional)                                       | SMTP server for reset emails, e.g. `smtp.gmail.com` |
| `SPRING_MAIL_PORT`     | —                                                  | e.g. `587`                                 |
| `SPRING_MAIL_USERNAME` | —                                                  | SMTP login, e.g. your Gmail address        |
| `SPRING_MAIL_PASSWORD` | —                                                  | SMTP password (for Gmail: an **App Password**) |
| `MAIL_FROM`            | `SPRING_MAIL_USERNAME`                             | Sender address of reset emails             |
| `SPRING_JPA_DATABASEPLATFORM` | —                                           | Set to `org.hibernate.dialect.MariaDBDialect` when using **MariaDB** |

**Sending reset emails with Gmail:** turn on 2-Step Verification on the Google account, create an
App Password (Google Account → Security → App passwords), then set `SPRING_MAIL_HOST=smtp.gmail.com`,
`SPRING_MAIL_PORT=587`, `SPRING_MAIL_USERNAME=<gmail address>` and
`SPRING_MAIL_PASSWORD=<16-character app password>`. Without these, the reset link appears in the
backend log instead.

**Upgrading an Increment 1 database:** nothing to do by hand. On start, Hibernate adds the
`password_hash` column and the `password_reset_tokens` table, and `schema-mysql.sql` makes
`google_id` nullable.

### 4. Run the frontend (port 5173)
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173, then sign in with Google or create an account with your email. In development, Vite proxies `/api`
to the backend (`VITE_BACKEND_URL`, default `http://localhost:8080`).

### 5. Make an existing account an Administrator
Either add the email to `ADMIN_EMAILS`, restart the backend, and sign in again, or update the role
in MySQL and sign in again:

```sql
UPDATE phishmenot.users SET role = 'ADMIN' WHERE email = 'your.admin.email@gmail.com';
```

### Run the tests
```bash
cd backend
./mvnw test
```
The tests use an in-memory H2 database in MySQL mode. They cover first-time registration,
returning users (no duplicates), duplicate-email rejection, required-field and verified-email
validation, admin role assignment, 401 for anonymous requests, 403 for General Users on admin
endpoints, CSRF-protected logout that ends the session, and role-based redirects after login.
Increment 2 tests (`PasswordAndProfileTest`) cover registration (hashing, validation, duplicates, no
admin escalation), password login, profile editing (validation, own profile only), change password
(wrong current, mismatch, policy, old password rejected), and reset links (hashed, single-use,
replaced by newer links, expiry, no email enumeration).

## Demo walkthrough
1. Open http://localhost:5173 → you are sent to `/login`.
2. Sign in with a Google account → a `USER` account is created in MySQL → you land on `/dashboard`.
3. Try http://localhost:5173/admin → you are shown the **403** page. Calling
   `http://localhost:5173/api/admin/dashboard` directly returns HTTP 403 JSON.
4. Sign out → the session ends, and `/dashboard` sends you back to `/login`.
5. Promote the account (step 5 above), sign in again → you land on the **Administrator Dashboard**
   with the admin navigation menu.

### Increment 2 walkthrough
1. On `/login` click **Create an account**, register with a name, email and password → you land on
   your dashboard. The `users` row has a `$2a$…` BCrypt hash, never the password.
2. Open **Profile**, change your name → **Save changes**. Try an empty name or an `http://`
   picture URL to see validation.
3. Under **Change password**, try a wrong current password, then change it properly. Sign out:
   the old password is rejected and the new one works.
4. Sign out → **Forgot password?** → enter your email. Open the emailed link (or the link from the
   backend log), set a new password, and sign in with it. Opening the same link again shows
   "invalid, has expired, or was already used".
