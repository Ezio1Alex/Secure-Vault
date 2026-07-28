# 🔒 Secure Vault

[![Deploy Worker](https://github.com/Ezio1Alex/Secure-Vault/actions/workflows/deploy.yml/badge.svg)](https://github.com/Ezio1Alex/Secure-Vault/actions/workflows/deploy.yml)

> 📖 中文版请见 [README.zh-CN.md](README.zh-CN.md)

**Secure Vault** is a **zero-knowledge, end-to-end encrypted** password manager built on Cloudflare Workers. Your passwords are encrypted and decrypted entirely in the browser — the server never sees plaintext credentials.

---

## Features ✨

| Feature | Description |
|---|---|
| 🔒 **Zero-knowledge architecture** | Server stores only ciphertext; plaintext never leaves the browser |
| 🛡️ **AES-GCM 256-bit encryption** | PBKDF2 key derivation (600k iterations) |
| 📱 **Mobile-responsive design** | Fully adaptive UI for phone and desktop |
| 🌙 **Dark / Light mode** | System theme auto-follow + manual toggle |
| 🔑 **Password generator** | Built-in customizable strong password generator |
| 📌 **Pin to top** | Pin frequently used credentials for quick access |
| 🔍 **Search & filter** | Search by site, username, or notes; filter by site |
| 📤 **Export / Import** | JSON backup export (plaintext) and import with re-encryption |
| ⏰ **Auto-lock** | Automatically locks after 3 minutes of inactivity |
| 🏗️ **Group by site** | Entries auto-grouped by website with collapsible sections |
| 🌐 **i18n Support** | Chinese (zh) / English (en) toggle, auto-detects browser language |

---

## Architecture 🏗️

```
┌──────────────────────────────────────────────────────────────────┐
│  Browser (Web Crypto API)                                        │
│                                                                  │
│  Master Password                                                 │
│       │                                                          │
│       ├── PBKDF2(SHA-256, 600k) ──► Master Key (AES-GCM)         │
│       │                              │                           │
│       └── SHA-256(username:password:salt) ──► Auth Key           │
│                                                  │               │
└───────────────────────────────────────────────────│──────────────┘
                                                   │ x-username
                                                   │ x-auth-key
                                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Cloudflare Workers (Hono)                   ┌──────────────────┐│
│  ● Auth Middleware (verify x-auth-key)       │  Cloudflare      ││
│  ● CRUD endpoints for encrypted blobs        │  D1 Database     ││
│  ● SPA served at GET /                       │  (SQLite)        ││
│                                              │                  ││
│                                              │  users           ││
│                                              │  passwords       ││
│                                              │  vault_config    ││
│                                              └──────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### Key Security Design

1. **Master Salt** — generated once on first request, stored in `vault_config` table
2. **Auth Key** — `SHA-256(username + ":" + password + ":" + salt)` sent as `x-auth-key` header
3. **Master Key** — `PBKDF2(password, salt, 600000 iterations)` → AES-GCM 256-bit. **Never leaves the browser**
4. **Encrypted Payload** — `{ site, username, password, note }` JSON → AES-GCM encrypted → base64 → stored in D1

> ⚠️ **Lost your master password? Data is unrecoverable.** There is no backdoor, no password reset, no admin override — by design.

---

## Tech Stack 🛠️

| Layer | Technology |
|---|---|
| Runtime | [Cloudflare Workers](https://workers.cloudflare.com/) |
| Web Framework | [Hono](https://hono.dev/) v4 |
| Database | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) |
| Encryption | Web Crypto API (AES-GCM 256 / PBKDF2 / SHA-256) |
| Frontend | Vanilla HTML + CSS + JS (SPA, no framework) |
| i18n | Client-side dictionary with `data-i18n` DOM bindings, `localStorage` persistence |
| Deployment | [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) + GitHub Actions |

---

## Quick Start 🚀

A complete walkthrough — from zero to a live app with auto-deploy.

---

### 📋 Prerequisites

| What you need | How to get it |
|---|---|
| [Node.js](https://nodejs.org/) 18+ | Download from nodejs.org |
| [Cloudflare account](https://dash.cloudflare.com/sign-up) | Free sign-up at Cloudflare |
| Wrangler CLI | `npm install -g wrangler` (comes with the project, but install globally for convenience) |

---

### 🔧 Part 1: One-time Setup (do this once)

#### 1. Clone & install

```bash
git clone https://github.com/Ezio1Alex/Secure-Vault.git
cd Secure-Vault
npm install
```

#### 2. Log in to Cloudflare

```bash
npx wrangler login
```

This opens your browser to authorize Wrangler. Select **Allow** — it needs this to create databases and deploy your code.

#### 3. Create a D1 database

```bash
npx wrangler d1 create vault_db
```

You'll see output like:
```
✅ Successfully created DB 'vault_db' in region APAC
Created your database using D1's new storage backend.
[[d1_databases]]
binding = "DB"
database_name = "vault_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Copy the `database_id`** (the UUID string), you'll need it in the next step.

#### 4. Configure wrangler.toml

Open [`wrangler.toml`](wrangler.toml) and paste your `database_id`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "vault_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← Paste your ID here
```

#### 5. Initialize the database tables

```bash
npx wrangler d1 migrations apply vault_db --remote
```

Expected output:
```
✅ Applied migration 001_create_tables.sql
```

If you get an error, make sure your `database_id` is correct in `wrangler.toml`.

#### 6. Test locally

```bash
npm run dev
# or: npx wrangler dev
```

Open `http://localhost:8787` in your browser. You should see the login screen.

To test with a real D1 database locally:
```bash
npx wrangler d1 migrations apply vault_db --local
npx wrangler dev
```

#### 7. Deploy for the first time

```bash
npm run deploy
# or: npx wrangler deploy
```

Your app is now live! The URL will be shown in the output, e.g. `https://secure-vault.your-account.workers.dev`.

---

### 🤖 Part 2: Auto-deploy with GitHub Actions

Once the app is running, set up CI/CD so every `git push` to `main` automatically deploys the latest version.

#### 1. Create a Cloudflare API Token

- Go to [Cloudflare Dashboard → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
- Click **Create Token** → Use the **Edit Cloudflare Workers** template
- Under **Permissions**, make sure these are included:

  | Permission | Access |
  |---|---|
  | Workers: Edit | Include |
  | Workers Routes: Edit | Include |
  | D1: Edit | Include |
  | Account Settings: Read | Include |

- Click **Continue to Summary → Create Token**
- **Copy the token now** — it's shown only once!

#### 2. Add the token as a GitHub Secret

- Go to your GitHub repo: `https://github.com/Ezio1Alex/Secure-Vault`
- Click **Settings → Secrets and variables → Actions**
- Click **New repository secret**
  - **Name**: `CLOUDFLARE_API_TOKEN`
  - **Secret**: Paste the token you just copied
  - Click **Add secret**

#### 3. Push to trigger auto-deploy

```bash
git add -A
git commit -m "update something"
git push origin main
```

That's it! Go to your repo's **Actions** tab — you'll see the workflow running:

```
✅ Setup Node.js
✅ Install dependencies
✅ Deploy to Cloudflare Workers
```

The workflow (`.github/workflows/deploy.yml`) simply deploys your code on every push. The database migration you ran during setup is a one-time task — if you add new migrations later, run them locally:

```bash
npx wrangler d1 migrations apply vault_db --remote
```

---

### 📊 How the deployment works

```
You push to GitHub main
        │
        ▼
GitHub Actions (deploy.yml)
        │
        ├─ npm ci              ← Install dependencies
        └─ wrangler deploy     ← Deploy Worker to Cloudflare
        │
        ▼
Your app is live at *.workers.dev
```

---

## Database Schema 📊

```sql
-- Users table (max 5 accounts by default)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Encrypted password records
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    encrypted_data TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pinned INTEGER DEFAULT 0,
    FOREIGN KEY(username) REFERENCES users(username)
);

-- Key-value configuration (stores master salt)
CREATE TABLE vault_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## API Reference 📡

| Method | Route | Auth | Description |
|---|---|---|---|
| `GET` | `/` | No | Serve the SPA |
| `GET` | `/api/salt` | No | Get or generate master salt |
| `POST` | `/api/register` | No | Register a new account |
| `POST` | `/api/login` | No | Authenticate |
| `GET` | `/api/secrets` | Yes | List all encrypted records |
| `POST` | `/api/secrets` | Yes | Create a new encrypted record |
| `PUT` | `/api/secrets/:id` | Yes | Update an existing record |
| `DELETE` | `/api/secrets/:id` | Yes | Delete a record |
| `POST` | `/api/secrets/:id/pin` | Yes | Toggle pinned status |

> Authenticated endpoints require `x-username` and `x-auth-key` headers (derived client-side).

---

## Project Structure 📁

```
secure-vault/
├── src/
│   └── index.ts          # Main application (API + SPA)
├── migrations/
│   └── 001_create_tables.sql
├── schema.sql            # Full database schema for reference
├── wrangler.toml         # Cloudflare Workers configuration
├── package.json
├── CLAUDE.md             # Claude AI assistant instructions (Chinese)
├── README.md             # Documentation (Chinese)
├── README_EN.md          # Documentation (English)
└── LICENSE
```

The entire application — backend API routes, auth middleware, database queries, and the full frontend SPA (HTML/CSS/JS) — is contained in a single file: [`src/index.ts`](src/index.ts). This keeps deployment simple and fast.

---

## Configuration 🌐

All configuration lives in [`wrangler.toml`](wrangler.toml). The D1 database binding named `DB` is the only required binding.

No secrets or API keys are hardcoded. For GitHub Actions deployment, set `CLOUDFLARE_API_TOKEN` in your repository secrets.

---

## Customization 🎨

- **User limit**: Change `5` in `src/index.ts` line 32 (`userCount.count >= 5`)
- **Password strength rules**: Edit `evaluatePasswordStrength()` in the SPA JavaScript section
- **Auto-lock timing**: Adjust `WARNING_MS` (150000) and `LOCK_MS` (180000) in the SPA JavaScript
- **PBKDF2 iterations**: Change `600000` in `deriveKey()` — higher = more secure but slower
- **Language toggle**: Click the **EN/中** button at the top-right of the login or main page to switch between English and Chinese. Your preference is saved in browser `localStorage`.

---

## License 📄

[MIT](LICENSE)

---

## Disclaimer ⚠️

This project is provided as-is for educational and personal use. While best practices in client-side encryption are followed, always review the code and understand the security model before trusting it with sensitive data. The authors are not responsible for any data loss or security breaches resulting from the use of this software.
