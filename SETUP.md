# Setup Guide — API Secure

A step-by-step guide to get this project running on a new machine from scratch.
Follow the steps in order. Total time: about 20 minutes.

The project has two parts that must both be running:

- **Backend** — Python (Flask), runs on port **3001**, does the actual security scanning
- **Frontend** — React (Vite), runs on port **5173**, the website you open in your browser

---

## Step 0 — Install the basics

Make sure these are installed. Check by running each command:

| Need | Check with | Minimum |
|------|-----------|---------|
| Python | `python3 --version` | 3.8 or newer |
| Node.js | `node --version` | 18 or newer |

Download from [python.org](https://www.python.org/downloads/) and [nodejs.org](https://nodejs.org/) if missing.

> **Note on commands:** This guide uses `python3` (macOS/Linux). On Windows, use `py` instead of `python3`.

---

## Step 1 — Set up the backend

Open a terminal in the `Main Project` folder and run:

```bash
cd "Main Project"

# Create an isolated Python environment (keeps this project's packages separate)
python3 -m venv .venv

# Install the Python packages
.venv/bin/pip install -r requirements.txt
```

On Windows the last command is `.venv\Scripts\pip install -r requirements.txt`.

Now create the backend settings file:

```bash
cp .env.example .env
```

**You do not need to edit this file to get started.** Everything in it is optional and
has a working default. You only touch it later if you want email reports (see Step 6).

---

## Step 2 — Create a Firebase project (for login)

Firebase handles "Sign in with Google". You need your own project.

1. Go to the [Firebase Console](https://console.firebase.google.com/) and click **Add project**.
2. Give it any name, then click through to create it. (Google Analytics is optional — skip it.)

### 2a. Turn on Authentication

This step is easy to miss, and login will **not** work without it.

1. In the left sidebar, click **Build → Authentication**.
2. Click the **Get started** button.
3. Open the **Sign-in method** tab.
4. Click **Google** in the provider list.
5. Flip the **Enable** switch on.
6. Pick a **Project support email** from the dropdown.
7. Click **Save**.

### 2b. Allow localhost

1. Still in Authentication, go to **Settings → Authorized domains**.
2. Confirm `localhost` is in the list. It is normally there by default — if not, click
   **Add domain** and add it.
3. When you later put the site online, add your real domain here too. Any domain not on
   this list is refused by Firebase.

### 2c. Copy your Firebase keys

1. Click the **gear icon → Project settings**.
2. Scroll to **Your apps** and click the web icon (`</>`) to register a web app.
   Give it a nickname; you do not need Firebase Hosting.
3. Firebase shows a code block containing a `firebaseConfig` object. Keep this page open —
   you will copy these seven values in Step 4.

It looks like this:

```js
const firebaseConfig = {
  apiKey: "AIza...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project",
  storageBucket: "your-project.firebasestorage.app",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abc123",
  measurementId: "G-XXXXXXX"
};
```

---

## Step 3 — Create a Supabase project (for user profiles)

Firebase handles the login itself; Supabase stores the username and profile details.

1. Go to [supabase.com](https://supabase.com/), sign in, and click **New project**.
2. Pick any name and password, then wait for it to finish setting up.

### 3a. Create the `users` table

1. In the left sidebar, click **SQL Editor**.
2. Paste the following and click **Run**:

```sql
create table users (
  id text primary key,
  email text unique not null,
  username text unique not null,
  google_connected boolean default false,
  google_display_name text,
  google_photo_url text,
  google_email text,
  has_password boolean default false,
  created_at timestamptz default now(),
  last_login timestamptz
);

-- The app talks to Supabase from the browser, so allow access with the public key.
alter table users enable row level security;

create policy "allow read" on users for select using (true);
create policy "allow insert" on users for insert with check (true);
create policy "allow update" on users for update using (true);
```

The `id` column holds the Firebase user ID, which is what links the two services together.

### 3b. Copy your Supabase keys

1. Click **Project Settings → API**.
2. Copy the **Project URL** and the **anon / public** key. You need both in Step 4.

---

## Step 4 — Enter your keys in the frontend

Create the frontend settings file:

```bash
cd "Main Project/frontend"
cp .env.example .env
```

Open `frontend/.env` in any text editor and fill in the nine values using what you
copied in Steps 2c and 3b:

```
VITE_FIREBASE_API_KEY=<apiKey>
VITE_FIREBASE_AUTH_DOMAIN=<authDomain>
VITE_FIREBASE_PROJECT_ID=<projectId>
VITE_FIREBASE_STORAGE_BUCKET=<storageBucket>
VITE_FIREBASE_MESSAGING_SENDER_ID=<messagingSenderId>
VITE_FIREBASE_APP_ID=<appId>
VITE_FIREBASE_MEASUREMENT_ID=<measurementId>
VITE_SUPABASE_URL=<Project URL>
VITE_SUPABASE_ANON_KEY=<anon public key>
```

Paste the values plainly — no quotes, no spaces around the `=`.

> **Important:** These values are only read when the frontend starts. If you change this
> file while the site is running, stop the frontend and start it again, or your change
> will be ignored.

---

## Step 5 — Install the frontend and run everything

Install the frontend packages (once):

```bash
cd "Main Project/frontend"
npm install
```

Now run both parts. **They each need their own terminal window, and both must stay open.**

**Terminal 1 — backend:**

```bash
cd "Main Project"
.venv/bin/python app.py
```

You should see `Running on http://127.0.0.1:3001`.

**Terminal 2 — frontend:**

```bash
cd "Main Project/frontend"
npm run dev
```

You should see `Local: http://localhost:5173/`.

### Open the app

Go to **http://localhost:5173** and sign in with Google.

> Use `localhost`, not `127.0.0.1`. The frontend only listens on `localhost`, and that
> is also the address allowed in Firebase.

To check the backend is alive on its own, open **http://localhost:3001/api/health** —
it should show `{"service": "API Secure", "status": "ok"}`.

---

## Step 6 — Email reports (optional)

Skip this unless you want scan reports emailed. Scanning works fine without it.

Edit `Main Project/.env` and fill in **one** of the two options:

**Option A — SMTP (simplest).** Works with Gmail, Outlook, or any mail server. For Gmail
you must create an [App Password](https://myaccount.google.com/apppasswords) — your normal
password will not work.

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=1
SMTP_USER=your.email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your.email@gmail.com
```

**Option B — Gmail OAuth.** Create OAuth credentials in Google Cloud Console, then run
`python3 scripts/get_gmail_refresh_token.py` once and paste the token it prints into `.env`.
See the comments in `.env.example` for the full instructions.

Restart the backend after editing `.env`.

---

## Step 7 — Putting it online (optional)

```bash
cd "Main Project/frontend"
npm run build
```

This creates a `dist` folder to upload to your web host. Then:

- In `Main Project/.env`, set `FLASK_ENV=production` and set `CORS_ORIGINS` to your real
  site address instead of `*`.
- In Firebase, add your real domain under **Authentication → Settings → Authorized domains**.
- Rebuild whenever you change `frontend/.env`, because these values get baked into the
  built files.

---

## A note on AI / LLM analysis

You do **not** need any AI or LLM keys to run this project. The reports are built with
lightweight, rule-based scripting and basic analysis.

- A local LLM such as BART could be added for AI-based analysis in the future. However, the
  backend is currently deployed on Render's free tier, which has resource limitations and
  cannot host an LLM model of 3 GB or larger.
- Using external LLM APIs would also add usage costs.
- So the current version was intentionally built without an external or locally hosted LLM.

The architecture can be extended later to support AI-powered analysis, intelligent
vulnerability interpretation, automated recommendations, and more advanced security
insights once suitable infrastructure or an LLM service is available.

---

## If something goes wrong

| What you see | What it means | Fix |
|---|---|---|
| "Google sign-in is not enabled for this Firebase project" | Authentication was never switched on | Redo **Step 2a** — the **Get started** button is the part people miss |
| "This domain is not authorized for sign-in" | Firebase does not recognise the address | Add the domain in **Step 2b** |
| "The Firebase API key is invalid" | A key is wrong or missing | Recheck `frontend/.env` against Step 2c, then restart the frontend |
| Sign-in popup opens then closes instantly | Browser blocked the popup | Allow popups for `localhost` |
| "Cannot reach the backend" | Backend is not running | Start Terminal 1 from Step 5 and leave it open |
| Login works but profile fails to save | `users` table missing or blocking access | Rerun the SQL in **Step 3a** |
| Changed `.env` but nothing happened | Settings load only at startup | Stop the frontend and run `npm run dev` again |
| `Port 3001 is in use` | An old copy is still running | Close the old terminal, or find and stop it: `lsof -i :3001` |

**Getting the real error:** if sign-in fails without a clear reason, open your browser's
developer tools (F12) and look at the **Console** tab. The exact Firebase error code is
printed there.

---

## Files you should never commit or share

Both `.env` files contain your private keys:

- `Main Project/.env`
- `Main Project/frontend/.env`

They are already listed in `.gitignore`. When handing the project to someone else, let
them create their own using the `.env.example` files as templates.
