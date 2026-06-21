# 🚀 Deploying ExtenShield online (free)

This guide takes your project from "runs on my laptop" to "anyone can use it
from a public web link." We use **GitHub** (to store the code online) and
**Streamlit Community Cloud** (to run it for free). No payment, no server setup.

When you finish, you'll have a link like `https://extenshield.streamlit.app`
that you can put in your report and show your evaluator.

Total time: about 20–30 minutes the first time.

---

## What you need (all free)

1. A **GitHub account** — https://github.com/signup
2. A **Streamlit Community Cloud account** — https://share.streamlit.io
   (you sign in using your GitHub account, so make GitHub first)

---

## Part A — Put your code on GitHub

GitHub is a website that stores code. "Pushing" your project there is what lets
Streamlit Cloud find and run it.

### Option 1 (easiest, no commands) — Upload through the website

1. Go to https://github.com and sign in.
2. Click the **+** icon (top-right) → **New repository**.
3. Fill in:
   - **Repository name:** `extenshield`
   - Set it to **Public** (Streamlit's free tier needs public repos).
   - Do **not** tick "Add a README" (you already have one).
4. Click **Create repository**.
5. On the next page, click the link **"uploading an existing file"**.
6. Open your project folder on your computer:
   `C:\Users\user\Documents\SEM4\FYP\Project\Extenshield`
7. Select **all the files and folders inside it** (app.py, cli.py, README.md,
   requirements.txt, the `extenshield` folder, the `samples` folder, the
   `tests` folder, `.gitignore`, and the `.streamlit` folder) and **drag them
   into the GitHub upload area**.
   - Tip: if the `.streamlit` folder is hidden, in File Explorer click
     **View → Show → Hidden items** so you can see and drag it.
8. Scroll down and click **Commit changes**.

Your code is now on GitHub. 

### Option 2 (if you prefer commands) — Git push

If you have Git installed, run these from inside the project folder:

```bash
git init
git add .
git commit -m "ExtenShield initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/extenshield.git
git push -u origin main
```

(Replace `YOUR_USERNAME` with your GitHub username.)

---

## Part B — Deploy on Streamlit Community Cloud

1. Go to https://share.streamlit.io and click **Sign in with GitHub**
   (approve access when asked).
2. Click **Create app** (or **New app**).
3. Choose **"Deploy a public app from GitHub"**.
4. Fill in the form:
   - **Repository:** `YOUR_USERNAME/extenshield`
   - **Branch:** `main`
   - **Main file path:** `app.py`
5. (Recommended) Click **Advanced settings** and set **Python version** to
   **3.12**. This avoids any issues with very new Python versions.
6. Click **Deploy**.

Streamlit now installs your `requirements.txt` and starts your app. The first
build takes 2–5 minutes (you'll see a log scrolling). When it's done, your app
opens at a public URL such as:

```
https://extenshield.streamlit.app
```

That link is now shareable with anyone. 🎉

---

## Part C — Test that real users can use it

Open your public link (try it on your phone too) and:

- Go to the **"Scan a folder path"** tab and type `samples/malicious_extension`
  then click **Scan folder**. Because your sample folders were uploaded with the
  code, this works on the live site as a built-in demo — great for showing your
  evaluator without needing any file.
  - Note: on the web, use a forward slash `/` in the path
    (`samples/malicious_extension`), not a backslash.
- Or use the **Upload** tab to upload a real extension `.zip` / `.crx`.

---

## Updating the app later

Whenever you change your code, just upload/commit the new version to GitHub.
Streamlit Cloud automatically redeploys within a minute — no extra steps.

---

## Troubleshooting

- **Build fails on "installing requirements"** → set Python version to **3.12**
  in Advanced settings and redeploy.
- **"main file not found"** → make sure **Main file path** is exactly `app.py`
  and that `app.py` sits at the top level of the repo (not inside a subfolder).
- **`ModuleNotFoundError: extenshield`** → the `extenshield` folder must be
  uploaded to the repo root, next to `app.py`. Re-check the upload.
- **App "sleeps" after inactivity** → normal on the free tier; the first visit
  after a while takes ~30 seconds to wake up. Just wait.

---

## How this maps to "a real product"

Once deployed, the user experience is: open a link → scan an extension → read a
risk report. No Python, no install, no files needed for the built-in demo. That
is exactly the "normal user" experience you were aiming for. The natural next
upgrade is letting users paste a **Chrome Web Store link** so the tool downloads
and scans the extension automatically — ask and I can add that.
