# OSINT Workspace

**Subtitle/Credit:** Tool By Musayyab Shah  
**Author Credit:** By Musayyab Shah

OSINT Workspace is a **defensive, local-first analyst assistant** built as a single-file Python desktop app (`osint_workspace.py`).
It helps you import a curated OSINT markdown list, organize tools, filter relevant options for a specific indicator, and launch tools safely.

> **Disclaimer:** Use only on assets you own or are authorized to investigate.

---

## Key Features

- Single-file Tkinter desktop app (Python 3.11+).
- Imports tools from `awesome_osint.md`.
- Parses categories + tool links + descriptions.
- Auto-detects indicator types (URL, domain, IP, email, username, phone, hash, etc.).
- Shows a **Relevant Tools** view based on indicator type.
- Safe launch actions:
  - Open Home
  - Open Search Page (only when a safe/public query template exists)
  - Copy Query
  - Favorite
  - Add Note
- Local notes/case tracking and export.
- Favorites, recent indicators, and recent launches.
- Optional API plugin placeholders (disabled by default).

---

## Safety Scope

This app is intentionally constrained to **safe OSINT workflow management**:

- ✅ Local organization, categorization, filtering, launching, and note-taking.
- ✅ Optional official API placeholders (disabled by default).
- ❌ No scraping of third-party sites.
- ❌ No login automation or CAPTCHA bypass.
- ❌ No anti-bot bypass or stealth behavior.
- ❌ No mass enumeration or bulk external querying.
- ❌ No exploit, malware, phishing, or offensive functions.

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
```

Optional packages (app still runs without them):

```bash
pip install ttkbootstrap validators tldextract
```

---

## Run

```bash
python osint_workspace.py
```

By default, the app expects:

- `awesome_osint.md` in the same directory.

You can change the markdown path in **Settings**.

---

## Data Files (Local JSON)

The app stores local state in:

- `tools_cache.json`
- `favorites.json`
- `notes.json`
- `settings.json`
- `recent.json`

---

## Indicator Types Supported

- URL
- Domain
- IP (IPv4 / IPv6)
- Email
- Username
- Phone
- Hash
- Company
- Person name
- Keyword

---

## Extending the App Safely

### Add new query templates
Edit `QUERY_TEMPLATES` in `osint_workspace.py` and only add patterns with clear, public, safe URL structures.
If uncertain, keep tools in manual-homepage mode.

### Add official API plugins
Use the `APIPluginBase` pattern and keep plugins disabled by default.
Only enable after explicit user configuration and official API key setup.

---

## Troubleshooting

- If no tools appear, verify `awesome_osint.md` path in **Settings**.
- If parsing misses entries, ensure markdown bullets use this format:
  - `* [Tool Name](https://example.com) - description`
- If a tool cannot prefill search, that is expected when no safe query template is known.

---

## License / Usage

Use responsibly and lawfully. This project is for **defensive analysis workflow support** only.
