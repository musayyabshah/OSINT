#!/usr/bin/env python3
"""
OSINT Workspace (Single-file Tkinter App)
=========================================

README (Quick Start)
--------------------
Install (Python 3.11+):
  python -m venv .venv
  source .venv/bin/activate      # Windows: .venv\Scripts\activate
  pip install --upgrade pip

Optional dependencies (app works without these):
  pip install ttkbootstrap validators tldextract

Run:
  python osint_workspace.py

Input data:
  Place a Markdown file named `awesome_osint.md` in the same directory,
  or set a custom path in Settings.

Safety Disclaimer:
  Use only on assets you own or are authorized to investigate.
  This is a defensive analyst organizer/launcher. It does not scrape websites,
  bypass protections, automate logins, or perform offensive operations.

Sample relevance mapping (inferred)
-----------------------------------
Indicator -> Preferred tags/categories
- URL/Domain/IP -> Domain/IP, DNS, Threat Intel, Archives, Search
- Username      -> Social, Search, Code
- Email         -> Email, Search
- Phone         -> Phone, Search
- Hash          -> Threat Intel, Search
- Person/Company/Keyword -> Search, Company, Social, Documents
"""

from __future__ import annotations

import json
import os
import re
import threading
import tkinter as tk
import webbrowser
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable
from urllib.parse import quote_plus, urlparse

APP_TITLE = "OSINT Workspace"
APP_SUBTITLE = "Tool By Faiza And Musayyab"
UI_DISCLAIMER = "Use only on assets you own or are authorized to investigate."

DEFAULT_FILES = {
    "tools_cache": "tools_cache.json",
    "favorites": "favorites.json",
    "notes": "notes.json",
    "settings": "settings.json",
    "recent": "recent.json",
}

CATEGORY_TAG_MAP: dict[str, set[str]] = {
    "search": {"Search"},
    "general search": {"Search"},
    "domain": {"Domain/IP", "DNS"},
    "ip": {"Domain/IP", "DNS", "Threat Intel"},
    "dns": {"DNS", "Domain/IP"},
    "social": {"Social"},
    "username": {"Social", "Search"},
    "email": {"Email"},
    "phone": {"Phone"},
    "image": {"Image"},
    "video": {"Video"},
    "geo": {"Maps/Geo"},
    "map": {"Maps/Geo"},
    "company": {"Company"},
    "threat": {"Threat Intel"},
    "archive": {"Archives"},
    "wayback": {"Archives"},
    "code": {"Code"},
    "github": {"Code", "Social"},
    "document": {"Documents"},
    "pdf": {"Documents"},
}

INDICATOR_RELEVANCE: dict[str, set[str]] = {
    "URL": {"Search", "Domain/IP", "DNS", "Threat Intel", "Archives"},
    "Domain": {"Search", "Domain/IP", "DNS", "Threat Intel", "Archives"},
    "IP": {"Domain/IP", "DNS", "Threat Intel"},
    "Email": {"Email", "Search"},
    "Username": {"Social", "Search", "Code"},
    "Phone": {"Phone", "Search"},
    "Hash": {"Threat Intel", "Search"},
    "Company": {"Company", "Search", "Documents"},
    "Person name": {"Search", "Social", "Documents"},
    "Keyword": {"Search", "Documents"},
    "Unknown": {"Search"},
}

QUERY_TEMPLATES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"google", re.I), "https://www.google.com/search?q={q}"),
    (re.compile(r"bing", re.I), "https://www.bing.com/search?q={q}"),
    (re.compile(r"duckduckgo", re.I), "https://duckduckgo.com/?q={q}"),
    (re.compile(r"whois", re.I), "https://who.is/whois/{q}"),
    (re.compile(r"crt\\.sh|certificate", re.I), "https://crt.sh/?q={q}"),
    (re.compile(r"wayback|archive", re.I), "https://web.archive.org/web/*/{q}"),
    (re.compile(r"github", re.I), "https://github.com/search?q={q}"),
    (re.compile(r"virustotal", re.I), "https://www.virustotal.com/gui/search/{q}"),
]


@dataclass
class Tool:
    name: str
    url: str
    description: str
    category: str
    tags: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    is_github: bool = False
    likely_auth: bool = False
    likely_paid: bool = False
    launcher_only: bool = True
    api_possible: bool = False

    @property
    def key(self) -> str:
        return f"{self.name.strip().lower()}::{self.url.strip().lower()}"


class LocalStore:
    def __init__(self, base: Path):
        self.base = base

    def load(self, name: str, default: Any) -> Any:
        path = self.base / DEFAULT_FILES[name]
        if not path.exists():
            return default
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    def save(self, name: str, data: Any) -> None:
        path = self.base / DEFAULT_FILES[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class IndicatorDetector:
    _url = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.I)
    _domain = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9]+)$")
    _email = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    _ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    _ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    _phone = re.compile(r"^\+?[0-9()\-\s]{7,20}$")
    _username = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
    _hash = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")

    @classmethod
    def detect(cls, text: str) -> str:
        s = text.strip()
        if not s:
            return "Unknown"
        if cls._url.match(s):
            return "URL"
        if cls._email.match(s):
            return "Email"
        if cls._ipv4.match(s):
            parts = s.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                return "IP"
        if ":" in s and cls._ipv6.match(s):
            return "IP"
        if cls._domain.match(s):
            return "Domain"
        if cls._phone.match(s) and any(ch.isdigit() for ch in s):
            return "Phone"
        if cls._hash.match(s):
            return "Hash"
        if " " in s:
            return "Person name" if len(s.split()) <= 4 else "Keyword"
        if cls._username.match(s):
            return "Username"
        return "Keyword"


class MarkdownParser:
    header_re = re.compile(r"^##\s+(?:\[[^\]]+\]\([^)]*\)\s*)?(.+?)\s*$")
    bullet_re = re.compile(r"^\*\s+\[([^\]]+)\]\((https?://[^)]+)\)\s*-?\s*(.*)$")

    def __init__(self, log: Callable[[str], None]):
        self.log = log

    def parse(self, path: Path) -> list[Tool]:
        tools: list[Tool] = []
        seen: set[str] = set()
        category = "Uncategorized"
        if not path.exists():
            self.log(f"Markdown file not found: {path}")
            return tools
        for ln, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            hm = self.header_re.match(line)
            if hm:
                category = self._normalize_category(hm.group(1))
                continue
            bm = self.bullet_re.match(line)
            if not bm:
                if line.startswith("*"):
                    self.log(f"Line {ln}: malformed bullet skipped")
                continue
            name, url, desc = bm.groups()
            t = Tool(
                name=name.strip(),
                url=url.strip(),
                description=desc.strip() or "No description.",
                category=category,
            )
            self._enrich(t)
            if t.key in seen:
                continue
            seen.add(t.key)
            tools.append(t)
        self.log(f"Parsed {len(tools)} tools across categories.")
        return tools

    def _normalize_category(self, s: str) -> str:
        s = re.sub(r"\s+", " ", s.replace("#", "").replace("↑", "")).strip()
        return s.title() if s else "Uncategorized"

    def _enrich(self, tool: Tool) -> None:
        txt = f"{tool.category} {tool.name} {tool.description}".lower()
        tags = set()
        for key, mapped in CATEGORY_TAG_MAP.items():
            if key in txt:
                tags.update(mapped)
        if not tags:
            tags.add("Search")
        tool.tags = sorted(tags)

        tool.is_github = "github.com" in tool.url.lower()
        tool.likely_auth = bool(re.search(r"login|account|signup|api key|subscription", txt))
        tool.likely_paid = bool(re.search(r"paid|pricing|premium|pro", txt))
        tool.api_possible = bool(re.search(r"api|developer", txt))
        tool.launcher_only = not tool.api_possible

        input_types = set()
        if any(k in txt for k in ("domain", "dns", "whois")):
            input_types.update({"Domain", "URL"})
        if "ip" in txt:
            input_types.add("IP")
        if "email" in txt:
            input_types.add("Email")
        if any(k in txt for k in ("username", "social", "handle")):
            input_types.add("Username")
        if "phone" in txt:
            input_types.add("Phone")
        if any(k in txt for k in ("hash", "malware", "ioc")):
            input_types.add("Hash")
        if any(k in txt for k in ("company", "business")):
            input_types.add("Company")
        if not input_types:
            input_types.add("Keyword")
        tool.input_types = sorted(input_types)


class APIPluginBase:
    name = "Base"

    def __init__(self, enabled: bool = False, api_key: str = "", timeout: int = 10, rate_limit_per_min: int = 5):
        self.enabled = enabled
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit_per_min = rate_limit_per_min

    def search(self, indicator: str) -> dict[str, Any]:
        if not self.enabled:
            return {"ok": False, "error": f"{self.name} plugin is disabled."}
        return {"ok": False, "error": "Plugin not implemented in safe-placeholder mode."}


class VirusTotalPlugin(APIPluginBase):
    name = "VirusTotal"


class SecurityTrailsPlugin(APIPluginBase):
    name = "SecurityTrails"


class ShodanPlugin(APIPluginBase):
    name = "Shodan"


class CensysPlugin(APIPluginBase):
    name = "Censys"


class OSINTWorkspaceApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x800")
        self.minsize(1024, 680)

        self.base = Path(__file__).resolve().parent
        self.store = LocalStore(self.base)
        self.settings = self._load_settings()

        self.tools: list[Tool] = []
        self.filtered_tools: list[Tool] = []
        self.favorites: set[str] = set(self.store.load("favorites", []))
        self.notes = self.store.load("notes", {"case_title": "", "entries": []})
        self.recent = self.store.load("recent", {"indicators": [], "launches": []})

        self.indicator_var = tk.StringVar()
        self.detected_type_var = tk.StringVar(value="Unknown")
        self.override_type_var = tk.StringVar(value="Auto")
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="All")
        self.status_var = tk.StringVar(value="Ready")

        self._configure_theme()
        self._build_ui()
        self._bind_events()
        self._load_tools_async()

    def _load_settings(self) -> dict[str, Any]:
        default = {
            "theme": "dark",
            "markdown_path": str(self.base / "awesome_osint.md"),
            "db_path": str(self.base),
            "api_integrations_enabled": False,
            "api_keys": {
                "VirusTotal": "",
                "SecurityTrails": "",
                "Shodan": "",
                "Censys": "",
            },
            "plugins": {
                "VirusTotal": False,
                "SecurityTrails": False,
                "Shodan": False,
                "Censys": False,
            },
        }
        cfg = self.store.load("settings", default)
        for k, v in default.items():
            cfg.setdefault(k, v)
        return cfg

    def _configure_theme(self) -> None:
        self.configure(bg="#11161d")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#11161d")
        style.configure("Card.TFrame", background="#1a2230")
        style.configure("TLabel", background="#11161d", foreground="#d7deea")
        style.configure("Card.TLabel", background="#1a2230", foreground="#d7deea")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground="#ffffff")
        style.configure("Sub.TLabel", foreground="#8aa1c1")
        style.configure("TButton", padding=6)

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text=APP_SUBTITLE, style="Sub.TLabel").pack(anchor="w")
        ttk.Label(header, text=UI_DISCLAIMER, foreground="#ffcc66").pack(anchor="w", pady=(6, 0))

        top = ttk.Frame(self, padding=(12, 0, 12, 6))
        top.pack(fill="x")
        ttk.Entry(top, textvariable=self.search_var).pack(side="left", fill="x", expand=True)
        ttk.Label(top, text="Indicator:").pack(side="left", padx=(10, 4))
        ttk.Entry(top, textvariable=self.indicator_var, width=34).pack(side="left")
        ttk.Label(top, text="Detected:").pack(side="left", padx=(8, 4))
        ttk.Label(top, textvariable=self.detected_type_var, foreground="#7ad6a7").pack(side="left")
        ttk.Label(top, text="Override:").pack(side="left", padx=(8, 4))
        ttk.Combobox(top, textvariable=self.override_type_var, width=12, state="readonly", values=[
            "Auto", "URL", "Domain", "IP", "Email", "Username", "Phone", "Hash", "Company", "Person name", "Keyword"
        ]).pack(side="left")

        body = ttk.Frame(self, padding=(12, 6, 12, 6))
        body.pack(fill="both", expand=True)

        sidebar = ttk.Frame(body, style="Card.TFrame", padding=8)
        sidebar.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(sidebar, text="Categories", style="Card.TLabel").pack(anchor="w")
        self.category_list = tk.Listbox(sidebar, height=30, bg="#1a2230", fg="#d7deea", activestyle="none", relief="flat")
        self.category_list.pack(fill="y", expand=True, pady=6)
        self.category_list.insert("end", "All")

        main = ttk.Frame(body)
        main.pack(side="left", fill="both", expand=True)
        self.tabs = ttk.Notebook(main)
        self.tabs.pack(fill="both", expand=True)

        self.dashboard_tab = ttk.Frame(self.tabs)
        self.browser_tab = ttk.Frame(self.tabs)
        self.relevant_tab = ttk.Frame(self.tabs)
        self.launch_tab = ttk.Frame(self.tabs)
        self.notes_tab = ttk.Frame(self.tabs)
        self.fav_tab = ttk.Frame(self.tabs)
        self.settings_tab = ttk.Frame(self.tabs)

        for name, frame in [
            ("Dashboard", self.dashboard_tab),
            ("Tool Browser", self.browser_tab),
            ("Relevant Tools", self.relevant_tab),
            ("Launch Pad", self.launch_tab),
            ("Notes", self.notes_tab),
            ("Favorites", self.fav_tab),
            ("Settings", self.settings_tab),
        ]:
            self.tabs.add(frame, text=name)

        self._build_dashboard()
        self._build_tool_browser(self.browser_tab)
        self._build_tool_browser(self.relevant_tab, relevant=True)
        self._build_launchpad()
        self._build_notes()
        self._build_favorites()
        self._build_settings()

        ttk.Label(self, textvariable=self.status_var, anchor="w", relief="sunken").pack(side="bottom", fill="x")

    def _build_dashboard(self) -> None:
        self.stats_frame = ttk.Frame(self.dashboard_tab, padding=12)
        self.stats_frame.pack(fill="x")
        self.stat_labels: dict[str, ttk.Label] = {}
        for key in ["Total Tools", "Categories", "Favorites", "Relevant", "Recent Launches"]:
            card = ttk.Frame(self.stats_frame, style="Card.TFrame", padding=12)
            card.pack(side="left", padx=6, pady=6, fill="x", expand=True)
            ttk.Label(card, text=key, style="Card.TLabel").pack(anchor="w")
            lbl = ttk.Label(card, text="0", style="Title.TLabel")
            lbl.pack(anchor="w")
            self.stat_labels[key] = lbl

        wf = ttk.Frame(self.dashboard_tab, padding=12)
        wf.pack(fill="x")
        for text, query in [
            ("Domain triage", "example.com"),
            ("Social username pivot", "some_username"),
            ("Email verification research", "analyst@example.com"),
            ("Archive lookup", "https://example.com"),
            ("Image metadata workflow", "image.jpg"),
        ]:
            ttk.Button(wf, text=text, command=lambda q=query: self._set_indicator(q)).pack(side="left", padx=4)

    def _build_tool_browser(self, parent: ttk.Frame, relevant: bool = False) -> None:
        frame = ttk.Frame(parent, padding=8)
        frame.pack(fill="both", expand=True)
        cols = ("Name", "Category", "Tags", "Notes")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=160 if c != "Name" else 240)
        ysb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ysb.set)
        tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")

        btns = ttk.Frame(frame, padding=(8, 0))
        btns.pack(side="left", fill="y")
        ttk.Button(btns, text="Open Home", command=lambda t=tree: self._open_selected(t, False)).pack(fill="x", pady=2)
        ttk.Button(btns, text="Open Search Page", command=lambda t=tree: self._open_selected(t, True)).pack(fill="x", pady=2)
        ttk.Button(btns, text="Copy Query", command=lambda t=tree: self._copy_query(t)).pack(fill="x", pady=2)
        ttk.Button(btns, text="Favorite", command=lambda t=tree: self._favorite_selected(t)).pack(fill="x", pady=2)
        ttk.Button(btns, text="Add Note", command=lambda t=tree: self._note_for_selected(t)).pack(fill="x", pady=2)

        if relevant:
            self.relevant_tree = tree
        else:
            self.tools_tree = tree

    def _build_launchpad(self) -> None:
        self.launch_list = tk.Listbox(self.launch_tab, bg="#161d2a", fg="#d7deea", relief="flat")
        self.launch_list.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_notes(self) -> None:
        top = ttk.Frame(self.notes_tab, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Case Title:").pack(side="left")
        self.case_var = tk.StringVar(value=self.notes.get("case_title", ""))
        ttk.Entry(top, textvariable=self.case_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Save", command=self._save_notes).pack(side="left")
        ttk.Button(top, text="Export TXT", command=lambda: self._export_notes("txt")).pack(side="left", padx=4)
        ttk.Button(top, text="Export JSON", command=lambda: self._export_notes("json")).pack(side="left")

        self.notes_text = tk.Text(self.notes_tab, bg="#161d2a", fg="#d7deea", insertbackground="#fff")
        self.notes_text.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_favorites(self) -> None:
        self.fav_list = tk.Listbox(self.fav_tab, bg="#161d2a", fg="#d7deea", relief="flat")
        self.fav_list.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_settings(self) -> None:
        wrap = ttk.Frame(self.settings_tab, padding=10)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="Markdown file path:").grid(row=0, column=0, sticky="w")
        self.md_var = tk.StringVar(value=self.settings.get("markdown_path", ""))
        ttk.Entry(wrap, textvariable=self.md_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(wrap, text="Browse", command=self._browse_md).grid(row=0, column=2)

        ttk.Label(wrap, text="Local JSON DB path:").grid(row=1, column=0, sticky="w")
        self.db_var = tk.StringVar(value=self.settings.get("db_path", ""))
        ttk.Entry(wrap, textvariable=self.db_var).grid(row=1, column=1, sticky="ew", padx=4)

        self.api_enabled_var = tk.BooleanVar(value=self.settings.get("api_integrations_enabled", False))
        ttk.Checkbutton(wrap, text="Enable optional official API integrations (disabled by default)", variable=self.api_enabled_var).grid(row=2, column=0, columnspan=3, sticky="w", pady=8)

        row = 3
        self.plugin_vars: dict[str, tk.BooleanVar] = {}
        self.key_vars: dict[str, tk.StringVar] = {}
        for plugin in ("VirusTotal", "SecurityTrails", "Shodan", "Censys"):
            pv = tk.BooleanVar(value=self.settings["plugins"].get(plugin, False))
            kv = tk.StringVar(value=self.settings["api_keys"].get(plugin, ""))
            self.plugin_vars[plugin] = pv
            self.key_vars[plugin] = kv
            ttk.Checkbutton(wrap, text=f"Enable {plugin} plugin", variable=pv).grid(row=row, column=0, sticky="w")
            ttk.Entry(wrap, textvariable=kv, show="*").grid(row=row, column=1, sticky="ew", padx=4)
            row += 1

        ttk.Button(wrap, text="Save Settings", command=self._save_settings).grid(row=row, column=0, pady=10, sticky="w")
        ttk.Button(wrap, text="Reload Markdown", command=self._load_tools_async).grid(row=row, column=1, pady=10, sticky="w")
        wrap.columnconfigure(1, weight=1)

    def _bind_events(self) -> None:
        self.search_var.trace_add("write", lambda *_: self.refresh_views())
        self.indicator_var.trace_add("write", lambda *_: self._on_indicator_change())
        self.override_type_var.trace_add("write", lambda *_: self.refresh_views())
        self.category_list.bind("<<ListboxSelect>>", lambda _: self._on_category_select())

    def _load_tools_async(self) -> None:
        self.status_var.set("Parsing markdown...")
        thread = threading.Thread(target=self._parse_tools_worker, daemon=True)
        thread.start()

    def _parse_tools_worker(self) -> None:
        logs: list[str] = []
        parser = MarkdownParser(log=lambda m: logs.append(m))
        tools = parser.parse(Path(self.md_var.get() if hasattr(self, "md_var") else self.settings["markdown_path"]))
        self.after(0, lambda: self._finish_parsing(tools, logs))

    def _finish_parsing(self, tools: list[Tool], logs: list[str]) -> None:
        self.tools = tools
        self.store.save("tools_cache", [asdict(t) for t in tools])
        self._refresh_category_sidebar()
        self.refresh_views()
        for line in logs[-5:]:
            self.status_var.set(line)
        if not logs:
            self.status_var.set("Markdown parsed.")

    def _refresh_category_sidebar(self) -> None:
        self.category_list.delete(0, "end")
        self.category_list.insert("end", "All")
        cats = sorted({t.category for t in self.tools})
        for c in cats:
            self.category_list.insert("end", c)

    def _on_category_select(self) -> None:
        idx = self.category_list.curselection()
        if not idx:
            self.category_var.set("All")
        else:
            self.category_var.set(self.category_list.get(idx[0]))
        self.refresh_views()

    def _on_indicator_change(self) -> None:
        self.detected_type_var.set(IndicatorDetector.detect(self.indicator_var.get()))
        self._remember_indicator(self.indicator_var.get())
        self.refresh_views()

    def _effective_indicator_type(self) -> str:
        ov = self.override_type_var.get()
        return self.detected_type_var.get() if ov == "Auto" else ov

    def _query_url_for_tool(self, tool: Tool, indicator: str) -> tuple[str, str]:
        if not indicator.strip():
            return tool.url, "manual"
        hay = f"{tool.name} {tool.category} {tool.url}".lower()
        for pat, tpl in QUERY_TEMPLATES:
            if pat.search(hay):
                return tpl.format(q=quote_plus(indicator.strip())), "template"
        return tool.url, "manual"

    def filtered(self) -> list[Tool]:
        q = self.search_var.get().strip().lower()
        cat = self.category_var.get()
        result = []
        for t in self.tools:
            if cat != "All" and t.category != cat:
                continue
            hay = f"{t.name} {t.description} {t.category} {' '.join(t.tags)}".lower()
            if q and q not in hay:
                continue
            result.append(t)
        return sorted(result, key=lambda x: (x.category, x.name.lower()))

    def relevant(self, indicator_type: str) -> list[Tool]:
        allowed = INDICATOR_RELEVANCE.get(indicator_type, {"Search"})
        return [t for t in self.filtered() if allowed.intersection(set(t.tags))]

    def refresh_views(self) -> None:
        filtered = self.filtered()
        relevant = self.relevant(self._effective_indicator_type())
        self._fill_tree(self.tools_tree, filtered)
        self._fill_tree(self.relevant_tree, relevant)
        self._fill_favorites()
        self._fill_launches()
        self._refresh_stats(filtered, relevant)

    def _fill_tree(self, tree: ttk.Treeview, items: list[Tool]) -> None:
        for iid in tree.get_children():
            tree.delete(iid)
        for t in items:
            notes = []
            notes.append("api" if t.api_possible else "manual")
            if t.likely_paid:
                notes.append("paid")
            if t.likely_auth:
                notes.append("auth")
            tree.insert("", "end", iid=t.key, values=(t.name, t.category, ", ".join(t.tags), ", ".join(notes)))

    def _refresh_stats(self, filtered: list[Tool], relevant: list[Tool]) -> None:
        self.stat_labels["Total Tools"].configure(text=str(len(self.tools)))
        self.stat_labels["Categories"].configure(text=str(len({t.category for t in self.tools})))
        self.stat_labels["Favorites"].configure(text=str(len(self.favorites)))
        self.stat_labels["Relevant"].configure(text=str(len(relevant)))
        self.stat_labels["Recent Launches"].configure(text=str(len(self.recent.get("launches", []))))

    def _get_tool_by_iid(self, iid: str) -> Tool | None:
        for t in self.tools:
            if t.key == iid:
                return t
        return None

    def _open_selected(self, tree: ttk.Treeview, with_query: bool) -> None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a tool first.")
            return
        tool = self._get_tool_by_iid(sel[0])
        if not tool:
            return
        url = tool.url
        note = "Opened homepage"
        if with_query:
            url, mode = self._query_url_for_tool(tool, self.indicator_var.get())
            note = "Opened search page" if mode == "template" else "Manual input required; opened homepage"
        webbrowser.open_new_tab(url)
        self.status_var.set(note)
        self._remember_launch(tool.name, url)

    def _copy_query(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        tool = self._get_tool_by_iid(sel[0])
        if not tool:
            return
        url, mode = self._query_url_for_tool(tool, self.indicator_var.get())
        self.clipboard_clear()
        self.clipboard_append(url)
        self.status_var.set("Copied query URL" if mode == "template" else "Copied homepage URL (manual input required)")

    def _favorite_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        self.favorites.add(sel[0])
        self.store.save("favorites", sorted(self.favorites))
        self.refresh_views()

    def _note_for_selected(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        tool = self._get_tool_by_iid(sel[0])
        if not tool:
            return
        indicator = self.indicator_var.get().strip()
        entry = {
            "time": datetime.utcnow().isoformat() + "Z",
            "tool": tool.name,
            "indicator": indicator,
            "text": f"Note for {tool.name} / {indicator}",
            "tags": ["tool-note"],
        }
        self.notes.setdefault("entries", []).append(entry)
        self._save_notes()
        self.status_var.set("Note added.")

    def _save_notes(self) -> None:
        self.notes["case_title"] = self.case_var.get().strip()
        text = self.notes_text.get("1.0", "end").strip()
        if text:
            self.notes.setdefault("entries", []).append({
                "time": datetime.utcnow().isoformat() + "Z",
                "tool": "",
                "indicator": self.indicator_var.get().strip(),
                "text": text,
                "tags": ["freeform"],
            })
            self.notes_text.delete("1.0", "end")
        self.store.save("notes", self.notes)

    def _export_notes(self, fmt: str) -> None:
        entries = self.notes.get("entries", [])
        if fmt == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if path:
                Path(path).write_text(json.dumps(self.notes, indent=2), encoding="utf-8")
        else:
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if path:
                lines = [f"Case: {self.notes.get('case_title', '')}"]
                for e in entries:
                    lines.append(f"[{e.get('time')}] {e.get('indicator')} / {e.get('tool')}: {e.get('text')}")
                Path(path).write_text("\n".join(lines), encoding="utf-8")

    def _remember_indicator(self, indicator: str) -> None:
        indicator = indicator.strip()
        if not indicator:
            return
        arr = self.recent.setdefault("indicators", [])
        if indicator in arr:
            arr.remove(indicator)
        arr.insert(0, indicator)
        del arr[25:]
        self.store.save("recent", self.recent)

    def _remember_launch(self, tool: str, url: str) -> None:
        arr = self.recent.setdefault("launches", [])
        arr.insert(0, {"time": datetime.utcnow().isoformat() + "Z", "tool": tool, "url": url})
        del arr[40:]
        self.store.save("recent", self.recent)
        self.refresh_views()

    def _fill_favorites(self) -> None:
        self.fav_list.delete(0, "end")
        for iid in sorted(self.favorites):
            t = self._get_tool_by_iid(iid)
            if t:
                self.fav_list.insert("end", f"{t.name} [{t.category}]")

    def _fill_launches(self) -> None:
        self.launch_list.delete(0, "end")
        for item in self.recent.get("launches", [])[:60]:
            self.launch_list.insert("end", f"{item['time']} | {item['tool']} | {item['url']}")

    def _browse_md(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Markdown", "*.md"), ("All files", "*.*")])
        if path:
            self.md_var.set(path)

    def _save_settings(self) -> None:
        self.settings["markdown_path"] = self.md_var.get().strip()
        self.settings["db_path"] = self.db_var.get().strip() or str(self.base)
        self.settings["api_integrations_enabled"] = bool(self.api_enabled_var.get())
        for p in self.plugin_vars:
            self.settings["plugins"][p] = bool(self.plugin_vars[p].get())
            self.settings["api_keys"][p] = self.key_vars[p].get().strip()
        self.store.save("settings", self.settings)
        self.status_var.set("Settings saved.")

    def _set_indicator(self, indicator: str) -> None:
        self.indicator_var.set(indicator)


def main() -> None:
    app = OSINTWorkspaceApp()
    app.mainloop()


if __name__ == "__main__":
    main()
