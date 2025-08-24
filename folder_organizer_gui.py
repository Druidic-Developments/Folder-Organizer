#!/usr/bin/env python3
"""
Folder Organizer — GUI (auto Type for chosen folders; no root container)
- Pick ANY folder via Browse. The app auto-switches to "Type (Extension)" mode
  so files are grouped into folders like PDF, TXT, PNG, NO EXTENSION.
- Optional Old (≥Nd) bucket groups older files under a top-level age folder.
- Preview (dry-run) and Undo supported.
- Only organizes TOP-LEVEL files (no recursion).

Works on Windows 10/11 with Python 3.9+; also runs elsewhere with limited hidden-file detection.
"""

from __future__ import annotations
import os
import re
import sys
import json
import time
import queue
import shutil
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ---------- config ----------
CATEGORY_MAP = {
    "Documents": {".pdf",".doc",".docx",".rtf",".txt",".md",".odt",".tex",".csv",".tsv",".ps",".eps",".epub"},
    "Spreadsheets": {".xls",".xlsx",".xlsm",".ods"},
    "Presentations": {".ppt",".pptx",".key",".odp"},
    "Images": {".png",".jpg",".jpeg",".gif",".bmp",".tiff",".webp",".heic",".svg",".ico"},
    "Video": {".mp4",".mov",".mkv",".avi",".wmv",".webm",".m4v"},
    "Audio": {".mp3",".wav",".flac",".m4a",".aac",".ogg",".wma"},
    "Archives": {".zip",".7z",".rar",".tar",".gz",".bz2",".xz"},
    "Code": {".py",".ipynb",".js",".ts",".tsx",".jsx",".html",".css",".json",".yml",".yaml",".xml",".c",".cpp",".h",".hpp",".rs",".go",".rb",".php",".cs",".java",".kt",".swift",".sh",".ps1",".bat",".cmd",".ini",".cfg",".toml"},
    "Installers": {".msi",".msix",".msixbundle",".exe"},
    "Shortcuts": {".lnk",".url"},
    "Design": {".fig",".sketch",".xd",".ai",".psd",".indd"},
    "Fonts": {".ttf",".otf",".woff",".woff2"},
    "Torrents": {".torrent"},
}
DEFAULT_BUCKET = "Misc"

# Undo log (stored directly in the chosen folder)
UNDO_LOG_BASENAME = "_organizer_last_run.jsonl"

# Windows attribute flags (best-effort; works cross-platform)
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

# Modes
MODE_CATEGORY = "category"
MODE_TYPE = "type"
# ---------------------------


def is_hidden_or_system(p: Path) -> bool:
    """Best-effort hidden/system detection (Windows + dotfile fallback)."""
    try:
        st = os.stat(p, follow_symlinks=False)
        attr = getattr(st, "st_file_attributes", 0)
        if attr:
            return bool(attr & FILE_ATTRIBUTE_HIDDEN) or bool(attr & FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        pass
    return p.name.startswith(".")


def classify(file: Path, mode: str) -> str:
    """
    Return the primary grouping label based on mode:
      - MODE_CATEGORY: a category like "Documents", "Images", ...
      - MODE_TYPE: an extension label like "PDF", "TXT", "PNG", "NO EXTENSION"
    """
    ext = file.suffix.lower()
    if mode == MODE_TYPE:
        return ext[1:].upper() if ext else "NO EXTENSION"

    # MODE_CATEGORY (default)
    for category, exts in CATEGORY_MAP.items():
        if ext in exts:
            if category == "Installers" and ext == ".exe":
                return "Apps"  # special case: .exe often shortcuts/launchers
            return category
    return DEFAULT_BUCKET


def unique_path(base: Path) -> Path:
    """Return a non-colliding path by appending ' (n)' before suffix."""
    if not base.exists():
        return base
    stem, suffix = base.stem, base.suffix
    core = stem
    m = re.match(r"^(.*) \((\d+)\)$", stem)
    n = int(m.group(2)) + 1 if m else 1
    if m:
        core = m.group(1)
    while True:
        candidate = base.with_name(f"{core} ({n}){suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def plan_moves(root: Path, age_days: int | None, mode: str) -> list[tuple[Path, Path]]:
    """
    Plan moves for TOP-LEVEL files only.
    - In Category mode, target folder = "<Category>"
    - In Type mode, target folder = "<EXT>" (e.g., PDF, TXT), or "NO EXTENSION"
    - If age_days is set and file is older, target becomes:
        "Old (≥Nd)/<Category or EXT>"
    """
    moves: list[tuple[Path, Path]] = []
    cutoff = None
    if age_days and age_days > 0:
        cutoff = time.time() - (age_days * 24 * 3600)

    for item in root.iterdir():
        if item.is_dir():
            continue
        if not item.is_file():
            continue
        if is_hidden_or_system(item):
            continue
        if item.name == UNDO_LOG_BASENAME:
            continue

        label = classify(item, mode)  # <Category> or <EXT>/NO EXTENSION
        top = label
        sub = ""  # default: no subfolder

        # Age bucket handling
        if cutoff:
            try:
                atime = item.stat().st_atime
                is_old = atime < cutoff
            except Exception:
                is_old = False
            if is_old:
                top = f"Old (≥{age_days}d)"
                sub = label  # nest grouping under age

        dest_dir = root / top
        if sub:
            dest_dir = dest_dir / sub
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = unique_path(dest_dir / item.name)
        if dest_path.resolve() != item.resolve():
            moves.append((item, dest_path))

    return moves


def write_log(root: Path, moves: list[tuple[Path, Path]]) -> Path:
    log_path = root / UNDO_LOG_BASENAME
    with log_path.open("w", encoding="utf-8") as f:
        for src, dst in moves:
            f.write(json.dumps({"src": str(src), "dst": str(dst)}) + "\n")
    return log_path


def load_latest_log(root: Path) -> list[dict]:
    log_path = root / UNDO_LOG_BASENAME
    if not log_path.exists():
        return []
    entries = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return list(reversed(entries))


def perform_moves(moves: list[tuple[Path, Path]], simulate: bool, log_cb) -> None:
    for src, dst in moves:
        if simulate:
            log_cb(f"[DRY] {src.name}  →  {dst.parent.name}/")
        else:
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dst))
                log_cb(f"Moved: {src.name}  →  {dst.parent.name}/")
            except Exception as e:
                log_cb(f"FAILED to move {src} -> {dst}: {e}")


def undo_last(root: Path, log_cb) -> None:
    entries = load_latest_log(root)
    if not entries:
        log_cb("No previous run log found in this folder.")
        return

    log_cb(f"Undoing last run in: {root}  ({len(entries)} items)")
    restored = 0
    for rec in entries:
        moved_to = Path(rec["dst"])
        original = Path(rec["src"])
        if not moved_to.exists():
            log_cb(f"[Skip] Missing: {moved_to}")
            continue
        target = original if not original.exists() else unique_path(original)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(moved_to), str(target))
            restored += 1
            log_cb(f"Restored: {target.name}")
        except Exception as e:
            log_cb(f"FAILED to restore {moved_to} -> {target}: {e}")

    log_cb(f"Undo complete. Restored {restored} item(s).")


# ---------------- GUI ----------------
class OrganizerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder Organizer (Auto Type for chosen folders)")
        self.geometry("900x560")
        self.minsize(720, 440)

        # State
        self.selected_path = tk.StringVar(value="")
        self.age_days = tk.IntVar(value=0)             # 0 = off
        self.mode = tk.StringVar(value=MODE_CATEGORY)  # category | type (auto-set on browse)
        self.busy = False
        self.queue = queue.Queue()

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        # Path row
        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Folder:").pack(side="left")
        self.path_entry = ttk.Entry(top, textvariable=self.selected_path)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
        ttk.Button(top, text="Browse…", command=self.on_browse).pack(side="left")

        # Options row: Mode (still changeable) + Age
        opts = ttk.Frame(self)
        opts.pack(fill="x", **pad)

        mode_box = ttk.LabelFrame(opts, text="Organize by")
        mode_box.pack(side="left", padx=(0, 18))
        ttk.Radiobutton(mode_box, text="Category", value=MODE_CATEGORY, variable=self.mode).pack(side="left", padx=8)
        ttk.Radiobutton(mode_box, text="Type (Extension)", value=MODE_TYPE, variable=self.mode).pack(side="left", padx=8)

        age_box = ttk.Frame(opts)
        age_box.pack(side="left")
        ttk.Label(age_box, text="Old (≥Nd):").pack(side="left")
        self.age_spin = ttk.Spinbox(age_box, from_=0, to=3650, width=6, textvariable=self.age_days)
        self.age_spin.pack(side="left", padx=(6, 8))
        ttk.Label(age_box, text="(0 disables age bucket)").pack(side="left")

        # Buttons
        btns = ttk.Frame(self)
        btns.pack(fill="x", **pad)

        self.btn_preview = ttk.Button(btns, text="Preview", command=self.on_preview)
        self.btn_preview.pack(side="left")

        self.btn_organize = ttk.Button(btns, text="Organize", command=self.on_organize)
        self.btn_organize.pack(side="left", padx=(8, 0))

        self.btn_undo = ttk.Button(btns, text="Undo", command=self.on_undo)
        self.btn_undo.pack(side="left", padx=(8, 0))

        self.btn_open = ttk.Button(btns, text="Open Folder", command=self.on_open_folder)
        self.btn_open.pack(side="left", padx=(8, 0))

        # Output
        self.output = ScrolledText(self, wrap="word", height=18, font=("Consolas", 10))
        self.output.pack(fill="both", expand=True, **pad)

        self.status = ttk.Label(self, text="Ready", anchor="w")
        self.status.pack(fill="x", side="bottom")

        # Enter-to-click convenience
        for child in top.winfo_children() + opts.winfo_children() + btns.winfo_children():
            child.bind("<Return>", lambda e: e.widget.invoke() if isinstance(e.widget, ttk.Button) else None)

    # Helpers
    def log(self, msg: str):
        self.output.insert("end", msg + "\n")
        self.output.see("end")
        self.update_idletasks()

    def set_status(self, msg: str):
        self.status.config(text=msg)
        self.update_idletasks()

    def get_root_path(self) -> Path | None:
        raw = self.selected_path.get().strip()
        if not raw:
            messagebox.showinfo("Pick a folder", "Please choose a folder to organize.")
            return None
        p = Path(raw).expanduser()
        if not p.exists() or not p.is_dir():
            messagebox.showerror("Invalid folder", f"Not a valid folder:\n{p}")
            return None
        return p

    def lock_ui(self, locked: bool):
        self.busy = locked
        state = "disabled" if locked else "normal"
        for b in (self.btn_preview, self.btn_organize, self.btn_undo, self.btn_open):
            b.config(state=state)
        self.path_entry.config(state=state)
        self.age_spin.config(state=state)
        self.set_status("Working…" if locked else "Ready")

    def enqueue(self, fn, *args, **kwargs):
        """Run fn in a worker thread and stream logs to the UI safely."""
        def runner():
            try:
                fn(*args, **kwargs)
            except Exception as e:
                self.queue.put(("log", f"ERROR: {e}"))
            finally:
                self.queue.put(("done", None))
        threading.Thread(target=runner, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "status":
                    self.set_status(payload)
                elif kind == "done":
                    self.lock_ui(False)
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    # Queue-safe logging callback
    def qlog(self, msg: str):
        self.queue.put(("log", msg))

    # Button handlers
    def on_browse(self):
        path = filedialog.askdirectory(title="Select a folder to organize")
        if path:
            self.selected_path.set(path)
            # NEW: auto-switch to Type when a folder is chosen (e.g., Documents)
            self.mode.set(MODE_TYPE)
            self.log("Mode auto-switched to Type (Extension) for folder-based organizing.")

    def on_open_folder(self):
        p = self.get_root_path()
        if not p: return
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(p))
            elif sys.platform == "darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception as e:
            messagebox.showerror("Open Folder", f"Could not open folder:\n{e}")

    def on_preview(self):
        if self.busy: return
        p = self.get_root_path()
        if not p: return
        age = self.age_days.get() or 0
        mode = self.mode.get()
        self.output.delete("1.0", "end")
        self.lock_ui(True)

        def work():
            self.qlog(f"Preview for: {p}")
            self.qlog(f"Mode: {'Type (Extension)' if mode==MODE_TYPE else 'Category'}")
            self.qlog(f"Age bucket: {'off' if age <= 0 else f'Old (≥{age}d)'}")
            moves = plan_moves(p, age if age > 0 else None, mode)
            if not moves:
                self.qlog("Nothing to organize. This folder already looks tidy!")
                return
            self.qlog(f"Planning to organize {len(moves)} item(s):\n")
            perform_moves(moves, simulate=True, log_cb=self.qlog)

        self.enqueue(work)

    def on_organize(self):
        if self.busy: return
        p = self.get_root_path()
        if not p: return
        age = self.age_days.get() or 0
        mode = self.mode.get()
        self.output.delete("1.0", "end")
        self.lock_ui(True)

        def work():
            self.qlog(f"Organizing in: {p}")
            self.qlog(f"Mode: {'Type (Extension)' if mode==MODE_TYPE else 'Category'}")
            moves = plan_moves(p, age if age > 0 else None, mode)
            if not moves:
                self.qlog("Nothing to organize. This folder already looks tidy!")
                return
            perform_moves(moves, simulate=False, log_cb=self.qlog)
            log_path = write_log(p, moves)
            self.qlog(f"\nDone. Undo log saved to: {log_path}")
            self.qlog("Tip: Click ‘Undo’ to revert the last run.")

        self.enqueue(work)

    def on_undo(self):
        if self.busy: return
        p = self.get_root_path()
        if not p: return
        self.output.delete("1.0", "end")
        self.lock_ui(True)

        def work():
            undo_last(p, log_cb=self.qlog)

        self.enqueue(work)


def main():
    app = OrganizerApp()
    # Prefill with Desktop if it exists (you can Browse to Documents, Downloads, etc.)
    desktop = Path.home() / "Desktop"
    if desktop.exists():
        app.selected_path.set(str(desktop))
    app.mainloop()


if __name__ == "__main__":
    main()
