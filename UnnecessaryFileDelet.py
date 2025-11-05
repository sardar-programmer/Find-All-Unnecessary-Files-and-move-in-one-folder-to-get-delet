# scan_and_quarantine.py
# Usage: run in Termux or Pydroid3 (with storage permission)
# Warning: This WILL MOVE files to quarantine directory. It will NOT delete installed apps or system files.

import os
import shutil
import hashlib
from datetime import datetime

# Directories to scan (common user storage locations)
SCAN_DIRS = [
    "/storage/emulated/0/Download",
    "/storage/emulated/0/Downloads",
    "/storage/emulated/0/Android/data",
    "/storage/emulated/0/Movies",
    "/storage/emulated/0/DCIM",
    "/storage/emulated/0/Pictures",
    "/storage/emulated/0/",
]

# Quarantine folder (create if not exists)
QUARANTINE = "/storage/emulated/0/quarantine_for_review"
os.makedirs(QUARANTINE, exist_ok=True)

# Simple heuristics for "suspicious" filename/extensions
SUSPICIOUS_EXTS = {".apk", ".exe", ".scr", ".bat", ".jar"}   # .apk is most relevant for Android
SUSPICIOUS_KEYWORDS = ["update", "service", "sys", "androidsystem", "flash", "installer", "temp", "hidden"]

def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                h.update(block)
        return h.hexdigest()
    except Exception:
        return None

def is_suspicious(file_path):
    name = os.path.basename(file_path).lower()
    _, ext = os.path.splitext(name)
    # 1) Suspicious extension
    if ext in SUSPICIOUS_EXTS:
        return True
    # 2) Strange keywords in filename
    for k in SUSPICIOUS_KEYWORDS:
        if k in name:
            return True
    # 3) Very large hidden files (optional heuristic)
    try:
        size = os.path.getsize(file_path)
        if size > 200 * 1024 * 1024 and name.startswith("."):  # >200MB and hidden
            return True
    except Exception:
        pass
    return False

def safe_move(src, dst_folder):
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.basename(src)
        dst = os.path.join(dst_folder, f"{ts}__{base}")
        shutil.move(src, dst)
        return dst
    except Exception as e:
        return None

def scan_and_quarantine():
    found = []
    for root in SCAN_DIRS:
        if not os.path.exists(root):
            continue
        # Walk but avoid system-level protected dirs
        for dirpath, dirnames, filenames in os.walk(root):
            # safety: skip obvious system dirs to avoid damage
            if "/system/" in dirpath or "/data/" in dirpath and "data" in dirpath and not "/storage/emulated/0" in dirpath:
                continue
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    if is_suspicious(fpath):
                        h = sha256_of_file(fpath)
                        dst = safe_move(fpath, QUARANTINE)
                        found.append((fpath, dst, h))
                        print(f"[QUARANTINED] {fpath} -> {dst}  sha256={h}")
                except Exception as e:
                    # ignore permission errors, continue scanning
                    print(f"[SKIP] {fpath}  ({e})")
    return found

if __name__ == "__main__":
    print("Starting scan... Quarantine:", QUARANTINE)
    items = scan_and_quarantine()
    print(f"Scan complete. {len(items)} files moved to quarantine.")
    print("Important: Manually review quarantined files before permanent deletion.")