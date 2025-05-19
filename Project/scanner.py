import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import requests
import hashlib
import sqlite3
import os
import time
import csv
import webbrowser

# ==== CONFIG ====
VT_API_KEY = 'YOUR_API_KEY_HERE'  # Replace your API Key
if VT_API_KEY == 'YOUR_API_KEY_HERE':
    raise Exception("Replace VT_API_KEY with your actual VirusTotal API Key")
VT_FILE_SCAN_URL = 'https://www.virustotal.com/api/v3/files'
VT_ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses/{}'
VT_REPORT_URL = 'https://www.virustotal.com/gui/file/{}/detection'
DB_PATH = 'database.db'

# ==== DATABASE ====
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    file_name TEXT,
                    sha256 TEXT UNIQUE,
                    date TEXT,
                    malicious INTEGER,
                    total INTEGER,
                    verdict TEXT
                )''')
    conn.commit()
    conn.close()

def save_scan(file_name, sha256, malicious, total, verdict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO scans (file_name, sha256, date, malicious, total, verdict)
                 VALUES (?, ?, datetime("now"), ?, ?, ?)''',
              (file_name, sha256, malicious, total, verdict))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY date DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan_by_sha256(sha256):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT malicious, total, verdict FROM scans WHERE sha256 = ?', (sha256,))
    row = c.fetchone()
    conn.close()
    return row

# ==== VIRUSTOTAL ====
def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def scan_file(filepath):
    headers = {"x-apikey": VT_API_KEY}

    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files)

    if response.status_code != 200:
        raise Exception(f"Upload failed: {response.status_code}, {response.text}")

    analysis_id = response.json()["data"]["id"]

    for _ in range(30):
        time.sleep(2)
        result = requests.get(VT_ANALYSIS_URL.format(analysis_id), headers=headers)
        res_json = result.json()
        status = res_json["data"]["attributes"]["status"]
        if status == "completed":
            stats = res_json["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            verdict = "Malicious" if malicious > 0 else "Clean"
            return malicious, total, verdict
    raise Exception("Timed out waiting for analysis.")

# ==== GUI ====
class MalwareScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Malware Scanner")
        self.root.geometry("750x650")
        self.style = ttk.Style('flatly') 

        frame_top = ttk.Frame(root)
        frame_top.pack(fill='x', pady=10, padx=10)

        self.file_label = ttk.Label(frame_top, text="No file or folder selected.", font=("Segoe UI", 11))
        self.file_label.pack(side='left', padx=5)

        self.select_button = ttk.Button(frame_top, text="Select File", bootstyle=SUCCESS, command=self.select_file)
        self.select_button.pack(side='right', padx=5)
        self.select_folder_button = ttk.Button(frame_top, text="Select Folder", bootstyle=INFO, command=self.select_folder)
        self.select_folder_button.pack(side='right', padx=5)

        frame_control = ttk.Frame(root)
        frame_control.pack(fill='x', pady=5, padx=10)

        self.scan_button = ttk.Button(frame_control, text="Scan", bootstyle=PRIMARY, command=self.scan)
        self.scan_button.pack(side='left', padx=5)

        self.export_button = ttk.Button(frame_control, text="Export to CSV", bootstyle=WARNING, command=self.export_to_csv)
        self.export_button.pack(side='left', padx=5)

        self.history_button = ttk.Button(frame_control, text="View History", bootstyle=SECONDARY, command=self.show_history)
        self.history_button.pack(side='left', padx=5)

        self.progress = ttk.Progressbar(root, length=700, mode='determinate')
        self.progress.pack(pady=10)

        self.result_text = tk.Text(root, height=20, width=90, font=("Consolas", 11))
        self.result_text.pack(padx=10, pady=10)

        self.targets = []

    def select_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.targets = [filepath]
            self.file_label.config(text=f"Selected: {os.path.basename(filepath)}")

    def select_folder(self):
        folderpath = filedialog.askdirectory()
        if folderpath:
            self.targets = []
            for root_dir, _, files in os.walk(folderpath):
                for f in files:
                    full_path = os.path.join(root_dir, f)
                    if os.path.isfile(full_path):
                        self.targets.append(full_path)
            self.file_label.config(text=f"Folder selected: {folderpath} ({len(self.targets)} files)")

    def scan(self):
        if not self.targets:
            messagebox.showwarning("Warning", "Please select a file or folder.")
            return

        self.result_text.delete("1.0", tk.END)
        self.progress["maximum"] = len(self.targets)
        self.progress["value"] = 0
        malware_found = False

        for i, filepath in enumerate(self.targets, 1):
            try:
                sha256 = hash_file(filepath)
                filename = os.path.basename(filepath)
                cached = get_scan_by_sha256(sha256)
                if cached:
                    malicious, total, verdict = cached
                    self.result_text.insert(tk.END, f"[CACHE] {filename} | {verdict} ({malicious}/{total})\n")
                else:
                    self.result_text.insert(tk.END, f"[SCAN] {filename}...\n")
                    self.root.update()
                    malicious, total, verdict = scan_file(filepath)
                    save_scan(filename, sha256, malicious, total, verdict)
                    self.result_text.insert(tk.END, f"        => {verdict} ({malicious}/{total})\n")

                if verdict == "Malicious" and not malware_found:
                    malware_found = True
                    report_url = VT_REPORT_URL.format(sha256)
                    webbrowser.open(report_url)

            except Exception as e:
                self.result_text.insert(tk.END, f"Error with {filepath}: {e}\n")

            self.progress["value"] = i
            self.root.update_idletasks()

        if not malware_found:
            messagebox.showinfo("Scan complete", "Scan finished. No malware detected.")

    def export_to_csv(self):
        scans = get_all_scans()
        if not scans:
            messagebox.showinfo("Export", "No scans to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["File Name", "SHA256", "Date", "Malicious", "Total", "Verdict"])
                for row in scans:
                    writer.writerow(row[1:])
            messagebox.showinfo("Export", f"Exported to {path}")

    def show_history(self):
        history_win = ttk.Toplevel(self.root)
        history_win.title("Scan History")
        history_win.geometry("700x400")

        tree = ttk.Treeview(history_win, columns=("File", "Hash", "Date", "Malicious", "Total", "Verdict"), show='headings')
        for col in tree["columns"]:
            tree.heading(col, text=col)
            tree.column(col, width=100 if col != "Hash" else 250)

        for row in get_all_scans():
            tree.insert("", "end", values=row[1:])

        def on_double_click(event):
            selected = tree.selection()
            if selected:
                values = tree.item(selected[0])['values']
                sha256 = values[1]
                self.show_report_detail(sha256)

        tree.bind("<Double-1>", on_double_click)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

    def show_report_detail(self, sha256):
        report_url = VT_REPORT_URL.format(sha256)
        top = ttk.Toplevel(self.root)
        top.title("VirusTotal Report")
        top.geometry("600x150")
        lbl = ttk.Label(top, text=f"Detailed report for SHA256:", font=("Segoe UI", 12, "bold"))
        lbl.pack(pady=10)
        text = tk.Text(top, height=3, width=80, font=("Segoe UI", 10))
        text.insert(tk.END, report_url)
        text.config(state=tk.DISABLED)
        text.pack(padx=10, pady=5)
        btn = ttk.Button(top, text="Open in Browser", bootstyle=INFO, command=lambda: webbrowser.open(report_url))
        btn.pack(pady=10)

if __name__ == "__main__":
    init_db()
    root = ttk.Window()
    app = MalwareScannerApp(root)
    root.mainloop()
