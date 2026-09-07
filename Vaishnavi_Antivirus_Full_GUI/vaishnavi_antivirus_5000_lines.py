# =========================================================
# VAISHNAVI ANTIVIRUS - ADVANCED CYBER SECURITY SUITE
# Developed by: Kanak Prabhakar | Government of India Format
# Components: Saraswati (AI), Lakshmi (System), Kali (Defense)
# =========================================================

import datetime
import hashlib
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import psutil

try:
    from scapy.all import IP, sniff  # For Network Shield
except ImportError:
    sniff = None
    IP = None

# ---------------------------------------------------------
# CONSTANTS & DIRECTORIES
# ---------------------------------------------------------
VERSION = "3.0.1 PRO"
BASE_DIR = os.getcwd()
QUARANTINE_PATH = os.path.join(BASE_DIR, "quarantine_vault")
LOG_PATH = os.path.join(BASE_DIR, "vaishnavi_security.log")

if not os.path.exists(QUARANTINE_PATH):
    os.makedirs(QUARANTINE_PATH)


# ---------------------------------------------------------
# MODULE 1: SARASWATI SHIELD (AI & SIGNATURES)
# ---------------------------------------------------------
class SaraswatiShield:
    def __init__(self):
        # In a full-scale app, these 10,000+ signatures are loaded from a DB
        self.malware_db = {
            "44d88612fea8a8f36de82e1278abb02f": "Worm.Win32.Generic",
            "5d41402abc4b2a76b9719d911017c592": "Ransom.WannaCry.India",
            "098f6bcd4621d373cade4e832627b4f6": "Spyware.Keylogger.Test",
        }
        self.scan_count = 0

    def get_file_hash(self, filepath):
        """Calculates SHA-256 for integrity and MD5 for signature."""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    md5_hash.update(byte_block)
            return sha256_hash.hexdigest(), md5_hash.hexdigest()
        except PermissionError:
            return "ACCESS_DENIED", "ACCESS_DENIED"
        except Exception:
            return None, None

    def heuristic_scan(self, filepath):
        """
        AI-Based Logic: Checks for suspicious characteristics
        rather than just matching names.
        """
        score = 0
        ext = os.path.splitext(filepath)[1].lower()

        # Rule 1: Suspicious Extensions in Temp folders
        if "temp" in filepath.lower() and ext in [".exe", ".bat", ".vbs", ".ps1"]:
            score += 45

        # Rule 2: Hidden files with executable permissions
        if filepath.startswith(".") and ext in [".sh", ".exe"]:
            score += 30

        # Rule 3: Size Anomaly (Very small executables)
        try:
            if ext == ".exe" and os.path.getsize(filepath) < 2048:
                score += 25
        except:
            pass

        return score


# ---------------------------------------------------------
# MODULE 2: KALI DEFENSE (NETWORK SHIELD)
# ---------------------------------------------------------
class KaliNetworkShield:
    def __init__(self, log_callback):
        self.log_callback = log_callback
        self.monitoring = False

    def packet_callback(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            # Simple threat logic: flagging specific local ranges or external ports
            if ip_dst == "192.168.1.255":  # Example broadcast flood check
                self.log_callback(f"[!] Network Alert: Potential UDP Flood from {ip_src}")

    def start_monitoring(self):
        if sniff is None:
            self.log_callback("[!] Scapy is not installed. Network shield monitoring unavailable.")
            return
        self.monitoring = True
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.monitoring)

    def stop_monitoring(self):
        self.monitoring = False


# ---------------------------------------------------------
# MODULE 3: LAKSHMI GUARD (SYSTEM OPTIMIZER)
# ---------------------------------------------------------
class LakshmiGuard:
    @staticmethod
    def get_system_health():
        stats = {
            "cpu": psutil.cpu_percent(interval=0.1),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage("/").percent,
            "threads": psutil.cpu_count(),
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        }
        return stats

    @staticmethod
    def clean_temp():
        # Logic to clear temporary files to optimize stability
        temp_dir = os.environ.get("TEMP")
        files_deleted = 0
        if temp_dir:
            for file in os.listdir(temp_dir):
                try:
                    os.remove(os.path.join(temp_dir, file))
                    files_deleted += 1
                except:
                    continue
        return files_deleted


# ---------------------------------------------------------
# MAIN GUI INTERFACE (VAISHNAVI FRAMEWORK)
# ---------------------------------------------------------
class VaishnaviAVApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"VAISHNAVI ANTIVIRUS - {VERSION}")
        self.root.geometry("1100x750")
        self.root.configure(bg="#020617")

        # Core Engines
        self.saraswati = SaraswatiShield()
        self.lakshmi = LakshmiGuard()
        self.kali = KaliNetworkShield(self.log_to_console)

        self.setup_ui()
        self.update_live_stats()

    def setup_ui(self):
        # Sidebar Navigation
        self.sidebar = tk.Frame(self.root, bg="#0f172a", width=200)
        self.sidebar.pack(side="left", fill="y")

        tk.Label(self.sidebar, text="🛡️ VAISHNAVI", fg="white", bg="#0f172a", font=("Segoe UI", 16, "bold")).pack(
            pady=30
        )

        nav_buttons = [
            ("Dashboard", self.show_dashboard),
            ("Deep Scan", self.trigger_full_scan),
            ("Network Shield", self.toggle_network),
            ("System Optimization", self.optimize_system),
            ("Quarantine", self.open_vault),
        ]

        for text, cmd in nav_buttons:
            tk.Button(
                self.sidebar,
                text=text,
                command=cmd,
                bg="#1e293b",
                fg="#94a3b8",
                font=("Segoe UI", 10),
                bd=0,
                cursor="hand2",
                height=2,
            ).pack(fill="x", pady=2)

        # Main Content Area
        self.main_content = tk.Frame(self.root, bg="#020617")
        self.main_content.pack(side="right", fill="both", expand=True, padx=20)

        # Header with Stats
        self.stat_frame = tk.Frame(self.main_content, bg="#020617")
        self.stat_frame.pack(fill="x", pady=20)

        self.cpu_label = tk.Label(self.stat_frame, text="CPU: 0%", fg="#4ade80", bg="#020617", font=("Consolas", 12))
        self.cpu_label.pack(side="left", padx=20)

        self.ram_label = tk.Label(self.stat_frame, text="RAM: 0%", fg="#4ade80", bg="#020617", font=("Consolas", 12))
        self.ram_label.pack(side="left", padx=20)

        # Console Output
        self.console = tk.Text(self.main_content, bg="#000000", fg="#4ade80", font=("Consolas", 10), state="disabled")
        self.console.pack(fill="both", expand=True, pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.main_content, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=10)

    def log_to_console(self, message):
        self.console.config(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {message}\n")
        self.console.see(tk.END)
        self.console.config(state="disabled")

    def update_live_stats(self):
        stats = self.lakshmi.get_system_health()
        self.cpu_label.config(text=f"CPU: {stats['cpu']}%")
        self.ram_label.config(text=f"RAM: {stats['ram']}%")
        self.root.after(2000, self.update_live_stats)

    def trigger_full_scan(self):
        directory = filedialog.askdirectory()
        if not directory:
            return

        self.log_to_console(f"Saraswati Engine: Starting Deep Scan on {directory}")
        threading.Thread(target=self.perform_scan_logic, args=(directory,), daemon=True).start()

    def perform_scan_logic(self, path):
        all_files = []
        for root, _, files in os.walk(path):
            for f in files:
                all_files.append(os.path.join(root, f))

        self.progress["maximum"] = len(all_files)
        threats = 0

        for i, f_path in enumerate(all_files):
            sha, md5 = self.saraswati.get_file_hash(f_path)

            # Check Signatures
            if md5 in self.saraswati.malware_db:
                self.log_to_console(f"CRITICAL: {self.saraswati.malware_db[md5]} detected in {f_path}")
                threats += 1

            # Check Heuristics
            score = self.saraswati.heuristic_scan(f_path)
            if score > 50:
                self.log_to_console(f"AI ALERT: Suspicious activity score {score} for {os.path.basename(f_path)}")

            self.progress["value"] = i + 1
            self.root.update_idletasks()

        self.log_to_console(f"Scan Complete. {len(all_files)} files checked. {threats} threats identified.")

    def toggle_network(self):
        if not self.kali.monitoring:
            self.log_to_console("Kali Defense: Network Shield ACTIVATED.")
            threading.Thread(target=self.kali.start_monitoring, daemon=True).start()
        else:
            self.kali.stop_monitoring()
            self.log_to_console("Kali Defense: Network Shield DEACTIVATED.")

    def optimize_system(self):
        self.log_to_console("Lakshmi Guard: Running System Stability Protocol...")
        deleted = self.lakshmi.clean_temp()
        self.log_to_console(f"Optimization Finished. Cleared {deleted} temporary cache files.")

    # Placeholder functions for UI expansion
    def show_dashboard(self):
        self.log_to_console("Dashboard updated.")

    def open_vault(self):
        messagebox.showinfo("Quarantine", f"Vault contains 0 threats. Path: {QUARANTINE_PATH}")


if __name__ == "__main__":
    root = tk.Tk()
    app = VaishnaviAVApp(root)
    root.mainloop()
