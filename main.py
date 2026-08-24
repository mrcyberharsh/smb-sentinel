"""
SMB Sentinel - MR CYBER
A friendly SMB misconfiguration scanner for your local network.

Free tier: small-range scan, SMBv1 + signing checks, color-coded results.
Premium tier (manual unlock): unlimited range, CVE matching, deep null-session
check, PDF/CSV export, scan history trends.
"""

import threading
import customtkinter as ctk
from tkinter import ttk, messagebox
import webbrowser

import scanner
import license_manager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

NEON_GREEN = "#00ff41"
NEON_CYAN = "#00ffcc"
DARK_BG = "#0d1117"
CARD_BG = "#161b22"

RISK_COLORS = {
    "high": "#ff4444",
    "medium": "#ffcc00",
    "low": "#66ccff",
    "safe": "#00ff41",
    "unknown": "#888888",
}

FREE_MAX_HOSTS = 14  # /28
PREMIUM_CONTACT_EMAIL = "cyber.h4rsh@zohomail.in"


class SMBSentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SMB Sentinel — MR CYBER")
        self.geometry("980x680")
        self.minsize(820, 560)
        self.configure(fg_color=DARK_BG)

        self.is_premium = license_manager.is_premium()
        self.scan_results = {}
        self.device_nicknames = {}

        self._build_header()
        self._build_controls()
        self._build_progress()
        self._build_results_table()
        self._build_footer()

        self.after(300, self._maybe_show_onboarding)

    # ------------------------------------------------------------------
    # UI sections
    # ------------------------------------------------------------------

    def _build_header(self):
        # White banner, black "MR CYBER" text, as requested
        header = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=0, height=64)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=20, pady=8)

        ctk.CTkLabel(
            left, text="MR CYBER", text_color="#000000",
            font=ctk.CTkFont(family="Arial", size=22, weight="bold")
        ).pack(side="left")

        ctk.CTkLabel(
            left, text="  |  SMB Sentinel", text_color="#333333",
            font=ctk.CTkFont(family="Arial", size=16)
        ).pack(side="left")

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=20)

        badge_text = "★ PREMIUM" if self.is_premium else "FREE VERSION"
        badge_color = "#00994d" if self.is_premium else "#888888"
        self.badge_label = ctk.CTkLabel(
            right, text=badge_text, text_color="#ffffff", fg_color=badge_color,
            corner_radius=6, padx=10, pady=4, font=ctk.CTkFont(size=12, weight="bold")
        )
        self.badge_label.pack(side="right")

    def _build_controls(self):
        frame = ctk.CTkFrame(self, fg_color=CARD_BG, corner_radius=10)
        frame.pack(fill="x", padx=16, pady=(16, 8))

        row1 = ctk.CTkFrame(frame, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=(14, 6))

        ctk.CTkLabel(row1, text="Network range (CIDR):", text_color="white").pack(side="left")
        self.range_entry = ctk.CTkEntry(row1, width=220, placeholder_text="e.g. 192.168.1.0/28")
        self.range_entry.pack(side="left", padx=10)

        ctk.CTkButton(
            row1, text="Auto-Detect My Network", command=self._auto_detect,
            fg_color="#333333", hover_color="#444444"
        ).pack(side="left", padx=6)

        self.scan_btn = ctk.CTkButton(
            row1, text="▶ Scan Network", command=self._start_scan,
            fg_color=NEON_GREEN, text_color="black", hover_color="#00cc33",
            font=ctk.CTkFont(weight="bold")
        )
        self.scan_btn.pack(side="right")

        row2 = ctk.CTkFrame(frame, fg_color="transparent")
        row2.pack(fill="x", padx=14, pady=(0, 12))
        limit_note = f"Free version scans up to {FREE_MAX_HOSTS} devices per scan."
        if self.is_premium:
            limit_note = "Premium: unlimited range scanning enabled."
        self.limit_label = ctk.CTkLabel(row2, text=limit_note, text_color="#999999", font=ctk.CTkFont(size=11))
        self.limit_label.pack(side="left")

    def _build_progress(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=16, pady=(0, 8))
        self.progress_bar = ctk.CTkProgressBar(frame, progress_color=NEON_GREEN)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", side="left", expand=True, padx=(0, 10))
        self.status_label = ctk.CTkLabel(frame, text="Idle", text_color="#999999", width=220, anchor="w")
        self.status_label.pack(side="left")

    def _build_results_table(self):
        container = ctk.CTkFrame(self, fg_color=CARD_BG, corner_radius=10)
        container.pack(fill="both", expand=True, padx=16, pady=8)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#0d1117", fieldbackground="#0d1117",
                         foreground="white", rowheight=28, font=("Arial", 10))
        style.configure("Treeview.Heading", background="#21262d", foreground="white",
                         font=("Arial", 10, "bold"))
        style.map("Treeview", background=[("selected", "#264f78")])

        columns = ("nickname", "ip", "risk", "findings")
        self.tree = ttk.Treeview(container, columns=columns, show="headings", height=14)
        self.tree.heading("nickname", text="Device Name")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("findings", text="Findings")
        self.tree.column("nickname", width=140)
        self.tree.column("ip", width=120)
        self.tree.column("risk", width=90, anchor="center")
        self.tree.column("findings", width=480)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree.bind("<Double-1>", self._on_row_double_click)

        for level, color in RISK_COLORS.items():
            self.tree.tag_configure(level, foreground=color)

    def _build_footer(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=16, pady=(0, 14))

        premium_features = [
            ("🔒 CVE Match & Severity", self._premium_gate),
            ("🔒 Export PDF / CSV Report", self._premium_gate),
            ("🔒 Deep Null-Session Check", self._premium_gate),
            ("🔒 Scan History / Trends", self._premium_gate),
        ]
        for label, cmd in premium_features:
            active = self.is_premium
            btn = ctk.CTkButton(
                frame, text=label.replace("🔒 ", "") if active else label,
                command=cmd, fg_color=(NEON_CYAN if active else "#2a2a2a"),
                text_color=("black" if active else "#888888"),
                hover_color="#1a1a1a", font=ctk.CTkFont(size=11)
            )
            btn.pack(side="left", padx=(0, 8), pady=4)

        ctk.CTkButton(
            frame, text="⚙ Settings / License Key", command=self._open_settings,
            fg_color="transparent", border_width=1, border_color="#555555",
            text_color="#cccccc"
        ).pack(side="right")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _auto_detect(self):
        nets = scanner.get_local_networks()
        if not nets:
            messagebox.showwarning("Auto-Detect", "Could not detect a network automatically. Please enter it manually.")
            return
        self.range_entry.delete(0, "end")
        self.range_entry.insert(0, nets[0])

    def _start_scan(self):
        cidr = self.range_entry.get().strip()
        if not cidr:
            messagebox.showwarning("Missing range", "Enter a network range or click Auto-Detect first.")
            return
        try:
            limit = None if self.is_premium else FREE_MAX_HOSTS
            ip_list = scanner.ips_in_cidr(cidr, limit=limit)
        except ValueError:
            messagebox.showerror("Invalid range", "That doesn't look like a valid CIDR, e.g. 192.168.1.0/28")
            return

        if not self.is_premium and len(ip_list) >= FREE_MAX_HOSTS:
            messagebox.showinfo(
                "Free version limit",
                f"Scanning the first {FREE_MAX_HOSTS} devices in this range. "
                "Upgrade to Premium for unlimited range scanning."
            )

        self.tree.delete(*self.tree.get_children())
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.progress_bar.set(0)
        self.status_label.configure(text=f"Starting scan of {len(ip_list)} hosts...")

        thread = threading.Thread(target=self._run_scan_thread, args=(ip_list,), daemon=True)
        thread.start()

    def _run_scan_thread(self, ip_list):
        def progress_cb(done, total, current_ip):
            pct = done / total if total else 0
            self.after(0, lambda: self.progress_bar.set(pct))
            self.after(0, lambda: self.status_label.configure(text=f"Scanning {current_ip}... ({done}/{total})"))

        results = scanner.scan_range(ip_list, progress_callback=progress_cb)
        self.scan_results = results
        self.after(0, self._display_results)

    def _display_results(self):
        self.scan_btn.configure(state="normal", text="▶ Scan Network")
        self.status_label.configure(text=f"Scan complete — {len(self.scan_results)} hosts checked.")

        for ip, data in self.scan_results.items():
            risk = data.get("risk_level", "unknown")
            findings = "; ".join(data.get("findings", []))
            nickname = self.device_nicknames.get(ip, "(double-click to name)")
            self.tree.insert("", "end", iid=ip, values=(nickname, ip, risk.upper(), findings), tags=(risk,))

    def _on_row_double_click(self, event):
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not item or col != "#1":
            return
        current = self.device_nicknames.get(item, "")
        new_name = ctk.CTkInputDialog(text=f"Nickname for {item}:", title="Rename Device").get_input()
        if new_name:
            self.device_nicknames[item] = new_name
            vals = list(self.tree.item(item, "values"))
            vals[0] = new_name
            self.tree.item(item, values=vals)

    def _premium_gate(self):
        if self.is_premium:
            messagebox.showinfo("Premium", "This feature is active. (Full implementation ships in the next build.)")
            return
        answer = messagebox.askyesno(
            "Premium Feature",
            "This is a Premium feature.\n\n"
            f"To unlock it, contact {PREMIUM_CONTACT_EMAIL} for manual activation.\n\n"
            "Open email now?"
        )
        if answer:
            webbrowser.open(f"mailto:{PREMIUM_CONTACT_EMAIL}?subject=SMB Sentinel Premium")

    def _open_settings(self):
        win = ctk.CTkToplevel(self)
        win.title("Settings")
        win.geometry("420x260")
        win.configure(fg_color=CARD_BG)

        ctk.CTkLabel(win, text="Appearance", font=ctk.CTkFont(weight="bold")).pack(pady=(16, 4))
        mode_var = ctk.StringVar(value=ctk.get_appearance_mode())
        ctk.CTkSegmentedButton(
            win, values=["Light", "Dark"], variable=mode_var,
            command=lambda v: ctk.set_appearance_mode(v)
        ).pack(pady=4)

        ctk.CTkLabel(win, text="Premium License Key", font=ctk.CTkFont(weight="bold")).pack(pady=(20, 4))
        key_entry = ctk.CTkEntry(win, width=300, placeholder_text="MRCYBER-XXXXXXXX-XXXXXXXX")
        key_entry.pack(pady=4)
        if self.is_premium:
            key_entry.insert(0, license_manager.load_saved_key())

        def activate():
            key = key_entry.get().strip()
            if license_manager.verify_key(key):
                license_manager.save_key(key)
                messagebox.showinfo("Success", "Premium activated! Restart the app to unlock all features.")
                win.destroy()
            else:
                messagebox.showerror("Invalid Key", "That license key isn't valid. Check for typos or contact support.")

        ctk.CTkButton(win, text="Activate", command=activate, fg_color=NEON_GREEN, text_color="black").pack(pady=10)

    def _maybe_show_onboarding(self):
        messagebox.showinfo(
            "Welcome to SMB Sentinel",
            "Quick start:\n\n"
            "1. Click 'Auto-Detect My Network' (or type your range manually)\n"
            "2. Click 'Scan Network'\n"
            "3. Review results — red/yellow means action needed\n"
            "4. Double-click a device name to label it (e.g. 'Reception PC')\n\n"
            "This tool only reads standard connection info — it does not "
            "attempt to log in or exploit anything."
        )


if __name__ == "__main__":
    app = SMBSentinelApp()
    app.mainloop()
