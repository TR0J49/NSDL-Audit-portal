"""
System Audit Agent - GUI Application (NSDL Inspection Style)
Uses CustomTkinter for a modern look and feel.
"""

import sys
import threading
import customtkinter as ctk
from audit_agent import SystemAuditor, upload_audit

# Configuration - change these before building
SERVER_URL = "http://localhost:8000"


class AuditAgentApp(ctk.CTk):
    def __init__(self, token: str):
        super().__init__()
        self.token = token
        self.title("NSDL e-Gov System Inspection Agent")
        self.geometry("520x460")
        self.resizable(False, False)

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 260
        y = (self.winfo_screenheight() // 2) - 230
        self.geometry(f"+{x}+{y}")

        self.build_ui()

    def build_ui(self):
        # Header bar
        header = ctk.CTkFrame(self, fg_color="#1a365d", height=60, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="NSDL e-Governance", font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white",
        ).pack(side="left", padx=20, pady=15)

        ctk.CTkLabel(
            header, text="System Inspection", font=ctk.CTkFont(size=13),
            text_color="#93c5fd",
        ).pack(side="right", padx=20, pady=15)

        # Body
        body = ctk.CTkFrame(self, fg_color="white", corner_radius=0)
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # Title
        ctk.CTkLabel(
            body, text="System Inspection Agent",
            font=ctk.CTkFont(size=20, weight="bold"), text_color="#1a365d",
        ).pack(pady=(30, 5))

        ctk.CTkLabel(
            body, text="Collecting system details for NSDL compliance verification",
            font=ctk.CTkFont(size=12), text_color="#64748b",
        ).pack(pady=(0, 20))

        # Status
        self.status_label = ctk.CTkLabel(
            body, text="Ready to start inspection",
            font=ctk.CTkFont(size=14), text_color="#475569",
        )
        self.status_label.pack(pady=(0, 10))

        # Step detail
        self.step_label = ctk.CTkLabel(
            body, text="",
            font=ctk.CTkFont(size=11), text_color="#94a3b8",
        )
        self.step_label.pack(pady=(0, 5))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(body, width=400, height=14, progress_color="#1a365d")
        self.progress_bar.pack(pady=(0, 5))
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            body, text="0%", font=ctk.CTkFont(size=12), text_color="#94a3b8",
        )
        self.progress_label.pack(pady=(0, 20))

        # Start button
        self.start_button = ctk.CTkButton(
            body, text="Start Inspection", font=ctk.CTkFont(size=15, weight="bold"),
            width=280, height=45, corner_radius=8, fg_color="#1a365d",
            hover_color="#2d4a7a", command=self.start_audit,
        )
        self.start_button.pack(pady=(0, 15))

        # Result label
        self.result_label = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=12), text_color="#64748b",
            wraplength=400,
        )
        self.result_label.pack()

        # Footer
        footer = ctk.CTkFrame(self, fg_color="#f1f5f9", height=30, corner_radius=0)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        ctk.CTkLabel(
            footer, text="Inspection Report by NSDL e-Governance",
            font=ctk.CTkFont(size=9), text_color="#800000",
        ).pack(pady=6)

    def start_audit(self):
        self.start_button.configure(state="disabled", text="Inspecting...")
        self.status_label.configure(text="Initializing inspection...")
        threading.Thread(target=self.run_audit, daemon=True).start()

    def run_audit(self):
        try:
            auditor = SystemAuditor()
            data = auditor.collect_all(progress_callback=self.update_progress)

            self.after(0, lambda: self.status_label.configure(text="Uploading inspection data..."))
            self.after(0, lambda: self.step_label.configure(text="Sending data to server securely"))
            self.after(0, lambda: self.progress_bar.set(0.95))
            self.after(0, lambda: self.progress_label.configure(text="95%"))

            success = upload_audit(SERVER_URL, self.token, data)

            if success:
                self.after(0, self.show_success)
            else:
                self.after(0, lambda: self.show_error("Upload failed. Please check your network connection and try again."))
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda: self.show_error(err_msg))

    def update_progress(self, step_name: str, percent: int):
        self.after(0, lambda: self.status_label.configure(text=f"Collecting: {step_name}"))
        self.after(0, lambda: self.step_label.configure(text=f"Scanning {step_name.lower()} information..."))
        self.after(0, lambda: self.progress_bar.set(percent / 100))
        self.after(0, lambda: self.progress_label.configure(text=f"{percent}%"))

    def show_success(self):
        self.progress_bar.set(1.0)
        self.progress_label.configure(text="100%")
        self.status_label.configure(text="Inspection Complete!", text_color="#16a34a")
        self.step_label.configure(text="All system details collected and uploaded")
        self.result_label.configure(
            text="System inspection data has been uploaded successfully.\n"
                 "The inspection report has been generated.\nYou may close this window.",
            text_color="#16a34a",
        )
        self.start_button.configure(text="Done", state="disabled", fg_color="#16a34a")

    def show_error(self, message: str):
        self.status_label.configure(text="Inspection Failed", text_color="#dc2626")
        self.step_label.configure(text="")
        self.result_label.configure(text=message, text_color="#dc2626")
        self.start_button.configure(text="Retry", state="normal", fg_color="#dc2626")


def main():
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    if not token:
        root = ctk.CTk()
        root.title("NSDL System Inspection Agent")
        root.geometry("440x220")
        root.resizable(False, False)

        ctk.set_appearance_mode("light")

        header = ctk.CTkFrame(root, fg_color="#1a365d", height=40, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="NSDL e-Governance", font=ctk.CTkFont(size=14, weight="bold"), text_color="white").pack(pady=8)

        body = ctk.CTkFrame(root, fg_color="white", corner_radius=0)
        body.pack(fill="both", expand=True)

        ctk.CTkLabel(body, text="Enter Verification Token", font=ctk.CTkFont(size=15, weight="bold"), text_color="#1a365d").pack(pady=(20, 8))
        entry = ctk.CTkEntry(body, width=340, placeholder_text="Paste your verification token here...")
        entry.pack(pady=5)

        def submit():
            t = entry.get().strip()
            if t:
                root.destroy()
                app = AuditAgentApp(t)
                app.mainloop()

        ctk.CTkButton(body, text="Start Inspection", command=submit, width=220, fg_color="#1a365d").pack(pady=10)
        root.mainloop()
    else:
        app = AuditAgentApp(token)
        app.mainloop()


if __name__ == "__main__":
    main()
