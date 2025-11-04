import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from datetime import datetime
from utils import run_command

class CrackingTab:
    def __init__(self, notebook, app):
        self.app = app
        self.cracking_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.cracking_tab, text="Password Cracking")

        # Initialize variables
        self.wordlist_file = tk.StringVar()
        self.is_cracking = False
        self.current_progress = ""

        # Create main container
        self.create_file_selection()

    def create_file_selection(self):
        """Create the file selection section with handshake and wordlist on one line."""
        file_frame = ttk.LabelFrame(self.cracking_tab, text="File Selection", style='Card.TLabelframe')
        file_frame.pack(fill="x", padx=10, pady=10)

        file_container = ttk.Frame(file_frame)
        file_container.pack(fill="x", padx=15, pady=10)

        file_selection_frame = ttk.Frame(file_container)
        file_selection_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(file_selection_frame, text="Handshake File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.app.handshake_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        handshake_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_handshake_file)
        handshake_btn.pack(side="left", padx=(0, 10))

        ttk.Label(file_selection_frame, text="Wordlist File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.wordlist_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        wordlist_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_wordlist_file)
        wordlist_btn.pack(side="left")

        bssid_frame = ttk.Frame(file_container)
        bssid_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(bssid_frame, text="Target BSSID:", style='Info.TLabel').pack(anchor="w")
        ttk.Label(bssid_frame, text="(From Handshake & Capture tab or enter manually)", style='Info.TLabel').pack(anchor="w")
        ttk.Entry(bssid_frame, textvariable=self.app.selected_bssid, font=('Arial', 10)).pack(fill="x", pady=(5, 0))

        control_container = ttk.Frame(file_container)
        control_container.pack(fill="x", pady=10)
        crack_btn = ttk.Button(control_container, text="🔓 Start Cracking", style='Success.TButton', command=self.start_cracking)
        crack_btn.pack(side="left", padx=(0, 10))
        stop_btn = ttk.Button(control_container, text="⏹️ Stop Cracking", style='Danger.TButton', command=self.stop_cracking)
        stop_btn.pack(side="left", padx=(0, 10))
        clear_btn = ttk.Button(control_container, text="🗑️ Clear Wordlist", style='Warning.TButton', command=self.clear_wordlist)
        clear_btn.pack(side="left")

        # Remove the old progress bar
        # self.progress_bar = ttk.Progressbar(file_container, mode='indeterminate', style='TProgressbar')
        # self.progress_bar.pack(fill="x", pady=(10, 5))

        self.status_label = ttk.Label(file_container, text="Ready to crack passwords", style='Info.TLabel')
        self.status_label.pack(pady=(5, 0))

    def select_handshake_file(self):
        """Select handshake capture file."""
        file_path = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap")])
        if file_path:
            self.app.handshake_file.set(file_path)
            self.app.log_message(f"Selected handshake file: {file_path}", "SUCCESS")

    def select_wordlist_file(self):
        """Select wordlist file."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.wordlist_file.set(file_path)
            self.app.log_message(f"Selected wordlist file: {file_path}", "SUCCESS")

    def clear_wordlist(self):
        """Clear the selected wordlist."""
        self.wordlist_file.set("")
        self.app.log_message("Wordlist selection cleared.", "INFO")

    def stop_cracking(self):
        """Stop the cracking process."""
        if self.is_cracking:
            run_command("pkill -9 -f 'aircrack-ng'", capture_output=False)
            self.is_cracking = False
            # self.progress_bar.stop()
            self.status_label.configure(text="Cracking stopped")
            self.app.log_message("Password cracking stopped.", "INFO")
            self.app.root.after(0, lambda: messagebox.showinfo("Success", "Password cracking process stopped."))

    def show_report_modal(self, report_content):
        """Display the cracking report in a GUI modal."""
        report_window = tk.Toplevel(self.app.root)
        report_window.title("Password Cracking Report")
        report_window.geometry("600x450")
        report_window.resizable(False, False)
        report_window.transient(self.app.root)
        report_window.grab_set()
        report_window.configure(bg='#ffffff')

        # Center the window
        report_window.update_idletasks()
        x = (report_window.winfo_screenwidth() // 2) - (300)
        y = (report_window.winfo_screenheight() // 2) - (225)
        report_window.geometry(f"600x450+{x}+{y}")

        # Report content
        content_frame = ttk.Frame(report_window, style='Card.TFrame')
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header_frame = ttk.Frame(content_frame)
        header_frame.pack(fill="x", pady=(0, 15))
        title_label = ttk.Label(header_frame, text="Password Cracking Report", style='Title.TLabel')
        title_label.pack(side="left")

        # Text widget with scrollbar
        text_container = ttk.Frame(content_frame)
        text_container.pack(fill="both", expand=True, pady=(0, 15))
        text_widget = tk.Text(
            text_container,
            wrap="word",
            font=('Arial', 10),
            bg='#ffffff',
            fg='#000000',
            relief='flat',
            padx=15,
            pady=15,
            height=15
        )
        scrollbar_y = ttk.Scrollbar(text_container, orient="vertical", command=text_widget.yview, style='Vertical.TScrollbar')
        text_widget.config(yscrollcommand=scrollbar_y.set)
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")
        text_widget.insert("1.0", report_content)
        text_widget.config(state="disabled")

        # Close button
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill="x", pady=(0, 10))
        close_btn = ttk.Button(
            button_frame,
            text="Close",
            style='Primary.TButton',
            command=report_window.destroy
        )
        close_btn.pack(side="right", padx=(10, 0))
        close_btn.focus_set()

    def start_cracking(self):
        """Start password cracking with aircrack-ng and show a modal progress bar."""
        handshake = self.app.handshake_file.get()
        wordlist = self.wordlist_file.get()
        bssid = self.app.selected_bssid.get()

        if not handshake or not wordlist:
            self.app.log_message("Please select both handshake and wordlist files.", "ERROR")
            messagebox.showerror("Error", "Please select both handshake and wordlist files.")
            return
        if not os.path.exists(handshake):
            self.app.log_message(f"Handshake file does not exist: {handshake}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return
        if not os.path.exists(wordlist):
            self.app.log_message(f"Wordlist file does not exist: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file does not exist.")
            return
        if os.path.getsize(wordlist) == 0:
            self.app.log_message(f"Wordlist file is empty: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file is empty.")
            return
        if not bssid:
            self.app.log_message("Please enter or select a network BSSID.", "ERROR")
            messagebox.showerror("Error", "Please enter or select a network BSSID.")
            return
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            self.app.log_message(f"Invalid BSSID format: {bssid}", "ERROR")
            messagebox.showerror("Error", "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX (e.g., 00:11:22:33:44:55).")
            return

        def validate_handshake():
            self.app.log_message("Validating handshake file...", "INFO")
            self.status_label.configure(text="Validating handshake")
            process = subprocess.Popen(
                f"aircrack-ng {handshake}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output, error = process.communicate()
            if "No valid WPA handshakes found" in output or "No valid WPA handshakes found" in error:
                self.app.log_message("No valid WPA handshake found in the capture file.", "ERROR")
                self.status_label.configure(text="Invalid handshake file")
                return False
            self.app.log_message("Handshake file validated successfully.", "SUCCESS")
            return True

        def crack():
            if not validate_handshake():
                self.status_label.configure(text="Ready to crack passwords")
                return

            self.is_cracking = True
            self.status_label.configure(text="Cracking in progress...")
            self.app.log_message(f"Starting password cracking with handshake: {handshake}, wordlist: {wordlist}, BSSID: {bssid}", "INFO")

            # Modal progress bar
            modal = tk.Toplevel(self.cracking_tab)
            modal.title("Cracking Password")
            modal.transient(self.cracking_tab)
            modal.grab_set()
            modal.geometry("350x120")
            ttk.Label(modal, text="Cracking password, please wait...", font=("Arial", 11)).pack(pady=10)
            progress = ttk.Progressbar(modal, mode='determinate', maximum=100)
            progress.pack(fill="x", padx=20, pady=10)
            percent_label = ttk.Label(modal, text="Progress: 0%")
            percent_label.pack(pady=5)

            process = subprocess.Popen(
                f"aircrack-ng -w {wordlist} -b {bssid} {handshake}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            progress_regex = re.compile(r"\[\s*(\d+)/(\d+)\s*\]\s*(\d+\.\d+\s*keys/s)?")
            total_keys = None
            current_keys = 0

            while process.poll() is None and self.is_cracking:
                line = process.stdout.readline()
                if line:
                    self.app.log_message(line.strip(), "INFO")
                    match = progress_regex.search(line)
                    if match:
                        current_keys = int(match.group(1))
                        total_keys = int(match.group(2))
                        speed = match.group(3) or "N/A"
                        percent = int((current_keys / total_keys) * 100) if total_keys else 0
                        progress["value"] = percent
                        percent_label.config(text=f"Progress: {percent}% ({current_keys}/{total_keys} keys)")
                        modal.update_idletasks()
                        self.status_label.configure(text=f"Cracking: {current_keys}/{total_keys} keys tested ({speed})")
                    self.app.log_text.see(tk.END)
                    self.app.root.update()
                time.sleep(0.1)

            modal.destroy()
            self.is_cracking = False

            output, error = process.communicate()
            self.status_label.configure(text="Ready to crack passwords")

            if output:
                self.app.log_message(output.strip(), "INFO")
            if error:
                self.app.log_message(f"Error: {error.strip()}", "ERROR")

            if "KEY FOUND" in output:
                match = re.search(r"KEY FOUND! \[ (.+?) \]", output)
                if match:
                    password = match.group(1)
                    duration = "N/A"
                    self.app.log_message(f"Password found: {password}", "SUCCESS")
                    self.status_label.configure(text=f"Password found: {password}")
                    self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                    # Generate and save report (same as quick crack tab)
                    report_dir = "/home/kali/Wireless-Security-Analyzer/reports"
                    os.makedirs(report_dir, exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    report_file = f"{report_dir}/{timestamp}_crack_report.txt"
                    client_mac = self.app.selected_client.get() if hasattr(self.app, "selected_client") else "FF:FF:FF:FF:FF:FF"
                    report_content = (
                        f"Wi-Fi Password Cracking Report\n"
                        f"=============================\n"
                        f"Timestamp: {datetime.now().strftime('%b %d %Y %H:%M:%S')}\n"
                        f"Password: {password}\n"
                        f"BSSID: {bssid}\n"
                        f"Client MAC: {client_mac}\n"
                        f"Handshake File: {handshake}\n"
                        f"Wordlist File: {wordlist}\n"
                        f"Cracking Duration: {duration}\n"
                        f"\nFindings:\n"
                        f"The password for the Wi-Fi network (BSSID: {bssid}) was successfully cracked using aircrack-ng, "
                        f"indicating a potential vulnerability in the current security configuration (likely WPA2). "
                        f"This demonstrates that the network is susceptible to brute-force attacks if weak passwords are used.\n"
                        f"\nRecommendations:\n"
                        f"- Transition to WPA3: Adopt WPA3, the latest Wi-Fi security standard, which offers stronger encryption "
                        f"and enhanced protection against offline brute-force attacks, significantly improving network security.\n"
                        f"- Use Strong Passwords: Implement complex passwords with at least 12 characters, including a mix of "
                        f"uppercase and lowercase letters, numbers, and special characters. Avoid dictionary words or predictable patterns.\n"
                        f"- Regular Security Updates: Periodically update Wi-Fi passwords and review network security settings to "
                        f"mitigate risks of unauthorized access.\n"
                        f"- Monitor Network Activity: Use intrusion detection tools to identify and respond to suspicious activity.\n"
                        f"\nSecurity Note:\n"
                        f"The successful cracking of this password highlights the critical need for stronger security standards like WPA3. "
                        f"WPA3 provides robust defenses against the types of attacks demonstrated by this tool, ensuring better protection "
                        f"for your network and data.\n"
                        f"=============================\n"
                    )
                    try:
                        with open(report_file, "w") as f:
                            f.write(report_content)
                        self.app.log_message(f"Crack report generated: {report_file}", "SUCCESS")
                        self.app.root.after(0, lambda: self.show_report_modal(report_content))
                    except Exception as e:
                        self.app.log_message(f"Failed to generate crack report: {str(e)}", "ERROR")
                else:
                    self.app.log_message("Password found but could not parse key.", "WARNING")
                    self.status_label.configure(text="Password found (key parsing failed)")
            else:
                self.app.log_message("Password not found in wordlist.", "WARNING")
                self.status_label.configure(text="Password not found")
                self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found in wordlist. Try a different wordlist or capture."))

            self.app.log_text.see(tk.END)

        threading.Thread(target=crack, daemon=True).start()