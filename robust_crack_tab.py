import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import time
import re

class RobustCrackTab:
    def __init__(self, notebook, app):
        self.app = app
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text="Robust Crack")
        self.cap_file = tk.StringVar()
        self.mask_pattern = tk.StringVar()
        self.create_widgets()
        self.hashcat_proc = None

    def create_widgets(self):
        main_frame = ttk.LabelFrame(self.frame, text="Robust Crack", style='Card.TLabelframe')
        main_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(main_frame, text="Capture File:", style='Info.TLabel').grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        file_entry = ttk.Entry(main_frame, textvariable=self.cap_file, width=40)
        file_entry.grid(row=0, column=1, padx=(10, 5), pady=10)
        browse_btn = ttk.Button(main_frame, text="Browse", command=self.browse_cap)
        browse_btn.grid(row=0, column=2, padx=(0, 10), pady=10)

        # Mask pattern dropdown for non-technical users
        ttk.Label(main_frame, text="Password Type:").grid(row=1, column=0, sticky="w", pady=5)
        self.mask_options = {
            "8-digit PIN (numbers)": "?d?d?d?d?d?d?d?d",
            "10-digit PIN (numbers)": "?d?d?d?d?d?d?d?d?d?d",
            "8 lowercase letters": "?l?l?l?l?l?l?l?l",
            "8 uppercase letters": "?u?u?u?u?u?u?u?u",
            "8 letters (mixed case)": "?l?u?l?u?l?u?l?u",
            "8 letters & numbers": "?l?d?l?d?l?d?l?d",
            "6 letters + 2 numbers": "?l?l?l?l?l?l?d?d",
            "1 letter + 8 digits": "?l?d?d?d?d?d?d?d?d",  # <-- Added option
            "Custom (advanced)": "custom"
        }
        self.mask_combo = ttk.Combobox(main_frame, values=list(self.mask_options.keys()), state="readonly", width=22)
        self.mask_combo.grid(row=1, column=1, padx=(10, 5), pady=5)
        self.mask_combo.current(0)
        self.mask_combo.bind("<<ComboboxSelected>>", self.on_mask_select)

        self.mask_entry = ttk.Entry(main_frame, textvariable=self.mask_pattern, width=22)
        self.mask_entry.grid(row=1, column=2, padx=(0, 10), pady=5)
        self.mask_entry.grid_remove()  # Hide initially

        self.start_btn = ttk.Button(main_frame, text="Start Crack", command=self.start_crack)
        self.start_btn.grid(row=2, column=1, padx=(10, 5), pady=10)
        self.stop_btn = ttk.Button(main_frame, text="Stop Crack", command=self.stop_crack, state="disabled")
        self.stop_btn.grid(row=2, column=2, padx=(0, 10), pady=10)

        # Remove the old progress bar
        # self.progress = ttk.Progressbar(main_frame, mode='determinate', maximum=100)
        # self.progress.pack(fill="x", padx=10, pady=(5, 10))
        # self.progress_label = ttk.Label(main_frame, text="Progress: 0%")
        # self.progress_label.pack(anchor="w", padx=10, pady=(0, 10))

    def browse_cap(self):
        filename = filedialog.askopenfilename(filetypes=[("Capture Files", "*.cap *.pcapng *.hccapx")])
        if filename:
            self.cap_file.set(filename)

    def on_mask_select(self, event=None):
        selected = self.mask_combo.get()
        if selected == "Custom (advanced)":
            self.mask_entry.grid()
            self.mask_pattern.set("")
        else:
            self.mask_entry.grid_remove()
            self.mask_pattern.set(self.mask_options[selected])

    def start_crack(self):
        cap_file = self.cap_file.get().strip()
        mask = self.mask_pattern.get().strip()
        if not cap_file:
            messagebox.showerror("Error", "Please select a capture file.")
            return
        if not mask:
            messagebox.showerror("Error", "Please select or enter a mask pattern.")
            return

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.app.log_message(f"Starting robust crack on {cap_file} with mask {mask}", "INFO")
        threading.Thread(target=self.run_hashcat_with_modal, args=(cap_file, mask), daemon=True).start()

    def stop_crack(self):
        if self.hashcat_proc and self.hashcat_proc.poll() is None:
            self.hashcat_proc.terminate()
            self.app.log_message("Hashcat process terminated by user.", "INFO")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def show_info_modal(self, title, message):
        modal = tk.Toplevel(self.frame)
        modal.title(title)
        modal.transient(self.frame)
        modal.grab_set()
        modal.geometry("350x120")
        ttk.Label(modal, text=message, font=("Arial", 11)).pack(pady=20)
        ttk.Button(modal, text="OK", command=modal.destroy).pack(pady=10)

    def run_hashcat_with_modal(self, cap_file, mask):
        # Convert .cap/.pcapng to .hccapx if needed
        hccapx_file = cap_file
        if not cap_file.endswith(".hccapx"):
            hccapx_file = cap_file + ".hccapx"
            convert_cmd = ["hcxpcapngtool", "-o", hccapx_file, cap_file]
            result = subprocess.run(convert_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.app.log_message(f"Failed to convert cap file: {result.stderr}", "ERROR")
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
                return

        # Modal progress bar
        modal = tk.Toplevel(self.frame)
        modal.title("Robust Crack Progress")
        modal.transient(self.frame)
        modal.grab_set()
        modal.geometry("350x120")
        ttk.Label(modal, text="Cracking password, please wait...", font=("Arial", 11)).pack(pady=10)
        progress = ttk.Progressbar(modal, mode='determinate', maximum=100)
        progress.pack(fill="x", padx=20, pady=10)
        percent_label = ttk.Label(modal, text="Progress: 0%")
        percent_label.pack(pady=5)

        hashcat_cmd = [
            "hashcat", "-m", "22000", hccapx_file, "-a", "3", mask,
            "--force", "--status", "--optimized-kernel-enable", "-w", "3", "--status-timer=5"
        ]
        try:
            self.hashcat_proc = subprocess.Popen(hashcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            percent = 0
            last_percent = 0
            while self.hashcat_proc.poll() is None:
                line = self.hashcat_proc.stdout.readline()
                if line:
                    self.app.log_message(line.strip(), "INFO")
                    percent_match = re.search(r"(\d+\.\d+)%", line)
                    if percent_match:
                        percent = float(percent_match.group(1))
                        try:
                            if modal.winfo_exists():
                                progress["value"] = percent
                                percent_label.config(text=f"Progress: {percent:.2f}%")
                                modal.update_idletasks()
                                last_percent = percent
                        except tk.TclError:
                            break
                time.sleep(0.2)

            # After process ends, ensure final progress is shown
            try:
                if modal.winfo_exists():
                    progress["value"] = last_percent
                    percent_label.config(text=f"Progress: {last_percent:.2f}%")
                    modal.update_idletasks()
                    time.sleep(0.5)
                    modal.destroy()
            except tk.TclError:
                pass

            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.hashcat_proc = None

            if self.hashcat_proc:
                stdout, stderr = self.hashcat_proc.communicate()
                if self.hashcat_proc.returncode == 0:
                    self.app.log_message("Robust crack completed successfully.", "SUCCESS")
                    self.show_info_modal("Success", "Password cracked or process finished. Check log for details.")
                else:
                    self.app.log_message("Robust crack failed or password not found.", "WARNING")
                    self.show_info_modal("Result", "Password not found or crack failed. Check log for details.")
            else:
                self.app.log_message("Hashcat process did not start or was terminated.", "ERROR")
                self.show_info_modal("Error", "Hashcat process did not start or was terminated.")
        except Exception as e:
            self.app.log_message(f"Error running hashcat: {str(e)}", "ERROR")
            self.show_info_modal("Error", f"Error running hashcat: {str(e)}")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.hashcat_proc = None