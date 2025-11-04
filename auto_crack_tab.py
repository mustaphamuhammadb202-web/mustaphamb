import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from utils import run_command
from datetime import datetime

class AutoCrackTab:
    def __init__(self, notebook, app):
        self.app = app
        self.auto_crack_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.auto_crack_tab, text="Auto Crack")

        # Initialize variables
        self.handshake_file = tk.StringVar()
        self.is_cracking = False
        self.crack_process = None
        self.converted_file = None

        # Create main container
        self.create_file_selection()

    def create_file_selection(self):
        """Create the file selection section with simple interface."""
        file_frame = ttk.LabelFrame(self.auto_crack_tab, text="Auto Crack Configuration", style='Card.TLabelframe')
        file_frame.pack(fill="x", padx=10, pady=10)

        # File selection container
        file_container = ttk.Frame(file_frame)
        file_container.pack(fill="x", padx=15, pady=10)

        # Handshake file selection
        file_selection_frame = ttk.Frame(file_container)
        file_selection_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(file_selection_frame, text="Handshake File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.handshake_file, state="readonly", font=('Arial', 10), width=30).pack(side="left", padx=(0, 10))
        handshake_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_handshake_file)
        handshake_btn.pack(side="left", padx=(0, 10))

        # Description
        desc_label = ttk.Label(file_container, text="Auto crack mode uses mask and brute force attacks to crack the password from the handshake file.", style='Info.TLabel')
        desc_label.pack(anchor="w", pady=(0, 10))

        # Control buttons
        control_container = ttk.Frame(file_container)
        control_container.pack(fill="x", pady=10)
        crack_btn = ttk.Button(control_container, text="⚡ Start Cracking", style='Success.TButton', command=self.start_cracking)
        crack_btn.pack(side="left", padx=(0, 10))
        stop_btn = ttk.Button(control_container, text="⏹️ Stop Cracking", style='Danger.TButton', command=self.stop_cracking)
        stop_btn.pack(side="left", padx=(0, 10))

        # Progress bar
        self.progress_bar = ttk.Progressbar(file_container, mode='indeterminate', style='TProgressbar')
        self.progress_bar.pack(fill="x", pady=(10, 5))

        # Status indicator
        self.status_label = ttk.Label(file_container, text="Ready to start cracking", style='Info.TLabel')
        self.status_label.pack(pady=(5, 0))

    def select_handshake_file(self):
        """Select handshake capture file."""
        file_path = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap *.hc22000")])
        if file_path:
            self.handshake_file.set(file_path)
            self.app.log_message(f"Selected handshake file: {file_path}", "SUCCESS")

    def convert_handshake(self, handshake_file):
        """Convert .cap to .hc22000 for Hashcat."""
        if not handshake_file.endswith(".hc22000"):
            output_file = os.path.splitext(handshake_file)[0] + ".hc22000"
            cmd = ["hcxpcapngtool", "-o", output_file, handshake_file]
            try:
                self.app.log_message(f"Converting handshake to Hashcat format: {output_file}", "INFO")
                self.status_label.configure(text="Converting handshake...")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self.app.log_message("Handshake converted successfully.", "SUCCESS")
                    self.converted_file = output_file
                    return output_file
                else:
                    self.app.log_message(f"Failed to convert handshake: {result.stderr}", "ERROR")
                    self.status_label.configure(text="Handshake conversion failed")
                    return None
            except subprocess.TimeoutExpired:
                self.app.log_message("Handshake conversion timed out.", "ERROR")
                self.status_label.configure(text="Handshake conversion timed out")
                return None
            except Exception as e:
                self.app.log_message(f"Error converting handshake: {str(e)}", "ERROR")
                self.status_label.configure(text="Handshake conversion failed")
                return None
        self.converted_file = handshake_file
        return handshake_file

    def validate_handshake(self, handshake_file):
        """Validate handshake file using aircrack-ng."""
        self.app.log_message("Validating handshake file...", "INFO")
        self.status_label.configure(text="Validating handshake")
        process = subprocess.Popen(
            f"aircrack-ng {handshake_file}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            output, error = process.communicate(timeout=30)
            if "No valid WPA handshakes found" in output or "No valid WPA handshakes found" in error:
                self.app.log_message("No valid WPA handshake found in the capture file.", "ERROR")
                self.status_label.configure(text="Invalid handshake file")
                return False
            hash_count = len(re.findall(r"WPA \(\d+ handshake", output))
            if hash_count > 1:
                self.app.log_message(f"Warning: Multiple ({hash_count}) handshakes detected in the file.", "WARNING")
            self.app.log_message("Handshake file validated successfully.", "SUCCESS")
            return True
        except subprocess.TimeoutExpired:
            self.app.log_message("Handshake validation timed out.", "ERROR")
            self.status_label.configure(text="Handshake validation timed out")
            return False

    def cleanup_converted_file(self):
        """Clean up the converted .hc22000 file if it was created."""
        if self.converted_file and os.path.exists(self.converted_file) and self.converted_file.endswith(".hc22000"):
            try:
                os.remove(self.converted_file)
                self.app.log_message(f"Cleaned up converted file: {self.converted_file}", "INFO")
                self.converted_file = None
            except Exception as e:
                self.app.log_message(f"Error cleaning up converted file: {str(e)}", "ERROR")

    def cleanup_candidate_file(self):
        """Clean up the candidate passwords file."""
        if self.candidate_file and os.path.exists(self.candidate_file):
            try:
                os.remove(self.candidate_file)
                self.app.log_message(f"Cleaned up candidate file: {self.candidate_file}", "INFO")
                self.candidate_file = None
            except Exception as e:
                self.app.log_message(f"Error cleaning up candidate file: {str(e)}", "ERROR")

    def stop_cracking(self):
        """Stop the cracking process."""
        if self.is_cracking:
            self.is_cracking = False
            if self.crack_process:
                try:
                    self.crack_process.terminate()
                    self.crack_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.crack_process.kill()
                self.crack_process = None
            run_command("pkill -9 -f 'hashcat'", capture_output=False)
            self.progress_bar.stop()
            self.status_label.configure(text="Cracking stopped")
            self.candidates_text.configure(state='normal')
            self.candidates_text.delete(1.0, tk.END)
            self.candidates_text.configure(state='disabled')
            self.app.log_message("Password cracking stopped.", "INFO")
            self.cleanup_converted_file()
            self.cleanup_candidate_file()
            self.app.root.after(0, lambda: messagebox.showinfo("Success", "Password cracking process stopped."))
        else:
            self.app.log_message("No cracking process is running.", "INFO")

    def update_candidates_display(self):
        """Read and display the latest candidate passwords from the candidate file."""
        if not self.candidate_file or not os.path.exists(self.candidate_file):
            return
        try:
            with open(self.candidate_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-5:]  # Display only the last 5 candidates to avoid overload
                self.candidates_text.configure(state='normal')
                self.candidates_text.delete(1.0, tk.END)
                self.candidates_text.insert(tk.END, "Latest candidate passwords (sample):\n")
                for line in lines:
                    password = line.strip()
                    if password:
                        self.candidates_text.insert(tk.END, f"{password}\n")
                self.candidates_text.configure(state='disabled')
                self.candidates_text.see(tk.END)
        except Exception as e:
            self.app.log_message(f"Error reading candidate file: {str(e)}", "ERROR")

    def start_cracking(self):
        """Start robust cracking using mask and brute force modes with Hashcat."""
        handshake = self.handshake_file.get()

        if not handshake:
            self.app.log_message("Please select a handshake file.", "ERROR")
            messagebox.showerror("Error", "Please select a handshake file.")
            return
        if not os.path.exists(handshake):
            self.app.log_message(f"Handshake file does not exist: {handshake}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return

        if not self.validate_handshake(handshake):
            return

        handshake = self.convert_handshake(handshake)
        if not handshake:
            return

        def crack():
            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Cracking in progress...")
            self.candidates_text.configure(state='normal')
            self.candidates_text.delete(1.0, tk.END)
            self.candidates_text.insert(tk.END, "Starting cracking...\n")
            self.candidates_text.configure(state='disabled')
            self.app.log_message(f"Starting robust cracking with handshake: {handshake}", "INFO")

            # Define candidate file
            self.candidate_file = os.path.splitext(handshake)[0] + "_candidates.txt"

            # Define mask and brute force commands with -w 3 and candidate output
            mask_cmd = ["hashcat", "-m", "22000", "-a", "3", "-w", "3", "--outfile", self.candidate_file, "--outfile-format", "2", handshake, "?l?l?l?l?l?l?l?l"]
            brute_cmd = ["hashcat", "-m", "22000", "-a", "3", "-w", "3", "-i", "--increment-min=8", "--increment-max=10", "--outfile", self.candidate_file, "--outfile-format", "2", handshake, "?l?d?s"]

            def run_crack_command(cmd, attack_type, timeout=3600):
                self.app.log_message(f"Starting {attack_type} attack...", "INFO")
                start_time = time.time()
                self.crack_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                while self.crack_process.poll() is None and self.is_cracking:
                    if time.time() - start_time > timeout:
                        self.app.log_message(f"{attack_type.capitalize()} attack timed out after {timeout} seconds.", "WARNING")
                        self.crack_process.terminate()
                        break
                    line = self.crack_process.stdout.readline()
                    if line:
                        self.app.log_message(line.strip(), "INFO")
                        progress_match = re.search(r"Progress.*?(\d+\.\d+%)\)", line)
                        if progress_match:
                            self.status_label.configure(text=f"Cracking in progress ({progress_match.group(1)})...")
                        if "Recovered" in line and "Hashes" in line:
                            match = re.search(r"Recovered.*?: \d+/(\d+) Hashes.*?\((\w+):(.+?)\)", line)
                            if match:
                                password = match.group(2).strip()
                                self.app.log_message(f"Password found: {password}", "SUCCESS")
                                self.status_label.configure(text=f"Password found: {password}")
                                self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                                return True
                    # Update candidate passwords every 2 seconds
                    self.app.root.after(2000, self.update_candidates_display)
                    time.sleep(0.1)
                return False

            # Run mask attack (1 hour timeout)
            if self.is_cracking:
                if run_crack_command(mask_cmd, "mask", timeout=3600):
                    self.is_cracking = False

            # Run brute force attack if mask didn't find it (2 hour timeout)
            if self.is_cracking:
                if run_crack_command(brute_cmd, "brute force", timeout=7200):
                    self.is_cracking = False

            self.is_cracking = False
            self.crack_process = None
            self.progress_bar.stop()
            self.status_label.configure(text="Cracking completed - No password found" if not self.status_label.cget("text").startswith("Password found") else self.status_label.cget("text"))
            self.candidates_text.configure(state='normal')
            self.candidates_text.delete(1.0, tk.END)
            self.candidates_text.insert(tk.END, "Cracking completed.\n")
            self.candidates_text.configure(state='disabled')
            self.app.log_message("Password cracking completed.", "INFO")
            self.cleanup_converted_file()
            self.cleanup_candidate_file()
            self.app.root.after(0, lambda: messagebox.showinfo("Completed", "Password cracking completed. Check log for details."))

        # Ensure no other cracking process is running
        if self.is_cracking:
            self.app.log_message("A cracking process is already running.", "ERROR")
            messagebox.showerror("Error", "A cracking process is already running. Please stop it first.")
            return

        threading.Thread(target=crack, daemon=True).start()