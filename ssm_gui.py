import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib, json, pyotp, nmap, threading
from datetime import datetime

# === AUTH MODULE ===

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    try:
        with open('user_db.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def authenticate(username, password):
    users = load_users()
    if username in users:
        hashed = hash_password(password)
        if users[username]['password'] == hashed:
            return users[username]['totp_secret']
    return None

def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

# === SCAN MODULE ===

def run_scan_gui(target, arguments, output_box):
    try:
        nm = nmap.PortScanner()
        output_box.insert(tk.END, f"[+] Running Nmap scan on {target} with arguments: {arguments}\n\n")
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            output_box.insert(tk.END, "[!] No hosts found. The target might be down or unreachable.\n")
            return

        result = nm.csv()
        output_box.insert(tk.END, "[+] Scan completed. Results:\n\n")
        output_box.insert(tk.END, result + "\n")

        for host in nm.all_hosts():
            output_box.insert(tk.END, f"\n[+] Host: {host} ({nm[host].hostname()})\n")
            output_box.insert(tk.END, f"    State: {nm[host].state()}\n")

            if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                output_box.insert(tk.END, "\n[+] OS Detection:\n")
                for match in nm[host]['osmatch']:
                    name = match.get('name', 'Unknown OS')
                    accuracy = match.get('accuracy', '?')
                    output_box.insert(tk.END, f"    - {name} (Accuracy: {accuracy}%)\n")
            elif '-O' in arguments or '-A' in arguments:
                output_box.insert(tk.END, "\n[!] OS detection attempted but no match found.\n")

            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    service = nm[host][proto][port].get('name', 'unknown')
                    state = nm[host][proto][port].get('state', '?')
                    output_box.insert(tk.END, f"    {proto.upper()} Port {port}: {state} ({service})\n")

        filename = f"scan_results_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(result)
        output_box.insert(tk.END, f"\n[+] Results saved to {filename}\n")
        output_box.see(tk.END)

    except Exception as e:
        output_box.insert(tk.END, f"[!] Error during scan: {e}\n")

# === UI APP ===

class SSMApp:
    def __init__(self, master):
        self.master = master
        self.master.title("System Security Management (SSM)")
        self.secret = None
        self.scan_type = tk.StringVar(value="-F")

        self.setup_style()
        self.login_frame()

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", font=('Segoe UI', 10), background="#e8eaf6")
        self.style.configure("TButton", font=('Segoe UI', 10, 'bold'), padding=6)
        self.style.configure("Header.TLabel", font=('Segoe UI', 16, 'bold'), background="#c5cae9", foreground="#1a237e")
        self.style.configure("TRadiobutton", background="#e8eaf6", foreground="#1a237e")

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def apply_background(self):
        canvas = tk.Canvas(self.master, bg="#303f9f", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        canvas.create_rectangle(0, 0, 1600, 1000, fill="#1a237e", outline="")
        return canvas

    def login_frame(self):
        self.clear_window()
        canvas = self.apply_background()

        frame = ttk.Frame(canvas, padding=20, style="Card.TFrame")
        frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(frame, text="🔐 Login to SSM", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(frame, text="Username").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Password").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(frame, show='*', width=30)
        self.password_entry.grid(row=2, column=1, pady=5)

        ttk.Button(frame, text="Login", command=self.login).grid(row=3, column=0, columnspan=2, pady=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        self.secret = authenticate(username, password)
        if not self.secret:
            messagebox.showerror("Error", "Invalid username or password.")
            return

        messagebox.showinfo("Success", "Password verified. Enter your OTP.")
        self.otp_frame()

    def otp_frame(self):
        self.clear_window()
        canvas = self.apply_background()

        frame = ttk.Frame(canvas, padding=20)
        frame.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(frame, text="🔑 Enter OTP", style="Header.TLabel").pack(pady=10)
        self.otp_entry = ttk.Entry(frame, width=30)
        self.otp_entry.pack(pady=5)
        
        ttk.Button(frame, text="Verify OTP", command=self.verify_otp).pack(pady=5)

    def verify_otp(self):
        otp = self.otp_entry.get().strip()
        if not otp:
            messagebox.showerror("Error", "Please enter the OTP.")
            return

        if verify_otp(self.secret, otp):
            messagebox.showinfo("Success", "Login successful.")
            self.scan_frame()
        else:
            messagebox.showerror("Error", "Invalid OTP. Try again.")

    def scan_frame(self):
        self.clear_window()
        canvas = self.apply_background()

        frame = ttk.Frame(canvas, padding=20)
        frame.place(relx=0.5, rely=0.02, anchor="n")

        ttk.Label(frame, text="🛡️ Nmap Scanner", style="Header.TLabel").pack(pady=10)

        form_frame = ttk.Frame(frame)
        form_frame.pack(pady=5)

        ttk.Label(form_frame, text="Target IP/Domain:").grid(row=0, column=0, sticky="e", padx=5)
        self.target_entry = ttk.Entry(form_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5)

        ttk.Label(form_frame, text="Scan Type:").grid(row=1, column=0, sticky="ne", padx=5, pady=10)

        scan_options = [
            ("Basic Scan", "-F"),
            ("Top 1000 Ports", "-p 1-1000"),
            ("Service Version Detection", "-sV"),
            ("OS Detection", "-O"),
            ("Aggressive Scan", "-A")
        ]

        option_frame = ttk.Frame(form_frame)
        option_frame.grid(row=1, column=1, sticky="w")

        for text, val in scan_options:
            ttk.Radiobutton(option_frame, text=text, variable=self.scan_type, value=val).pack(anchor="w")

        ttk.Button(frame, text="Run Scan", command=self.start_scan).pack(pady=10)

        self.output_box = scrolledtext.ScrolledText(canvas, width=110, height=30, font=("Consolas", 10), bg="#ede7f6", fg="#1a237e")
        self.output_box.place(relx=0.5, rely=0.5, anchor="n")

    def start_scan(self):
        target = self.target_entry.get().strip()
        arguments = self.scan_type.get()
        self.output_box.delete(1.0, tk.END)

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return

        threading.Thread(target=run_scan_gui, args=(target, arguments, self.output_box), daemon=True).start()

# === MAIN ===

if __name__ == "__main__":
    root = tk.Tk()
    root.title("System Security Management - SSM")
    root.geometry("1000x900")
    root.configure(bg="#1a237e")
    SSMApp(root)
    root.mainloop()
