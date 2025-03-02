import os
import re
import logging
from datetime import datetime
import hashlib
from email import message_from_file, policy
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


# Constants
EML_FILE_EXTENSION = ".eml"
ILLEGAL_CHARS_REGEX = r'[/\\|\[\]\{\}:<>+=;,?!*"~#$%&@\']'
VIRUSTOTAL_API_KEY = "cd28faa05ea54cddc5e67b3c5608611e948d9d2abbefe3db878dff98bbc4f4c2"     
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

# Custom logging handler to output to GUI
class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.insert(tk.END, msg + "\n")
        self.text_widget.see(tk.END)

# VirusTotal check function
def check_virustotal(file_hash, log_widget):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"{VIRUSTOTAL_API_URL}{file_hash}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]
            log_widget.insert(tk.END, f"VirusTotal Results for hash {file_hash}:\n")
            log_widget.insert(tk.END, f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}\n")
            return stats["malicious"] > 0 or stats["suspicious"] > 0  # True if potentially malicious
        elif response.status_code == 404:
            log_widget.insert(tk.END, f"Hash {file_hash} not found in VirusTotal database.\n")
            return False  # Not found, assume safe
        else:
            log_widget.insert(tk.END, f"VirusTotal API error: {response.status_code}\n")
            return True  # Err on caution if API fails
    except Exception as e:
        log_widget.insert(tk.END, f"Error checking VirusTotal: {e}\n")
        return True  # Err on caution if exception occurs

# Forensic extraction functions
def forensic_analysis(file: Path, log_widget, analyst_name: str, app_instance):
    try:
        log_widget.insert(tk.END, f'Processing file: "{file}"\n')
        log_widget.insert(tk.END, f"Analyst: {analyst_name}, Date: {datetime.now()}\n")
        with file.open(errors="ignore") as f:
            email_message = message_from_file(f, policy=policy.default)
            # Log full email headers
            log_widget.insert(tk.END, "Full Email Headers:\n")
            for header, value in email_message.items():
                log_widget.insert(tk.END, f"{header}: {value}\n")
            log_widget.insert(tk.END, "-" * 50 + "\n")
            # Log basic email details
            email_subject = email_message.get("Subject")
            email_sender = email_message.get("From")
            email_receiver = email_message.get("To")
            email_date_sent = email_message.get("Date")
            email_date_received = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_widget.insert(tk.END, f"Subject: {email_subject}\n")
            log_widget.insert(tk.END, f"Sender: {email_sender}\n")
            log_widget.insert(tk.END, f"Receiver: {email_receiver}\n")
            log_widget.insert(tk.END, f"Date Sent: {email_date_sent}\n")
            log_widget.insert(tk.END, f"Date Received: {email_date_received}\n")
            # Check for attachments and URLs
            attachments = [item for item in email_message.iter_attachments() if item.is_attachment()]
            app_instance.attachments = []
            app_instance.has_malicious = False  # Track if any attachment is malicious
            if not attachments:
                log_widget.insert(tk.END, "No attachments found.\n")
            else:
                for attachment in attachments:
                    filename = attachment.get_filename()
                    log_widget.insert(tk.END, f"Attachment found: {filename}\n")
                    payload = attachment.get_payload(decode=True)
                    temp_file = Path(f"temp_{filename}")
                    with temp_file.open("wb") as f:
                        f.write(payload)
                    file_hash = hash_file(temp_file)
                    log_widget.insert(tk.END, f"Attachment hash ({filename}): {file_hash}\n")
                    is_suspicious = check_virustotal(file_hash, log_widget)
                    app_instance.attachments.append((filename, payload, file_hash, is_suspicious))
                    if is_suspicious:
                        app_instance.has_malicious = True
                    if not isinstance(payload, str):
                        try:
                            decoded_payload = payload.decode("utf-8", errors="replace")
                            log_forensic_artefacts(decoded_payload, log_widget)
                        except UnicodeDecodeError as e:
                            log_widget.insert(tk.END, f"Error decoding payload: {e}\n")
                    temp_file.unlink()
            log_widget.insert(tk.END, "Forensic analysis complete.\n")
    except Exception as e:
        log_widget.insert(tk.END, f"Error processing file: {file}. Exception: {e}\n")

def extract_attachments(app_instance, destination: Path, log_widget):
    try:
        if not app_instance.attachments:
            log_widget.insert(tk.END, "No attachments to extract.\n")
            return
        email_subject = app_instance.selected_file.stem
        basepath = destination / sanitise_foldername(email_subject)
        if app_instance.has_malicious:
            proceed = messagebox.askyesno("Malicious Content Warning",
                "One or more attachments were flagged as potentially malicious by VirusTotal. Extract anyway?")
            if not proceed:
                log_widget.insert(tk.END, "Extraction aborted due to malicious content.\n")
                return
        # If no malicious content or user overrides, extract all
        for filename, payload, file_hash, is_suspicious in app_instance.attachments:
            filepath = basepath / filename
            if filepath.exists():
                overwrite = messagebox.askyesno("File Exists", f'The file "{filename}" already exists! Overwrite it?')
                if overwrite:
                    save_attachment(filepath, payload, log_widget)
                else:
                    log_widget.insert(tk.END, f"Skipping {filename}...\n")
            else:
                basepath.mkdir(exist_ok=True)
                save_attachment(filepath, payload, log_widget)
            log_widget.insert(tk.END, f"Attachment hash ({filename}): {file_hash}\n")
        log_widget.insert(tk.END, "Attachment extraction complete.\n")
    except Exception as e:
        log_widget.insert(tk.END, f"Error extracting attachments: {e}\n")

def log_forensic_artefacts(payload: str, log_widget) -> None:
    urls = re.findall(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        payload,
    )
    for url in urls:
        log_widget.insert(tk.END, f"Found URL: {url}\n")

def sanitise_foldername(name: str) -> str:
    return re.sub(ILLEGAL_CHARS_REGEX, "_", name)

def save_attachment(file: Path, payload: bytes, log_widget) -> None:
    with file.open("wb") as f:
        log_widget.insert(tk.END, f'Saving attachment to "{file}"\n')
        f.write(payload)

def hash_file(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as file:
        while chunk := file.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# GUI Class
class EmlExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Forensic Extractor with VirusTotal")
        self.root.geometry("700x600")
        self.attachments = []
        self.has_malicious = False

        # Variables
        self.file_var = tk.StringVar(value="")
        self.analyst_var = tk.StringVar(value=os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "DefaultAnalyst")
        self.dest_var = tk.StringVar(value=str(Path.cwd()))
        self.selected_file = None

        # Input Frame
        input_frame = ttk.Frame(root)
        input_frame.pack(pady=10, padx=10, fill="x")

        # File Selection
        ttk.Label(input_frame, text="Select EML File:").grid(row=0, column=0, pady=5, sticky="w")
        ttk.Entry(input_frame, textvariable=self.file_var, width=50).grid(row=0, column=1, pady=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, pady=5, padx=5)

        # Analyst Name
        ttk.Label(input_frame, text="Analyst Name:").grid(row=1, column=0, pady=5, sticky="w")
        ttk.Entry(input_frame, textvariable=self.analyst_var, width=50).grid(row=1, column=1, pady=5)

        # Log Display
        ttk.Label(root, text="Forensic Log:").pack(pady=5)
        self.log_widget = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.log_widget.pack(pady=10, padx=10, fill="both", expand=True)

        # Setup logging to GUI
        handler = TextHandler(self.log_widget)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

        # Buttons Frame
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=10)

        # Forensic Analysis Button
        self.forensic_button = ttk.Button(self.button_frame, text="Forensic Analysis", command=self.run_forensic_analysis)
        self.forensic_button.pack(side=tk.LEFT, padx=5)

        # Extract Button (initially hidden)
        self.extract_button = ttk.Button(self.button_frame, text="Extract Attachments", command=self.run_extraction)
        self.extract_button.pack(side=tk.LEFT, padx=5)
        self.extract_button.pack_forget()

    def browse_file(self):
        file = filedialog.askopenfilename(
            initialdir=Path.cwd(),
            title="Select EML File",
            filetypes=(("EML files", "*.eml"), ("All files", "*.*"))
        )
        if file:
            self.file_var.set(file)
            self.selected_file = Path(file)
            self.extract_button.pack_forget()

    def run_forensic_analysis(self):
        if not self.selected_file or not self.selected_file.exists():
            messagebox.showerror("Error", "Please select a valid EML file.")
            return
        self.log_widget.delete(1.0, tk.END)
        forensic_analysis(self.selected_file, self.log_widget, self.analyst_var.get(), self)
        self.extract_button.pack(side=tk.LEFT, padx=5)

    def run_extraction(self):
        destination = filedialog.askdirectory(initialdir=self.dest_var.get(), title="Select Destination Directory")
        if not destination:
            return
        self.dest_var.set(destination)
        extract_attachments(self, Path(destination), self.log_widget)
        if not self.has_malicious:
            messagebox.showinfo("Success", "Attachment extraction completed!")
        else:
            messagebox.showinfo("Extraction Status", "Extraction halted or partially completed due to malicious content.")

def main():
    root = tk.Tk()
    app = EmlExtractorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
