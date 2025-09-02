import os
import threading
import base64
import tkinter as tk
from tkinter import filedialog, ttk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import webbrowser

# --- Constants ---
ITERATIONS = 480_000
BLOCK_SIZE = 64 * 1024  # 64 KB

# --- Helper Functions ---


def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def unique_name(path: str) -> str:
    """Avoid overwriting files by appending numbers if needed."""
    base, ext = os.path.splitext(path)
    counter = 1
    new_path = path
    while os.path.exists(new_path):
        new_path = f"{base}({counter}){ext}"
        counter += 1
    return new_path


def password_strength(password: str) -> (str, str):
    """Assess password strength and return description and color."""
    score = 0
    if len(password) >= 8: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/|\\`~" for c in password): score += 1

    if score <= 2:
        return "Weak 🔴", "red"
    elif score <= 4:
        return "Moderate 🟡", "orange"
    else:
        return "Strong 🟢", "green"


# --- File Operations ---


def encrypt_file(filepath: str, password: str, confirm_password: str) -> (bool, str):
    """Encrypt a file with a password."""
    if not password:
        return False, "Password cannot be empty."
    if password != confirm_password:
        return False, "Passwords do not match."
    if filepath.endswith(".encrypted"):
        return False, "File is already encrypted."

    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        fernet = Fernet(key)

        target_path = unique_name(f"{filepath}.encrypted")

        with open(filepath, "rb") as f_in, open(target_path, "wb") as f_out:
            f_out.write(salt)
            while chunk := f_in.read(BLOCK_SIZE):
                f_out.write(fernet.encrypt(chunk))

        return True, f"Encrypted:\n{filepath}\n→\n{target_path}"
    except FileNotFoundError:
        return False, f"File not found: {filepath}"
    except Exception as e:
        return False, f"Error during encryption: {e}"


def decrypt_file(filepath: str, password: str) -> (bool, str):
    """Decrypt a previously encrypted file."""
    if not password:
        return False, "Password cannot be empty."
    if not filepath.endswith(".encrypted"):
        return False, "This does not appear to be an encrypted file."

    try:
        with open(filepath, "rb") as f_in:
            salt = f_in.read(16)
            key = generate_key(password, salt)
            fernet = Fernet(key)

            target_path = unique_name(filepath.rsplit('.encrypted', 1)[0])

            with open(target_path, "wb") as f_out:
                while chunk := f_in.read(BLOCK_SIZE + 100):
                    f_out.write(fernet.decrypt(chunk))

        return True, f"Decrypted:\n{filepath}\n→\n{target_path}"
    except FileNotFoundError:
        return False, f"File not found: {filepath}"
    except InvalidToken:
        return False, "Wrong password or corrupted file."
    except Exception as e:
        return False, f"Error during decryption: {e}"


# --- GUI Application ---


class FileCryptoGUI(tk.Tk):
    """Graphical interface for file encryption and decryption."""

    def __init__(self):
        super().__init__()
        self.title("🔐 File Encryptor/Decryptor")
        self.geometry("700x520")
        self.resizable(False, False)

        # Colors
        self.bg = "#212121"
        self.fg = "#e0e0e0"
        self.accent = "#61dafb"
        self.btn_bg = "#343434"
        self.btn_fg = "#ffffff"

        self.configure(bg=self.bg)
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._setup_styles()

        # Variables
        self.file_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.status_var = tk.StringVar()

        self._build_ui()

    def _setup_styles(self):
        self.style.configure("TFrame", background=self.bg)
        self.style.configure("TLabel", background=self.bg, foreground=self.fg, font=("Helvetica", 12))
        self.style.configure("TButton", background=self.btn_bg, foreground=self.btn_fg, font=("Helvetica", 10, "bold"), padding=10)
        self.style.map("TButton", background=[("active", self.accent)])
        self.style.configure("TEntry", fieldbackground=self.btn_bg, foreground=self.fg, insertbackground=self.accent)
        self.style.configure("Title.TLabel", background=self.bg, foreground=self.accent, font=("Helvetica", 20, "bold"))
        self.style.configure("Status.TLabel", background=self.btn_bg, foreground=self.fg, font=("Helvetica", 12))

    def _build_ui(self):
        title_frame = ttk.Frame(self, style="TFrame")
        title_frame.pack(fill="x", pady=20)
        ttk.Label(title_frame, text="🔐 File Encryptor/Decryptor", style="Title.TLabel").pack()

        main_frame = ttk.Frame(self, padding=20, style="TFrame")
        main_frame.pack(expand=True, fill="both")
        main_frame.columnconfigure(1, weight=1)

        ttk.Label(main_frame, text="Select File:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        ttk.Entry(main_frame, textvariable=self.file_var).grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ttk.Button(main_frame, text="Browse", command=self._browse_file).grid(row=0, column=2, padx=10, pady=10)

        ttk.Label(main_frame, text="Enter Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        pw_entry = ttk.Entry(main_frame, textvariable=self.pw_var, show="*")
        pw_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        pw_entry.bind("<KeyRelease>", self._update_strength)
        self.strength_label = ttk.Label(main_frame, text="", font=("Helvetica", 10, "bold"))
        self.strength_label.grid(row=1, column=2, padx=10, pady=10)

        ttk.Label(main_frame, text="Confirm Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        ttk.Entry(main_frame, textvariable=self.confirm_var, show="*").grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        button_frame = ttk.Frame(main_frame, style="TFrame")
        button_frame.grid(row=3, column=0, columnspan=3, pady=30)
        ttk.Button(button_frame, text="Encrypt", command=lambda: self._run_thread(self._encrypt_file), width=15).pack(side="left", padx=20)
        ttk.Button(button_frame, text="Decrypt", command=lambda: self._run_thread(self._decrypt_file), width=15).pack(side="left", padx=20)
        ttk.Button(button_frame, text="Clear Fields", command=self._clear_fields, width=15).pack(side="left", padx=20)
        ttk.Button(button_frame, text="Open Folder", command=self._open_folder, width=15).pack(side="left", padx=20)

        status_panel = ttk.Frame(self, style="TFrame")
        status_panel.pack(side="bottom", fill="x", padx=20, pady=10)
        self.status_label = ttk.Label(status_panel, textvariable=self.status_var, style="Status.TLabel", anchor="center", wraplength=650)
        self.status_label.pack(fill="x", padx=10, pady=5)
        self.progress = ttk.Progressbar(status_panel, orient="horizontal", mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=5)

    # --- Event Methods ---

    def _browse_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.file_var.set(file)
            self.status_var.set(f"📂 Selected: {file}")
            self.status_label.configure(foreground=self.accent)

    def _update_strength(self, event=None):
        strength, color = password_strength(self.pw_var.get())
        self.strength_label.configure(text=strength, foreground=color)

    def _run_thread(self, func):
        threading.Thread(target=func, daemon=True).start()

    def _encrypt_file(self):
        self.progress.start()
        success, msg = encrypt_file(self.file_var.get(), self.pw_var.get(), self.confirm_var.get())
        self.progress.stop()
        self.status_var.set(msg)
        self.status_label.configure(foreground="#2ecc71" if success else "#e74c3c")

    def _decrypt_file(self):
        self.progress.start()
        success, msg = decrypt_file(self.file_var.get(), self.pw_var.get())
        self.progress.stop()
        self.status_var.set(msg)
        self.status_label.configure(foreground="#2ecc71" if success else "#e74c3c")

    def _clear_fields(self):
        self.file_var.set("")
        self.pw_var.set("")
        self.confirm_var.set("")
        self.strength_label.config(text="")
        self.status_var.set("")

    def _open_folder(self):
        path = os.path.dirname(self.file_var.get()) or os.getcwd()
        if os.path.exists(path):
            webbrowser.open(path)


if __name__ == "__main__":
    app = FileCryptoGUI()
    app.mainloop()
